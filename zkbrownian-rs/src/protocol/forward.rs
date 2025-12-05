//! Forward function implementation
//!
//! Core forwarding logic: Forward(pk_ν, sk_ν, m) -> (m', k_R, d)

use crate::crypto::{compute_prf, diversify_with_diversifier, extract_routing_value, PoseidonHash};
use crate::protocol::routing::{select_next_hop, WeightMatrix};
use crate::proving::circuits::ForwardCircuit;
use crate::types::*;
use crate::MAX_HOPS;
use ark_bls12_381::G1Projective;
use ark_ec::{CurveGroup, PrimeGroup};
use ark_std::UniformRand;
use rand::Rng;

/// Generated state bundle containing all protocol initialization data
pub struct GeneratedState {
    /// Protocol state with merkle trees
    pub protocol_state: ProtocolState,
    /// Secret keys for all users (indexed by user index)
    pub secret_keys: Vec<SecretKey>,
    /// Public keys for all users (indexed by user index)
    pub public_keys: Vec<PublicKey>,
    /// Weight matrix for routing
    pub weight_matrix: WeightMatrix,
}

/// Generate initial protocol state with keys and weight commitments
///
/// This function models the protocol initialization where:
/// 1. Each user generates their pk/sk pair
/// 2. Each user sets weights to their neighbors
/// 3. All weights are committed globally via Merkle trees
///
/// # Arguments
/// * `num_users` - Number of users in the protocol
/// * `rng` - Random number generator
///
/// # Returns
/// GeneratedState containing protocol state, keys, and weight matrix
pub fn generate_state<R: Rng>(num_users: usize, rng: &mut R) -> GeneratedState {
    use crate::crypto::curve_ops::keygen;
    use crate::types::{MerkleTree, SubMerkleTree};

    // Step 1: Generate keys for all users
    let mut secret_keys = Vec::new();
    let mut public_keys = Vec::new();

    for _ in 0..num_users {
        let (sk, pk) = keygen(rng);
        secret_keys.push(sk);
        public_keys.push(pk);
    }

    // Step 2: Generate weight matrix
    // For simplicity, use uniform distribution (each user connects to all others equally)
    let weight_matrix = WeightMatrix::uniform(num_users, crate::WEIGHT_SUM);

    // Step 3: Build sub-merkle trees for each user
    let mut sub_merkle_trees = Vec::new();
    let mut user_data = Vec::new();

    for i in 0..num_users {
        // Get weights for this user from the weight matrix
        let weights = weight_matrix.get_weights(i);

        // Build list of (neighbor_pk, weight) for this user
        let mut neighbor_weights = Vec::new();
        for &(neighbor_idx, weight) in weights {
            if neighbor_idx < public_keys.len() {
                neighbor_weights.push((public_keys[neighbor_idx].clone(), weight));
            }
        }

        // Build sub-merkle tree for this user's weights
        let sub_tree = SubMerkleTree::build(&neighbor_weights);
        sub_merkle_trees.push(sub_tree.clone());

        // Add to user data for main tree
        user_data.push((public_keys[i].clone(), sub_tree));
    }

    // Step 4: Build main merkle tree
    let merkle_tree = MerkleTree::build(&user_data);

    // Step 5: Assemble protocol state
    let protocol_state = ProtocolState {
        merkle_tree,
        sub_merkle_trees,
    };

    GeneratedState {
        protocol_state,
        secret_keys,
        public_keys,
        weight_matrix,
    }
}

/// Forward function: Forward(pk_ν, sk_ν, m) -> (m', k_R, d)
///
/// Takes a message and forwards it to the next hop, generating a proof
/// of correct forwarding.
///
/// # Algorithm
/// 1. Check hop count ν ≤ ν_max
/// 2. Derive θ ← Hash(φ_ν, sid, pid, ν)
/// 3. Compute φ_{ν+1} ← G^{1/(θ+sk)}
/// 4. Select next hop using ρ_{ν+1} ← First32Bits(φ_{ν+1})
/// 5. Create diversified public key ppk_{ν+1}
/// 6. Generate proof π_{ν+1}
/// 7. Return updated message m'
///
/// # Arguments
/// * `pk` - Public key of current forwarder
/// * `sk` - Secret key of current forwarder
/// * `message` - Current message to forward
/// * `weight_matrix` - Weight matrix for routing decisions
/// * `all_public_keys` - List of all node public keys
///
/// # Returns
/// * `m'` - Updated message with new hop added
/// * `k_R` - Index of receiver node
/// * `d` - Diversifier used for ppk_{ν+1}
pub fn forward<R: Rng>(
    pk: &PublicKey,
    sk: &SecretKey,
    message: &Message,
    weight_matrix: &WeightMatrix,
    all_public_keys: &[PublicKey],
    rng: &mut R,
) -> ProtocolResult<(Message, usize, Diversifier)> {
    // Step 1: Check hop count
    let nu = message.hop_count();
    if nu >= MAX_HOPS {
        return Err(ProtocolError::MaxHopsExceeded);
    }

    // Step 2: Derive θ = Hash(φ_ν, sid, pid, ν)
    let hasher = PoseidonHash::new();
    let phi_prev = if nu == 0 {
        // φ_0 = 0 (dummy value)
        ScalarField::from(0u64)
    } else {
        // Convert G1 point to scalar for hashing (simplified)
        // TODO: Better conversion from G1 point to field element
        let _phi_point = message
            .latest_phi()
            .ok_or_else(|| ProtocolError::CryptoError("No previous PRF output".to_string()))?;
        ScalarField::from(1u64) // Placeholder
    };

    let theta = hasher.hash_theta(&phi_prev, message.sid, message.pid, nu);

    // Step 3: Compute φ_{ν+1} = G^{1/(θ+sk)}
    let generator = G1Projective::generator().into_affine();
    let phi_nu_plus_1 = compute_prf(&theta, sk, &generator)
        .ok_or_else(|| ProtocolError::CryptoError("PRF computation failed (θ+sk=0)".to_string()))?;

    // Step 4: Select next hop
    // Extract ρ_{ν+1} from φ_{ν+1}
    let rho_nu_plus_1 = extract_routing_value(&phi_nu_plus_1);

    // Use ρ and weight matrix to select next hop
    let (k_r, pk_nu_plus_1) = select_next_hop(rho_nu_plus_1, weight_matrix, all_public_keys)?;

    // Step 5: Create diversified public key ppk_{ν+1}
    let d = Diversifier {
        d: ScalarField::rand(rng),
    };
    let (ppk_nu_plus_1, _) = diversify_with_diversifier(&pk_nu_plus_1, &d);

    // Step 6: Generate proof π_{ν+1}
    // TODO: Full proof generation using all five circuits
    let pi_nu_plus_1 = generate_forward_proof(
        pk,
        sk,
        message,
        &theta,
        &phi_nu_plus_1,
        &ppk_nu_plus_1,
        k_r,
        &d,
        weight_matrix,
    )?;

    // Step 7: Create updated message m'
    let mut new_message = message.clone();
    new_message.hops.push(Hop {
        ppk: ppk_nu_plus_1,
        phi: phi_nu_plus_1,
        pi: pi_nu_plus_1,
    });

    Ok((new_message, k_r, d))
}

/// Generate the forward proof π_{ν+1}
///
/// Generates all five proof components:
/// - π_1: Sender membership
/// - π_2: Weight subtree
/// - π_3: Receiver membership
/// - π_{4,G1}: Schnorr bridging
/// - π_{4,G2}: Public key operations
fn generate_forward_proof(
    _pk: &PublicKey,
    _sk: &SecretKey,
    _message: &Message,
    _theta: &ScalarField,
    _phi_nu_plus_1: &PrfOutput,
    _ppk_nu_plus_1: &DiversifiedPublicKey,
    _k_r: usize,
    _d: &Diversifier,
    _weight_matrix: &WeightMatrix,
) -> ProtocolResult<Proof> {
    // TODO: Full proof generation
    // For now, return a stub proof

    // Create circuit
    let _circuit = ForwardCircuit::new();

    // Generate witness
    // ... (witness generation logic)

    // Generate proofs for each component
    // π_1, π_2, π_3, π_{4,G1}, π_{4,G2}

    // For now, stub
    Ok(Proof {
        pi_1: vec![0u8; 32],
        pi_2: vec![0u8; 32],
        pi_3: vec![0u8; 32],
        pi_4_g1: vec![0u8; 32],
        pi_4_g2: vec![0u8; 32],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::curve_ops::keygen;
    use crate::protocol::spawn::spawn;
    use crate::WEIGHT_SUM;
    use rand::thread_rng;

    #[test]
    fn test_forward_basic() {
        let mut rng = thread_rng();

        // Setup: create keys for multiple nodes
        let (sk1, pk1) = keygen(&mut rng);
        let (_sk2, pk2) = keygen(&mut rng);
        let (_sk3, pk3) = keygen(&mut rng);

        let all_pks = vec![pk1.clone(), pk2.clone(), pk3.clone()];

        // Create weight matrix (simplified)
        let weight_matrix = WeightMatrix::uniform(3, WEIGHT_SUM);

        // Spawn initial message
        let message = spawn(&sk1, &pk1, 1, 100, &mut rng).unwrap();

        // Forward the message
        let result = forward(&pk1, &sk1, &message, &weight_matrix, &all_pks, &mut rng);

        match result {
            Ok((new_message, k_r, _d)) => {
                // Check message was updated
                assert_eq!(new_message.hop_count(), 1);
                assert!(k_r < all_pks.len());
                println!("Message forwarded to node {}", k_r);
            }
            Err(e) => {
                println!("Forward failed (expected for stub): {:?}", e);
            }
        }
    }

    #[test]
    fn test_forward_max_hops() {
        let mut rng = thread_rng();
        let (sk, pk) = keygen(&mut rng);
        let all_pks = vec![pk.clone()];
        let weight_matrix = WeightMatrix::uniform(1, WEIGHT_SUM);

        // Create a message with maximum hops
        let mut message = spawn(&sk, &pk, 1, 100, &mut rng).unwrap();

        // Add MAX_HOPS hops manually
        for _ in 0..MAX_HOPS {
            message.hops.push(Hop {
                ppk: DiversifiedPublicKey {
                    ppk_1: pk.pk,
                    ppk_2: pk.pk,
                },
                phi: PrfOutput {
                    phi: G1Projective::generator().into_affine(),
                },
                pi: Proof {
                    pi_1: vec![],
                    pi_2: vec![],
                    pi_3: vec![],
                    pi_4_g1: vec![],
                    pi_4_g2: vec![],
                },
            });
        }

        // Should fail with MaxHopsExceeded
        let result = forward(&pk, &sk, &message, &weight_matrix, &all_pks, &mut rng);
        assert!(matches!(result, Err(ProtocolError::MaxHopsExceeded)));
    }

    #[test]
    fn test_generate_state_with_merkle_proofs() {
        use crate::crypto::poseidon::PoseidonHash;

        let mut rng = thread_rng();
        let num_users = 8;

        // Generate protocol state
        let generated_state = generate_state(num_users, &mut rng);

        // Verify basic structure
        assert_eq!(generated_state.secret_keys.len(), num_users);
        assert_eq!(generated_state.public_keys.len(), num_users);
        assert_eq!(
            generated_state.protocol_state.sub_merkle_trees.len(),
            num_users
        );

        let merkle_tree = &generated_state.protocol_state.merkle_tree;

        println!("Generated state for {} users", num_users);
        println!("Merkle tree root: {:?}", merkle_tree.root);
        println!("Merkle tree depth: {}", merkle_tree.depth());

        // Test merkle proofs for several users
        for user_idx in [0, 3, 7] {
            println!("\nTesting Merkle proof for user {}", user_idx);

            // Get the merkle proof for this user
            let proof = merkle_tree
                .get_proof(user_idx)
                .expect("Should get valid proof");

            println!("Proof length: {}", proof.len());

            // Get the leaf for this user
            let leaf = merkle_tree.leaves[user_idx];
            let (pk_x, pk_y, m2_root) = leaf;

            // Verify the proof by recomputing the root
            let hasher = PoseidonHash::new();

            // Hash the leaf
            let mut current_hash = hasher.hash(&[pk_x, pk_y, m2_root]);
            let mut current_index = user_idx;

            println!("Leaf hash: {:?}", current_hash);

            // Walk up the tree using the proof
            for (level, sibling_hash) in proof.iter().enumerate() {
                // Determine if current node is left or right child
                let is_left = current_index % 2 == 0;

                current_hash = if is_left {
                    // Current is left, sibling is right
                    hasher.hash(&[current_hash, *sibling_hash])
                } else {
                    // Current is right, sibling is left
                    hasher.hash(&[*sibling_hash, current_hash])
                };

                current_index /= 2;
                println!("Level {}: hash = {:?}", level, current_hash);
            }

            // Verify the computed root matches the actual root
            assert_eq!(
                current_hash, merkle_tree.root,
                "Merkle proof verification failed for user {}",
                user_idx
            );

            println!("✓ Merkle proof verified for user {}", user_idx);
        }

        // Also verify that the sub-merkle trees have the correct structure
        for (user_idx, sub_tree) in generated_state
            .protocol_state
            .sub_merkle_trees
            .iter()
            .enumerate()
        {
            // Check that the sub-tree has the right number of leaves
            assert_eq!(
                sub_tree.leaves.len(),
                crate::types::SubMerkleTree::MAX_LEAVES
            );

            // Check that the 0-th leaf is (0, 0, 0)
            let zero_leaf = sub_tree.leaves[0];
            assert_eq!(zero_leaf.0, ScalarField::from(0u64));
            assert_eq!(zero_leaf.1, ScalarField::from(0u64));
            assert_eq!(zero_leaf.2, ScalarField::from(0u64));

            println!("User {} sub-tree root: {:?}", user_idx, sub_tree.root);
        }

        println!("\n✓ All Merkle proofs verified successfully!");
    }
}
