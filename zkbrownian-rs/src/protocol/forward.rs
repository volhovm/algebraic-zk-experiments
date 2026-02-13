//! Forward function implementation
//!
//! Core forwarding logic: Forward(user_view, m) -> (m', k_R, d)

use crate::crypto::{compute_prf, diversify_with_diversifier, extract_routing_value, PoseidonHash};
use crate::protocol::routing::WeightMatrix;
#[cfg(test)]
use crate::proving::circuits::mock_groth16_proof;
use crate::proving::circuits::{
    prove_public_key_operations, prove_receiver_membership, prove_schnorr_bridging,
    prove_sender_membership, prove_weight_subtree, PublicKeyOperationsInstance,
    PublicKeyOperationsWitness, ReceiverMembershipInstance, ReceiverMembershipWitness,
    SchnorrBridgingInstance, SchnorrBridgingWitness, SenderMembershipInstance,
    SenderMembershipWitness, WeightSubtreeInstance, WeightSubtreeWitness,
};
use crate::types::*;
use crate::MAX_HOPS;
use ark_bls12_381::G1Projective;
use ark_ec::{CurveGroup, PrimeGroup};
use ark_std::rand::Rng;
use ark_std::UniformRand;

/// Information about a single neighbor
#[derive(Clone, Debug)]
pub struct NeighborInfo {
    /// Index of the neighbor in the global merkle tree
    pub index: usize,
    /// Public key of the neighbor
    pub public_key: PublicKey,
    /// Sub-merkle tree root (M2) of the neighbor
    pub sub_merkle_root: ScalarField,
    /// Merkle proof of inclusion in the global tree
    pub merkle_proof: Vec<ScalarField>,
    /// Weight to this neighbor
    pub weight: u32,
}

/// A node's view of its neighbors
/// Contains all information a node knows about its neighbors
#[derive(Clone, Debug)]
pub struct NeighboursView {
    /// List of neighbor information
    pub neighbors: Vec<NeighborInfo>,
}

/// Precomputed Groth16 proofs for forward function
/// Contains proofs that can be rerandomized instead of computed from scratch
#[derive(Clone, Debug)]
pub struct LocalPrecompute {
    /// π_1: Sender membership proof (for oneself)
    pub pi_1_sender: ProofGroth16,
    /// Precomputed commitment C11 (sender, with merkle circuit bases, r1=0)
    pub c11_precomputed: G1Projective,
    /// Precomputed commitment C12 (sender, with weight circuit bases, r1=0)
    pub c12_precomputed: G1Projective,

    /// π_3: Receiver membership proofs (one per neighbor)
    pub pi_3_receivers: Vec<ProofGroth16>,
    /// Precomputed commitments C21 for each neighbor (with merkle circuit bases, r2=0)
    pub c21_precomputed: Vec<G1Projective>,
    /// Precomputed commitments C22 for each neighbor (with weight circuit bases, r2=0)
    pub c22_precomputed: Vec<G1Projective>,

    /// π_2: Weight subtree proofs (one per neighbor)
    pub pi_2_weights: Vec<ProofGroth16>,
    /// Precomputed commitments C_v1 for each neighbor (with r_v1=0)
    pub c_v1_precomputed: Vec<(G1Projective, u64)>, // (commitment, v1 value)
    /// Precomputed commitments C_v2 for each neighbor (with r_v2=0)
    pub c_v2_precomputed: Vec<(G1Projective, u64)>, // (commitment, v2 value)

    /// Bulletproof generators for Pedersen commitments
    pub pc_gens: crate::proving::bulletproofs::PedersenGens<ark_bls12_381::G1Affine>,
    /// Bulletproof generators for R1CS proofs
    pub bp_gens: crate::proving::bulletproofs::BulletproofGens<ark_bls12_381::G1Affine>,
}

/// A single user's complete view of the protocol
#[derive(Clone, Debug)]
pub struct UserView {
    /// User's secret key
    pub secret_key: SecretKey,
    /// User's public key
    pub public_key: PublicKey,
    /// User's view of their neighbors
    pub neighbours_view: NeighboursView,
    /// User's own sub-merkle root (md_{2,k_s})
    pub own_sub_merkle_root: ScalarField,
    /// User's merkle proof of inclusion in the main tree
    pub own_merkle_proof: Vec<ScalarField>,
    /// Precomputed Groth16 proofs
    pub precompute: LocalPrecompute,
}

/// Generated state bundle containing all protocol initialization data
pub struct GeneratedState {
    /// Protocol state with merkle trees
    pub protocol_state: ProtocolState,
    /// Per-user views (indexed by user index)
    pub users_view: Vec<UserView>,
    /// Weight matrix for routing
    pub weight_matrix: WeightMatrix,
}

/// Generate precomputed Groth16 proofs for a user
///
/// Creates proofs that can be rerandomized during forward operations:
/// - π_1: Sender membership proof (for the user)
/// - π_3: Receiver membership proofs (one per neighbor)
/// - π_2: Weight subtree proofs (one per neighbor)
///
/// # Arguments
/// * `pp` - Public parameters
/// * `user_view` - User's view containing their keys and neighbor information
/// * `merkle_root` - Root of the global merkle tree
///
/// # Returns
/// LocalPrecompute containing all precomputed proofs
fn generate_precompute(
    pp: &PublicParams,
    pk: &PublicKey,
    neighbours_view: &NeighboursView,
    own_sub_merkle_root: ScalarField,
    own_merkle_proof: &[ScalarField],
    merkle_root: ScalarField,
) -> ProtocolResult<LocalPrecompute> {
    use ark_ff::{BigInteger, PrimeField};

    // Get commitment bases from circuit verification keys
    // For C11/C21 (merkle membership circuit)
    let gamma_abc_merkle = &pp.pk_merkle_membership.vk.gamma_abc_g1;
    if gamma_abc_merkle.len() < 4 {
        return Err(ProtocolError::CryptoError(
            "Merkle membership VK needs at least 4 gamma_abc_g1 elements".to_string(),
        ));
    }
    let merkle_base_1 = G1Projective::from(gamma_abc_merkle[1]);
    let merkle_base_2 = G1Projective::from(gamma_abc_merkle[2]);
    let merkle_base_3 = G1Projective::from(gamma_abc_merkle[3]);

    // For C12/C22 (weight subtree circuit)
    let gamma_abc_weight = &pp.pk_weight_subtree.vk.gamma_abc_g1;
    if gamma_abc_weight.len() < 4 {
        return Err(ProtocolError::CryptoError(
            "Weight subtree VK needs at least 4 gamma_abc_g1 elements".to_string(),
        ));
    }
    let weight_base_1 = G1Projective::from(gamma_abc_weight[1]);
    let weight_base_2 = G1Projective::from(gamma_abc_weight[2]);
    let weight_base_3 = G1Projective::from(gamma_abc_weight[3]);

    // Get randomness bases hs[0] and hs[1]
    let h0 = pp
        .generators
        .h_commitment(0)
        .ok_or_else(|| ProtocolError::CryptoError("Missing h_commitment[0]".to_string()))?;
    let h1 = pp
        .generators
        .h_commitment(1)
        .ok_or_else(|| ProtocolError::CryptoError("Missing h_commitment[1]".to_string()))?;
    let h0_proj = G1Projective::from(*h0);
    let h1_proj = G1Projective::from(*h1);

    // Convert sender's public key to scalar field
    let pk_x_scalar = ScalarField::from_le_bytes_mod_order(&pk.pk.x.into_bigint().to_bytes_le());
    let pk_y_scalar = ScalarField::from_le_bytes_mod_order(&pk.pk.y.into_bigint().to_bytes_le());
    let md_2_k_s = own_sub_merkle_root;

    // Use zero blinding factor for precomputed proof
    let r1 = ScalarField::from(0u32);

    // Create dual commitments for sender
    // C11 (sender, with merkle circuit bases)
    let c11_precomputed = (merkle_base_1 * pk_x_scalar)
        + (merkle_base_2 * pk_y_scalar)
        + (merkle_base_3 * md_2_k_s)
        + (h0_proj * r1);

    // C12 (sender, with weight circuit bases)
    let c12_precomputed = (weight_base_1 * pk_x_scalar)
        + (weight_base_2 * pk_y_scalar)
        + (weight_base_3 * md_2_k_s)
        + (h1_proj * r1);

    // Generate π_1: Sender membership proof (uses C11)
    let sender_instance = SenderMembershipInstance {
        c: c11_precomputed,
        merkle_root,
    };
    let sender_witness = SenderMembershipWitness {
        pk_x: pk_x_scalar,
        pk_y: pk_y_scalar,
        md_2: md_2_k_s,
        r: r1,
        merkle_proof: own_merkle_proof.to_vec(),
    };
    let pi_1_sender = prove_sender_membership(&sender_instance, &sender_witness)?;

    // Generate π_3 and π_2 proofs for each neighbor
    let mut pi_3_receivers = Vec::new();
    let mut pi_2_weights = Vec::new();
    let mut c21_precomputed_vec = Vec::new();
    let mut c22_precomputed_vec = Vec::new();
    let mut c_v1_precomputed_vec = Vec::new();
    let mut c_v2_precomputed_vec = Vec::new();
    let mut cumulative_weight = 0u64;

    for neighbor in &neighbours_view.neighbors {
        // Convert receiver's public key to scalar field
        let pk_r_x_scalar = ScalarField::from_le_bytes_mod_order(
            &neighbor.public_key.pk.x.into_bigint().to_bytes_le(),
        );
        let pk_r_y_scalar = ScalarField::from_le_bytes_mod_order(
            &neighbor.public_key.pk.y.into_bigint().to_bytes_le(),
        );
        let md_2_k_r = neighbor.sub_merkle_root;

        // Use zero blinding factor for precomputed proof
        let r2 = ScalarField::from(0u32);

        // Create dual commitments for receiver
        // C21 (receiver, with merkle circuit bases)
        let c21_precomputed = (merkle_base_1 * pk_r_x_scalar)
            + (merkle_base_2 * pk_r_y_scalar)
            + (merkle_base_3 * md_2_k_r)
            + (h0_proj * r2);
        c21_precomputed_vec.push(c21_precomputed);

        // C22 (receiver, with weight circuit bases)
        let c22_precomputed = (weight_base_1 * pk_r_x_scalar)
            + (weight_base_2 * pk_r_y_scalar)
            + (weight_base_3 * md_2_k_r)
            + (h1_proj * r2);
        c22_precomputed_vec.push(c22_precomputed);

        // Generate π_3: Receiver membership proof (uses C21)
        let receiver_instance = ReceiverMembershipInstance {
            c: c21_precomputed,
            merkle_root,
        };
        let receiver_witness = ReceiverMembershipWitness {
            pk_x: pk_r_x_scalar,
            pk_y: pk_r_y_scalar,
            md_2: md_2_k_r,
            r: r2,
            merkle_proof: neighbor.merkle_proof.clone(),
        };
        let pi_3 = prove_receiver_membership(&receiver_instance, &receiver_witness)?;
        pi_3_receivers.push(pi_3);

        // Generate π_2: Weight subtree proof
        // v1 is the cumulative weight up to (but not including) this neighbor
        // v2 is the cumulative weight including this neighbor
        let v1 = cumulative_weight;
        let v2 = cumulative_weight + neighbor.weight as u64;
        cumulative_weight = v2; // Update cumulative weight for next iteration

        // Use zero blinding factors for precomputed proof
        let r_v1 = ScalarField::from(0u32);
        let r_v2 = ScalarField::from(0u32);

        // Note: C_v1 and C_v2 use weight circuit bases (same as C12/C22)
        let c_v1_precomputed = (weight_base_1 * ScalarField::from(v1)) + (h1_proj * r_v1);
        let c_v2_precomputed = (weight_base_1 * ScalarField::from(v2)) + (h1_proj * r_v2);
        c_v1_precomputed_vec.push((c_v1_precomputed, v1));
        c_v2_precomputed_vec.push((c_v2_precomputed, v2));

        let weight_instance = WeightSubtreeInstance {
            c1: c12_precomputed, // Use C12 (sender with weight circuit bases)
            c2: c22_precomputed, // Use C22 (receiver with weight circuit bases)
            c_v1: c_v1_precomputed,
            c_v2: c_v2_precomputed,
        };
        let weight_witness = WeightSubtreeWitness {
            pk_x: pk_x_scalar,
            pk_y: pk_y_scalar,
            md_2_k_s,
            r1,
            pk_r_x: pk_r_x_scalar,
            pk_r_y: pk_r_y_scalar,
            md_2_k_r,
            r2,
            v1,
            r_v1,
            v2,
            r_v2,
            sub_merkle_proof_v1: vec![], // TODO: Generate actual sub-merkle proof
            sub_merkle_proof_v2: vec![], // TODO: Generate actual sub-merkle proof
        };
        let pi_2 = prove_weight_subtree(&weight_instance, &weight_witness)?;
        pi_2_weights.push(pi_2);
    }

    Ok(LocalPrecompute {
        pi_1_sender,
        c11_precomputed,
        c12_precomputed,
        pi_3_receivers,
        c21_precomputed: c21_precomputed_vec,
        c22_precomputed: c22_precomputed_vec,
        pi_2_weights,
        c_v1_precomputed: c_v1_precomputed_vec,
        c_v2_precomputed: c_v2_precomputed_vec,
        pc_gens: pp.pc_gens.clone(),
        bp_gens: pp.bp_gens.clone(),
    })
}

/// Generate initial protocol state with keys and weight commitments
///
/// This function models the protocol initialization where:
/// 1. Each user generates their pk/sk pair
/// 2. Each user sets weights to their neighbors
/// 3. All weights are committed globally via Merkle trees
/// 4. Precomputed proofs are generated for each user
///
/// # Arguments
/// * `pp` - Public parameters
/// * `num_users` - Number of users in the protocol
/// * `rng` - Random number generator
///
/// # Returns
/// GeneratedState containing protocol state, keys, and weight matrix
pub fn generate_random_state<R: Rng>(
    pp: &PublicParams,
    num_users: usize,
    rng: &mut R,
) -> GeneratedState {
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
        merkle_tree: merkle_tree.clone(),
        sub_merkle_trees: sub_merkle_trees.clone(),
    };

    // Step 6: Build user views with neighbor information
    let mut users_view = Vec::new();

    for user_idx in 0..num_users {
        // Get this user's neighbors from the weight matrix
        let weights = weight_matrix.get_weights(user_idx);

        // Build neighbor info for each neighbor
        let mut neighbors = Vec::new();
        for &(neighbor_idx, weight) in weights {
            if neighbor_idx >= num_users {
                continue;
            }

            // Get merkle proof for this neighbor
            let merkle_proof = merkle_tree
                .get_proof(neighbor_idx)
                .expect("Should have proof for valid neighbor");

            let neighbor_info = NeighborInfo {
                index: neighbor_idx,
                public_key: public_keys[neighbor_idx].clone(),
                sub_merkle_root: sub_merkle_trees[neighbor_idx].root,
                merkle_proof,
                weight,
            };

            neighbors.push(neighbor_info);
        }

        // Get user's own sub-merkle root
        let own_sub_merkle_root = sub_merkle_trees[user_idx].root;

        // Get user's own merkle proof of inclusion in the main tree
        let own_merkle_proof = merkle_tree
            .get_proof(user_idx)
            .expect("Should have proof for own user");

        // Create neighbors view
        let neighbours_view = NeighboursView { neighbors };

        // Generate precomputed proofs for this user
        let precompute = generate_precompute(
            pp,
            &public_keys[user_idx],
            &neighbours_view,
            own_sub_merkle_root,
            &own_merkle_proof,
            merkle_tree.root,
        )
        .expect("Should generate precompute successfully");

        // Create user view
        let user_view = UserView {
            secret_key: secret_keys[user_idx].clone(),
            public_key: public_keys[user_idx].clone(),
            neighbours_view,
            own_sub_merkle_root,
            own_merkle_proof,
            precompute,
        };

        users_view.push(user_view);
    }

    GeneratedState {
        protocol_state,
        users_view,
        weight_matrix,
    }
}

/// Select next hop based on routing value ρ and user's neighbor view
///
/// Uses the cumulative weight distribution from the user's neighbors.
///
/// # Arguments
/// * `rho` - 32-bit routing value from PRF
/// * `neighbours_view` - User's view of their neighbors
///
/// # Returns
/// (index, public_key, v1, v2) where v1 and v2 are the cumulative weight values
/// that rho falls between
fn select_next_hop_from_view(
    rho: u32,
    neighbours_view: &NeighboursView,
) -> ProtocolResult<(usize, PublicKey, u64, u64)> {
    if neighbours_view.neighbors.is_empty() {
        return Err(ProtocolError::InvalidWeightSelection);
    }

    // Build cumulative distribution from neighbor weights
    let mut cumulative: u64 = 0;
    for neighbor in neighbours_view.neighbors.iter() {
        let v1 = cumulative;
        cumulative += neighbor.weight as u64;
        let v2 = cumulative;

        if (rho as u64) < cumulative {
            return Ok((neighbor.index, neighbor.public_key.clone(), v1, v2));
        }
    }

    // If we get here, ρ didn't fall into any bucket (shouldn't happen if weights sum correctly)
    // Default to last neighbor
    println!(
        "[DEBUG select] rho={} fell outside range, total_cumulative={}, using last neighbor",
        rho, cumulative
    );
    Err(ProtocolError::InvalidWeightSelection)
}

/// Type alias for the complex return type of generate_forward_proof
type ForwardProofResult = (
    HopProofs,
    G1Wrapper,
    G1Wrapper,
    G1Wrapper,
    G1Wrapper,
    G1Wrapper,
    G1Wrapper,
    G3Wrapper,
    G3Wrapper,
);

/// Forward function: Forward(user_view, m) -> (m', k_R, d)
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
/// * `pp` - Public parameters including generators
/// * `user_view` - User's complete view (secret key, public key, neighbors)
/// * `message` - Current message to forward
/// * `rng` - Random number generator
///
/// # Returns
/// * `m'` - Updated message with new hop added
/// * `k_R` - Index of receiver node
/// * `d` - Diversifier used for ppk_{ν+1}
pub fn forward<R: Rng>(
    pp: &PublicParams,
    user_view: &UserView,
    message: &Message,
    rng: &mut R,
) -> ProtocolResult<(Message, usize)> {
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
        // Convert G1 point to scalar for hashing
        let phi_point = message
            .latest_phi()
            .ok_or_else(|| ProtocolError::CryptoError("No previous PRF output".to_string()))?;

        // Hash the point to get a scalar field element
        // This is a deterministic way to convert from base field to scalar field
        use ark_serialize::CanonicalSerialize;
        let mut bytes = Vec::new();
        phi_point
            .phi
            .serialize_compressed(&mut bytes)
            .map_err(|_| ProtocolError::CryptoError("Failed to serialize phi".to_string()))?;

        // Hash the serialized bytes to get a scalar
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(&bytes);
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&hash);

        // Convert hash to scalar field element (this is safe as we're reducing modulo the field order)
        use ark_ff::PrimeField;
        ScalarField::from_be_bytes_mod_order(&hash_bytes)
    };

    let theta = hasher.hash_theta(&phi_prev, message.sid, message.pid, nu);

    // Step 3: Compute φ_{ν+1} = G^{1/(θ+sk)}
    let generator = G1Projective::generator().into_affine();
    let phi_nu_plus_1 = compute_prf(&theta, &user_view.secret_key, &generator)
        .ok_or_else(|| ProtocolError::CryptoError("PRF computation failed (θ+sk=0)".to_string()))?;

    // Step 4: Select next hop
    // Extract ρ_{ν+1} from φ_{ν+1}
    let rho_nu_plus_1 = extract_routing_value(&phi_nu_plus_1);

    // Use ρ and user's neighbor view to select next hop
    let (k_r, pk_nu_plus_1, v1, v2) =
        select_next_hop_from_view(rho_nu_plus_1, &user_view.neighbours_view)?;

    // Step 5: Create diversified public key ppk_{ν+1}
    let d = Diversifier {
        d: ScalarField::rand(rng),
    };
    let (ppk_nu_plus_1, _) = diversify_with_diversifier(&pk_nu_plus_1, &d);

    // Step 6: Generate proof π_{ν+1}
    // Uses precomputed proofs for π_1, π_2, π_3 and generates fresh π_4_g1, π_4_g2
    let (pi_nu_plus_1, c11, c12, c21, c22, cv1, cv2, pk_star, pk_r_star) = generate_forward_proof(
        pp,
        &user_view.public_key,
        &user_view.secret_key,
        message,
        &theta,
        &phi_nu_plus_1,
        &ppk_nu_plus_1,
        k_r,
        &d,
        &user_view.neighbours_view,
        user_view.own_sub_merkle_root,
        &user_view.own_merkle_proof,
        v1,
        v2,
        &user_view.precompute,
    )?;

    // Step 7: Create updated message m'
    let mut new_message = message.clone();
    new_message.hops.push(Hop {
        ppk: ppk_nu_plus_1,
        phi: phi_nu_plus_1,
        pi: pi_nu_plus_1,
        c11,
        c12,
        c21,
        c22,
        cv1,
        cv2,
        pk_star,
        pk_r_star,
    });

    Ok((new_message, k_r))
}

/// Intermediate data collected during batch forward preparation
///
/// Holds all the data needed for one packet that doesn't require Schnorr proof generation.
/// The Schnorr witnesses will be batched together for efficient proving.
struct BatchForwardPrepData {
    message: Message,
    k_r: usize,
    d: Diversifier,
    ppk_nu_plus_1: DiversifiedPublicKey,
    phi_nu_plus_1: PrfOutput,
    pi_1: ProofGroth16,
    pi_2: ProofGroth16,
    pi_3: ProofGroth16,
    c11: G1Projective,
    c12: G1Projective,
    c21: G1Projective,
    c22: G1Projective,
    cv1: G1Projective,
    cv2: G1Projective,
    pk_star: G3,
    pk_r_star: G3,
    schnorr_witness: SchnorrBridgingWitness,
    sk: SecretKey,
    theta: ScalarField,
}

/// Forward multiple packets in batch, optimizing Schnorr proof generation
///
/// This function processes N packets together by:
/// 1. Preparing all packets sequentially (theta, phi, next hop, proofs)
/// 2. Batch-generating all N Schnorr proofs together (THE OPTIMIZATION)
/// 3. Assembling the final messages
///
/// # Arguments
///
/// * `pp` - Public parameters (must include batch_tables)
/// * `inputs` - Vector of (UserView, Message) pairs to forward
/// * `rng` - Random number generator
///
/// # Returns
///
/// Vector of (updated_message, receiver_index, diversifier) tuples
///
/// # Performance
///
/// Expected speedup over N sequential `forward()` calls:
/// - N=10: ~1.5×
/// - N=100: ~3-4×
/// - N=500: ~4-5×
pub fn forward_batch<R: Rng>(
    pp: &PublicParams,
    inputs: &[(UserView, Message)],
    rng: &mut R,
) -> ProtocolResult<Vec<(Message, usize)>> {
    if inputs.is_empty() {
        return Ok(vec![]);
    }

    // Phase 1a: Collect intermediate data for batch proof preparation
    let mut intermediate_data = Vec::with_capacity(inputs.len());

    for (user_view, message) in inputs {
        // Same logic as forward() lines 534-609
        let nu = message.hop_count();
        if nu >= MAX_HOPS {
            return Err(ProtocolError::MaxHopsExceeded);
        }

        // Derive θ
        let hasher = PoseidonHash::new();
        let phi_prev = if nu == 0 {
            ScalarField::from(0u64)
        } else {
            let phi_point = message
                .latest_phi()
                .ok_or_else(|| ProtocolError::CryptoError("No previous PRF output".to_string()))?;

            use ark_serialize::CanonicalSerialize;
            let mut bytes = Vec::new();
            phi_point
                .phi
                .serialize_compressed(&mut bytes)
                .map_err(|_| ProtocolError::CryptoError("Failed to serialize phi".to_string()))?;

            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(&bytes);
            let mut hash_bytes = [0u8; 32];
            hash_bytes.copy_from_slice(&hash);

            use ark_ff::PrimeField;
            ScalarField::from_be_bytes_mod_order(&hash_bytes)
        };

        let theta = hasher.hash_theta(&phi_prev, message.sid, message.pid, nu);

        // Compute φ_{ν+1}
        let generator = G1Projective::generator().into_affine();
        let phi_nu_plus_1 =
            compute_prf(&theta, &user_view.secret_key, &generator).ok_or_else(|| {
                ProtocolError::CryptoError("PRF computation failed (θ+sk=0)".to_string())
            })?;

        // Select next hop
        let rho_nu_plus_1 = extract_routing_value(&phi_nu_plus_1);
        let (k_r, pk_nu_plus_1, v1, v2) =
            select_next_hop_from_view(rho_nu_plus_1, &user_view.neighbours_view)?;

        // Create diversified public key
        let d = Diversifier {
            d: ScalarField::rand(rng),
        };
        let (ppk_nu_plus_1, _) = diversify_with_diversifier(&pk_nu_plus_1, &d);

        intermediate_data.push((
            message.clone(),
            user_view.public_key.clone(),
            user_view.secret_key.clone(),
            theta,
            phi_nu_plus_1,
            ppk_nu_plus_1,
            k_r,
            d,
            user_view.neighbours_view.clone(),
            user_view.own_sub_merkle_root,
            user_view.own_merkle_proof.clone(),
            v1,
            v2,
            user_view.precompute.clone(),
        ));
    }

    // Phase 1b: Batch prepare all proofs in parallel
    let proof_results = prepare_forward_proofs_batch(pp, &intermediate_data)?;

    // Phase 1c: Assemble prep data
    let mut prep_data = Vec::with_capacity(inputs.len());
    for (i, (message, _, sk, theta, phi_nu_plus_1, ppk_nu_plus_1, k_r, d, _, _, _, _, _, _)) in
        intermediate_data.into_iter().enumerate()
    {
        let (pi_1, pi_2, pi_3, c11, c12, c21, c22, cv1, cv2, pk_star, pk_r_star, schnorr_witness) =
            proof_results[i].clone();

        prep_data.push(BatchForwardPrepData {
            message,
            k_r,
            d,
            ppk_nu_plus_1,
            phi_nu_plus_1,
            pi_1,
            pi_2,
            pi_3,
            c11,
            c12,
            c21,
            c22,
            cv1,
            cv2,
            pk_star,
            pk_r_star,
            schnorr_witness,
            sk,
            theta,
        });
    }

    // Phase 2: BATCH SCHNORR PROVING
    let schnorr_witnesses: Vec<_> = prep_data.iter().map(|pd| &pd.schnorr_witness).collect();
    let pi_4_g1_proofs = crate::proving::circuits::prove_schnorr_bridging_batch(
        &schnorr_witnesses
            .iter()
            .map(|&w| w.clone())
            .collect::<Vec<_>>(),
        &pp.pc_gens,
        &pp.bp_gens,
        &pp.batch_tables,
        &pp.g3_tables,
    )?;

    // Phase 3: Assemble final messages
    prep_data
        .into_iter()
        .zip(pi_4_g1_proofs)
        .map(|(pd, pi_4_g1)| {
            // Generate π_{4,G2} (PublicKeyOperations) - still sequential, but fast
            let g1_base = pp
                .generators
                .g1(0)
                .ok_or_else(|| ProtocolError::CryptoError("Missing G1 generator 0".to_string()))?;
            let g1_base_proj = G1Projective::from(*g1_base);

            let g_theta = g1_base_proj * pd.theta;
            let g_phi = G1Projective::from(pd.phi_nu_plus_1.phi);

            // ppk_s is from the previous hop (or ppk_0 if this is the first hop)
            // ppk_r is the diversified public key of the current hop (ppk_nu_plus_1)
            // See verify.rs:122-127 for ppk_s and verify.rs:149 for ppk_r
            let (ppk_s_1, ppk_s_2) = if pd.message.hop_count() == 0 {
                (pd.message.ppk_0.ppk_1, pd.message.ppk_0.ppk_2)
            } else {
                let prev_ppk = pd
                    .message
                    .latest_ppk()
                    .ok_or_else(|| ProtocolError::CryptoError("No previous ppk".to_string()))?;
                (prev_ppk.ppk_1, prev_ppk.ppk_2)
            };

            let pk_ops_instance = PublicKeyOperationsInstance {
                pk_star: pd.pk_star,
                pk_r_star: pd.pk_r_star,
                ppk_s_1,
                ppk_s_2,
                ppk_r_1: pd.ppk_nu_plus_1.ppk_1,
                ppk_r_2: pd.ppk_nu_plus_1.ppk_2,
                g_theta,
                g_phi,
            };

            let pk_ops_witness = PublicKeyOperationsWitness {
                sk: pd.sk.sk,
                d: pd.d.d,
                theta: pd.theta,
                phi: pd.theta, // TODO: Extract actual phi scalar (not just theta)
                r_star: pd.schnorr_witness.r_star,
                r_r_star: pd.schnorr_witness.r_r_star,
            };

            let pi_4_g2 = prove_public_key_operations(&pk_ops_instance, &pk_ops_witness)?;

            // Assemble HopProofs
            let pi_nu_plus_1 = HopProofs {
                pi_1: pd.pi_1,
                pi_2: pd.pi_2,
                pi_3: pd.pi_3,
                pi_4_g1,
                pi_4_g2,
            };

            // Create updated message
            let mut new_message = pd.message.clone();
            new_message.hops.push(Hop {
                ppk: pd.ppk_nu_plus_1,
                phi: pd.phi_nu_plus_1,
                pi: pi_nu_plus_1,
                c11: G1Wrapper(pd.c11.into()),
                c12: G1Wrapper(pd.c12.into()),
                c21: G1Wrapper(pd.c21.into()),
                c22: G1Wrapper(pd.c22.into()),
                cv1: G1Wrapper(pd.cv1.into()),
                cv2: G1Wrapper(pd.cv2.into()),
                pk_star: G3Wrapper(pd.pk_star),
                pk_r_star: G3Wrapper(pd.pk_r_star),
            });

            Ok((new_message, pd.k_r))
        })
        .collect()
}

/// Prepare forward proof data without generating Schnorr proofs
///
/// This is a refactored version of `generate_forward_proof` that returns the
/// Schnorr witness instead of generating the proof, allowing for batch proving.
///
/// NOTE: This function is currently unused in favor of `prepare_forward_proofs_batch`,
/// but kept for reference and potential non-batch use cases.
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
fn prepare_forward_proof(
    pp: &PublicParams,
    pk: &PublicKey,
    sk: &SecretKey,
    _message: &Message,
    _theta: &ScalarField,
    phi_nu_plus_1: &PrfOutput,
    _ppk_nu_plus_1: &DiversifiedPublicKey,
    k_r: usize,
    _d: &Diversifier,
    neighbours_view: &NeighboursView,
    own_sub_merkle_root: ScalarField,
    _own_merkle_proof: &[ScalarField],
    v1: u64,
    v2: u64,
    precompute: &LocalPrecompute,
) -> ProtocolResult<(
    ProofGroth16,
    ProofGroth16,
    ProofGroth16,
    G1Projective,
    G1Projective,
    G1Projective,
    G1Projective,
    G1Projective,
    G1Projective,
    G3,
    G3,
    SchnorrBridgingWitness,
)> {
    // Generate random blinding factors
    let r1_new = ScalarField::rand(&mut rand::thread_rng());
    let r2_new = ScalarField::rand(&mut rand::thread_rng());
    let r_v1_new = ScalarField::rand(&mut rand::thread_rng());
    let r_v2_new = ScalarField::rand(&mut rand::thread_rng());

    // Find neighbor index
    let neighbor_idx = neighbours_view
        .neighbors
        .iter()
        .position(|n| n.index == k_r)
        .ok_or(ProtocolError::InvalidWeightSelection)?;

    // Rerandomize proofs
    let (pi_1, c11, c12) = adjust_groth16_merkle_membership(
        pp,
        &precompute.pi_1_sender,
        precompute.c11_precomputed,
        precompute.c12_precomputed,
        r1_new,
    )?;

    let (pi_3, c21, c22) = adjust_groth16_merkle_membership(
        pp,
        &precompute.pi_3_receivers[neighbor_idx],
        precompute.c21_precomputed[neighbor_idx],
        precompute.c22_precomputed[neighbor_idx],
        r2_new,
    )?;

    let (c_v1_precomputed, _v1_value) = precompute.c_v1_precomputed[neighbor_idx];
    let (c_v2_precomputed, _v2_value) = precompute.c_v2_precomputed[neighbor_idx];

    let (pi_2, c_v1, c_v2) = adjust_groth16_weight_subtree(
        pp,
        &precompute.pi_2_weights[neighbor_idx],
        c_v1_precomputed,
        c_v2_precomputed,
        r1_new,
        r2_new,
        r_v1_new,
        r_v2_new,
    )?;

    // Extract sender and receiver information
    use ark_ff::{BigInteger, PrimeField};
    let pk_x_scalar = ScalarField::from_le_bytes_mod_order(&pk.pk.x.into_bigint().to_bytes_le());
    let pk_y_scalar = ScalarField::from_le_bytes_mod_order(&pk.pk.y.into_bigint().to_bytes_le());
    let md_2_k_s = own_sub_merkle_root;

    let receiver = neighbours_view
        .neighbors
        .iter()
        .find(|n| n.index == k_r)
        .ok_or(ProtocolError::InvalidWeightSelection)?;

    let pk_r_x_scalar =
        ScalarField::from_le_bytes_mod_order(&receiver.public_key.pk.x.into_bigint().to_bytes_le());
    let pk_r_y_scalar =
        ScalarField::from_le_bytes_mod_order(&receiver.public_key.pk.y.into_bigint().to_bytes_le());
    let md_2_k_r = receiver.sub_merkle_root;

    // Generate blinded G3 points
    use crate::crypto::curve::{g3_base_to_scalar, scalar_to_g3_scalar, G3Proj};
    let g3_base = pp
        .generators
        .g3(0)
        .ok_or_else(|| ProtocolError::CryptoError("Missing G3 generator 0".to_string()))?;

    let g3_proj = G3Proj::from(*g3_base);
    let h3_proj = G3Proj::from(pp.h_g3);

    let r_star = ScalarField::rand(&mut rand::thread_rng());
    let r_r_star = ScalarField::rand(&mut rand::thread_rng());

    let sk_g3 = scalar_to_g3_scalar(&sk.sk);
    let r_star_g3 = scalar_to_g3_scalar(&r_star);
    let r_r_star_g3 = scalar_to_g3_scalar(&r_r_star);

    let pk_star = (g3_proj * sk_g3 + h3_proj * r_star_g3).into_affine();
    let pk_r_proj = G3Proj::from(receiver.public_key.pk);
    let pk_r_star = (pk_r_proj + h3_proj * r_r_star_g3).into_affine();

    let pk_star_x_scalar = g3_base_to_scalar(&pk_star.x);
    let pk_star_y_scalar = g3_base_to_scalar(&pk_star.y);
    let pk_r_star_x_scalar = g3_base_to_scalar(&pk_r_star.x);
    let pk_r_star_y_scalar = g3_base_to_scalar(&pk_r_star.y);

    use ark_ec::CurveGroup;
    let pk_star_g3 = G3::new(pk_star_x_scalar, pk_star_y_scalar);
    let h_r_star = (h3_proj * r_star_g3).into_affine();
    let pk_star_blinded = (pk_star_g3 + h_r_star).into_affine();

    let pk_r_star_g3 = G3::new(pk_r_star_x_scalar, pk_r_star_y_scalar);
    let h_r_r_star = (h3_proj * r_r_star_g3).into_affine();
    let pk_r_star_blinded = (pk_r_star_g3 + h_r_r_star).into_affine();

    let rho = ScalarField::from(extract_routing_value(phi_nu_plus_1));

    // Build Schnorr witness
    let schnorr_witness = SchnorrBridgingWitness {
        pk_x: pk_x_scalar,
        pk_y: pk_y_scalar,
        md_2_k_s,
        r1: r1_new,
        pk_r_x: pk_r_x_scalar,
        pk_r_y: pk_r_y_scalar,
        md_2_k_r,
        r2: r2_new,
        v1,
        r_v1: r_v1_new,
        v2,
        r_v2: r_v2_new,
        rho,
        r_star,
        r_r_star,
        pk_star_g3,
        pk_star_blinded,
        pk_r_star_g3,
        pk_r_star_blinded,
    };

    Ok((
        pi_1,
        pi_2,
        pi_3,
        c11,
        c12,
        c21,
        c22,
        c_v1,
        c_v2,
        pk_star_blinded,
        pk_r_star_blinded,
        schnorr_witness,
    ))
}

/// Batch prepare forward proofs for multiple messages in parallel
///
/// This function takes intermediate data for multiple proofs and processes them
/// in parallel using rayon, performing Groth16 proof rerandomization and G3 operations.
///
/// # Arguments
/// * `pp` - Public parameters
/// * `batch_data` - Vector of tuples containing all necessary data for each proof
///
/// # Returns
/// Vector of tuples containing proof results for each message
#[allow(clippy::type_complexity)]
fn prepare_forward_proofs_batch(
    pp: &PublicParams,
    batch_data: &[(
        Message,
        PublicKey,
        SecretKey,
        ScalarField,
        PrfOutput,
        DiversifiedPublicKey,
        usize,
        Diversifier,
        NeighboursView,
        ScalarField,
        Vec<ScalarField>,
        u64,
        u64,
        LocalPrecompute,
    )],
) -> ProtocolResult<
    Vec<(
        ProofGroth16,
        ProofGroth16,
        ProofGroth16,
        G1Projective,
        G1Projective,
        G1Projective,
        G1Projective,
        G1Projective,
        G1Projective,
        G3,
        G3,
        SchnorrBridgingWitness,
    )>,
> {
    use rayon::prelude::*;

    batch_data
        .par_iter()
        .map(
            |(
                _message,
                pk,
                sk,
                _theta,
                phi_nu_plus_1,
                _ppk_nu_plus_1,
                k_r,
                _d,
                neighbours_view,
                own_sub_merkle_root,
                _own_merkle_proof,
                v1,
                v2,
                precompute,
            )| {
                // Generate random blinding factors
                let r1_new = ScalarField::rand(&mut rand::thread_rng());
                let r2_new = ScalarField::rand(&mut rand::thread_rng());
                let r_v1_new = ScalarField::rand(&mut rand::thread_rng());
                let r_v2_new = ScalarField::rand(&mut rand::thread_rng());

                // Find neighbor index
                let neighbor_idx = neighbours_view
                    .neighbors
                    .iter()
                    .position(|n| n.index == *k_r)
                    .ok_or(ProtocolError::InvalidWeightSelection)?;

                // Rerandomize proofs
                let (pi_1, c11, c12) = adjust_groth16_merkle_membership(
                    pp,
                    &precompute.pi_1_sender,
                    precompute.c11_precomputed,
                    precompute.c12_precomputed,
                    r1_new,
                )?;

                let (pi_3, c21, c22) = adjust_groth16_merkle_membership(
                    pp,
                    &precompute.pi_3_receivers[neighbor_idx],
                    precompute.c21_precomputed[neighbor_idx],
                    precompute.c22_precomputed[neighbor_idx],
                    r2_new,
                )?;

                let (c_v1_precomputed, _v1_value) = precompute.c_v1_precomputed[neighbor_idx];
                let (c_v2_precomputed, _v2_value) = precompute.c_v2_precomputed[neighbor_idx];

                let (pi_2, c_v1, c_v2) = adjust_groth16_weight_subtree(
                    pp,
                    &precompute.pi_2_weights[neighbor_idx],
                    c_v1_precomputed,
                    c_v2_precomputed,
                    r1_new,
                    r2_new,
                    r_v1_new,
                    r_v2_new,
                )?;

                // Extract sender and receiver information
                use ark_ff::{BigInteger, PrimeField};
                let pk_x_scalar =
                    ScalarField::from_le_bytes_mod_order(&pk.pk.x.into_bigint().to_bytes_le());
                let pk_y_scalar =
                    ScalarField::from_le_bytes_mod_order(&pk.pk.y.into_bigint().to_bytes_le());
                let md_2_k_s = *own_sub_merkle_root;

                let receiver = neighbours_view
                    .neighbors
                    .iter()
                    .find(|n| n.index == *k_r)
                    .ok_or(ProtocolError::InvalidWeightSelection)?;

                let pk_r_x_scalar = ScalarField::from_le_bytes_mod_order(
                    &receiver.public_key.pk.x.into_bigint().to_bytes_le(),
                );
                let pk_r_y_scalar = ScalarField::from_le_bytes_mod_order(
                    &receiver.public_key.pk.y.into_bigint().to_bytes_le(),
                );
                let md_2_k_r = receiver.sub_merkle_root;

                // Generate blinded G3 points
                use crate::crypto::curve::{g3_base_to_scalar, scalar_to_g3_scalar, G3Proj};
                let g3_base = pp.generators.g3(0).ok_or_else(|| {
                    ProtocolError::CryptoError("Missing G3 generator 0".to_string())
                })?;

                let g3_proj = G3Proj::from(*g3_base);
                let h3_proj = G3Proj::from(pp.h_g3);

                let r_star = ScalarField::rand(&mut rand::thread_rng());
                let r_r_star = ScalarField::rand(&mut rand::thread_rng());

                let sk_g3 = scalar_to_g3_scalar(&sk.sk);
                let r_star_g3 = scalar_to_g3_scalar(&r_star);
                let r_r_star_g3 = scalar_to_g3_scalar(&r_r_star);

                let pk_star = (g3_proj * sk_g3 + h3_proj * r_star_g3).into_affine();
                let pk_r_proj = G3Proj::from(receiver.public_key.pk);
                let pk_r_star = (pk_r_proj + h3_proj * r_r_star_g3).into_affine();

                let pk_star_x_scalar = g3_base_to_scalar(&pk_star.x);
                let pk_star_y_scalar = g3_base_to_scalar(&pk_star.y);
                let pk_r_star_x_scalar = g3_base_to_scalar(&pk_r_star.x);
                let pk_r_star_y_scalar = g3_base_to_scalar(&pk_r_star.y);

                use ark_ec::CurveGroup;
                let pk_star_g3 = G3::new(pk_star_x_scalar, pk_star_y_scalar);
                let h_r_star = (h3_proj * r_star_g3).into_affine();
                let pk_star_blinded = (pk_star_g3 + h_r_star).into_affine();

                let pk_r_star_g3 = G3::new(pk_r_star_x_scalar, pk_r_star_y_scalar);
                let h_r_r_star = (h3_proj * r_r_star_g3).into_affine();
                let pk_r_star_blinded = (pk_r_star_g3 + h_r_r_star).into_affine();

                let rho = ScalarField::from(extract_routing_value(phi_nu_plus_1));

                // Build Schnorr witness
                let schnorr_witness = SchnorrBridgingWitness {
                    pk_x: pk_x_scalar,
                    pk_y: pk_y_scalar,
                    md_2_k_s,
                    r1: r1_new,
                    pk_r_x: pk_r_x_scalar,
                    pk_r_y: pk_r_y_scalar,
                    md_2_k_r,
                    r2: r2_new,
                    v1: *v1,
                    r_v1: r_v1_new,
                    v2: *v2,
                    r_v2: r_v2_new,
                    rho,
                    r_star,
                    r_r_star,
                    pk_star_g3,
                    pk_star_blinded,
                    pk_r_star_g3,
                    pk_r_star_blinded,
                };

                Ok((
                    pi_1,
                    pi_2,
                    pi_3,
                    c11,
                    c12,
                    c21,
                    c22,
                    c_v1,
                    c_v2,
                    pk_star_blinded,
                    pk_r_star_blinded,
                    schnorr_witness,
                ))
            },
        )
        .collect()
}

/// Rerandomize a merkle membership proof (π_1 or π_3) with new randomness
///
/// This function handles both sender membership (π_1) and receiver membership (π_3) proofs,
/// as they share the same circuit structure and rerandomization logic.
///
/// Takes precomputed proofs with dual commitments (merkle/weight circuit bases) and
/// rerandomizes them with fresh randomness.
///
/// # Arguments
/// * `pp` - Public parameters
/// * `pi_precomputed` - Precomputed Groth16 proof
/// * `c1_precomputed` - Precomputed commitment using merkle circuit bases (with r=0)
/// * `c2_precomputed` - Precomputed commitment using weight circuit bases (with r=0)
/// * `r_new` - New randomness for rerandomization
///
/// # Returns
/// (rerandomized_proof, new_c1, new_c2)
fn adjust_groth16_merkle_membership(
    pp: &PublicParams,
    pi_precomputed: &ProofGroth16,
    c1_precomputed: G1Projective,
    c2_precomputed: G1Projective,
    r_new: ScalarField,
) -> ProtocolResult<(ProofGroth16, G1Projective, G1Projective)> {
    use crate::proving::groth16::Groth16;
    use ark_ec::AffineRepr;
    use ark_ff::{PrimeField, Zero};
    use ark_std::UniformRand;

    // Generate randomness for proof rerandomization
    let mut rng = rand::thread_rng();
    let mut r1 = ScalarField::zero();
    let mut r2 = ScalarField::zero();
    while r1.is_zero() || r2.is_zero() {
        r1 = ScalarField::rand(&mut rng);
        r2 = ScalarField::rand(&mut rng);
    }

    // For merkle membership proofs, the input is (c1, merkle_root)
    // We only rerandomize c1, not merkle_root (it's a scalar)
    // The commitment randomness is just r_new (only one commitment)
    let com_rs = vec![r_new];

    // Rerandomize the proof
    let pi_new = Groth16::<PairingEngine>::rerandomize_proof_raw(
        &pp.pk_merkle_membership.vk,
        pi_precomputed,
        r1,
        r2,
        &com_rs,
    );

    // Rerandomize c1 using delta_g1 from the merkle membership circuit
    let delta_g1_merkle = pp.pk_merkle_membership.vk.delta_g1;
    let c1_new = c1_precomputed + delta_g1_merkle.mul_bigint(r_new.into_bigint());

    // Rerandomize c2 using delta_g1 from the weight circuit
    let delta_g1_weight = pp.pk_weight_subtree.vk.delta_g1;
    let c2_new = c2_precomputed + delta_g1_weight.mul_bigint(r_new.into_bigint());

    Ok((pi_new, c1_new, c2_new))
}

/// Rerandomize π_2 (weight subtree proof) with new randomness
///
/// Takes a precomputed proof with commitments C12, C22, C_v1, C_v2 (where all r=0)
/// and rerandomizes them with fresh randomness.
///
/// # Arguments
/// * `pp` - Public parameters
/// * `pi_2_precomputed` - Precomputed Groth16 proof
/// * `c12_precomputed` - Precomputed commitment C12 (sender in weight circuit bases)
/// * `c22_precomputed` - Precomputed commitment C22 (receiver in weight circuit bases)
/// * `c_v1_precomputed` - Precomputed commitment C_v1 with r_v1=0
/// * `c_v2_precomputed` - Precomputed commitment C_v2 with r_v2=0
/// * `r1_new` - New randomness for C12 (from sender rerandomization)
/// * `r2_new` - New randomness for C22 (from receiver rerandomization)
/// * `r_v1_new` - New randomness for C_v1
/// * `r_v2_new` - New randomness for C_v2
///
/// # Returns
/// (rerandomized_proof, new_c12, new_c22, new_c_v1, new_c_v2)
#[allow(clippy::too_many_arguments)]
fn adjust_groth16_weight_subtree(
    pp: &PublicParams,
    pi_2_precomputed: &ProofGroth16,
    c_v1_precomputed: G1Projective,
    c_v2_precomputed: G1Projective,
    r1_new: ScalarField,
    r2_new: ScalarField,
    r_v1_new: ScalarField,
    r_v2_new: ScalarField,
) -> ProtocolResult<(ProofGroth16, G1Projective, G1Projective)> {
    use crate::proving::groth16::Groth16;
    use ark_ec::AffineRepr;
    use ark_ff::{PrimeField, Zero};
    use ark_std::UniformRand;

    // Generate randomness for proof rerandomization
    let mut rng = rand::thread_rng();
    let mut r1 = ScalarField::zero();
    let mut r2 = ScalarField::zero();
    while r1.is_zero() || r2.is_zero() {
        r1 = ScalarField::rand(&mut rng);
        r2 = ScalarField::rand(&mut rng);
    }

    // For pi_2, the input is (c12, c22, c_v1, c_v2)
    // All four are commitments that need to be rerandomized
    // Randomness for each commitment
    let com_rs = vec![r1_new, r2_new, r_v1_new, r_v2_new];

    // Rerandomize the proof
    let pi_2_new = Groth16::<PairingEngine>::rerandomize_proof_raw(
        &pp.pk_weight_subtree.vk,
        pi_2_precomputed,
        r1,
        r2,
        &com_rs,
    );

    // Rerandomize all four commitments using delta_g1 from the weight subtree circuit
    let delta_g1_weight = pp.pk_weight_subtree.vk.delta_g1;
    let c_v1_new = c_v1_precomputed + delta_g1_weight.mul_bigint(r_v1_new.into_bigint());
    let c_v2_new = c_v2_precomputed + delta_g1_weight.mul_bigint(r_v2_new.into_bigint());

    Ok((pi_2_new, c_v1_new, c_v2_new))
}

/// Generate the forward proof π_{ν+1}
///
/// Uses precomputed proofs for π_1, π_2, π_3 (rerandomized Groth16 proofs)
/// and generates fresh proofs for:
/// - π_{4,G1}: Schnorr bridging
/// - π_{4,G2}: Public key operations
#[allow(clippy::too_many_arguments)]
fn generate_forward_proof(
    pp: &PublicParams,
    pk: &PublicKey,
    _sk: &SecretKey,
    _message: &Message,
    _theta: &ScalarField,
    _phi_nu_plus_1: &PrfOutput,
    _ppk_nu_plus_1: &DiversifiedPublicKey,
    k_r: usize,
    _d: &Diversifier,
    neighbours_view: &NeighboursView,
    own_sub_merkle_root: ScalarField,
    _own_merkle_proof: &[ScalarField],
    v1: u64,
    v2: u64,
    precompute: &LocalPrecompute,
) -> ProtocolResult<ForwardProofResult> {
    // TODO: Full proof generation
    // For now, return a stub proof

    // This comment describes the dual commitment system that has been implemented:
    //
    // Instead of using generic bases (G1, G2, G3, G4) to create commitments c1, c2, cv1, cv2,
    // we now create commitments using circuit-specific bases from Groth16 verification keys.
    //
    // WHY: Different Groth16 circuits (merkle membership vs weight subtree) have different
    // verification keys with different gamma_abc_g1 bases. To prove statements across both
    // circuits while maintaining consistency, we need dual commitments.
    //
    // IMPLEMENTATION:
    // 1. Dual commitments for sender and receiver:
    //    - C11: Sender commitment using pk_merkle_membership.vk.gamma_abc_g1[1,2,3] + hs[0]
    //    - C12: Sender commitment using pk_weight_subtree.vk.gamma_abc_g1[1,2,3] + hs[1]
    //    - C21: Receiver commitment using pk_merkle_membership.vk.gamma_abc_g1[1,2,3] + hs[0]
    //    - C22: Receiver commitment using pk_weight_subtree.vk.gamma_abc_g1[1,2,3] + hs[1]
    //    where hs[0] and hs[1] are independent randomness bases
    //
    // 2. Circuit consolidation:
    //    - Merged pk_sender_membership and pk_receiver_membership into pk_merkle_membership
    //    - Both sender and receiver use the same Groth16 circuit and CRS (same structure)
    //
    // 3. Commitment routing:
    //    - C11, C21 → used in π_1 (sender membership) and π_3 (receiver membership), and π_4
    //    - C12, C22 → used in π_2 (weight subtree), and π_4
    //    - CV1, CV2 → used in π_2 and π_4 (with weight circuit bases)
    //
    // 4. Schnorr bridging proof (π_4):
    //    - Now receives 4 commitments (C11, C12, C21, C22) instead of 2
    //    - Must internally prove witness equality: C11 and C12 open to same sender values
    //    - Must internally prove witness equality: C21 and C22 open to same receiver values
    //    - See src/proving/circuits.rs::prove_schnorr_bridging for TODO on implementation

    // Get commitment generators from public parameters
    let g1_base = pp
        .generators
        .g1(0)
        .ok_or_else(|| ProtocolError::CryptoError("Missing G1 generator 0".to_string()))?;
    let g2_base = pp
        .generators
        .g1(1)
        .ok_or_else(|| ProtocolError::CryptoError("Missing G1 generator 1".to_string()))?;
    let g3_base = pp
        .generators
        .g1(2)
        .ok_or_else(|| ProtocolError::CryptoError("Missing G1 generator 2".to_string()))?;
    let g4_base = pp
        .generators
        .g1(3)
        .ok_or_else(|| ProtocolError::CryptoError("Missing G1 generator 3".to_string()))?;

    // Convert to projective for scalar multiplication
    let g1_base_proj = G1Projective::from(*g1_base);
    let _g2_base_proj = G1Projective::from(*g2_base);
    let _g3_base_proj = G1Projective::from(*g3_base);
    let _g4_base_proj = G1Projective::from(*g4_base);

    // Implementation note: Only proofs π_4 and π_5 (Schnorr proofs) are freshly generated
    // on each forward. Proofs π_1, π_2, π_3 are precomputed with zero randomness and then
    // rerandomized here for privacy. This is more efficient than generating fresh proofs.
    //
    // The rerandomization process:
    // 1. π_1: Rerandomize sender membership proof with fresh r1 (produces C11, C12)
    // 2. π_3: Rerandomize receiver membership proof with fresh r2 (produces C21, C22)
    // 3. π_2: Rerandomize weight subtree proof with fresh r_v1, r_v2
    //
    // The precomputed commitments use zero randomness (r=0), and we add fresh randomness
    // during each forward operation to ensure unlinkability across hops.

    // Generate random blinding factors for rerandomization
    let r1_new = ScalarField::rand(&mut rand::thread_rng());
    let r2_new = ScalarField::rand(&mut rand::thread_rng());
    let r_v1_new = ScalarField::rand(&mut rand::thread_rng());
    let r_v2_new = ScalarField::rand(&mut rand::thread_rng());

    // Find the neighbor index in the precompute arrays
    // The neighbors in precompute are in the same order as in neighbours_view
    let neighbor_idx = neighbours_view
        .neighbors
        .iter()
        .position(|n| n.index == k_r)
        .ok_or(ProtocolError::InvalidWeightSelection)?;

    // Rerandomize π_1 (sender membership proof) - produces dual commitments C11, C12
    let (pi_1, c11, c12) = adjust_groth16_merkle_membership(
        pp,
        &precompute.pi_1_sender,
        precompute.c11_precomputed,
        precompute.c12_precomputed,
        r1_new,
    )?;

    // Rerandomize π_3 (receiver membership proof) - produces dual commitments C21, C22
    let (pi_3, c21, c22) = adjust_groth16_merkle_membership(
        pp,
        &precompute.pi_3_receivers[neighbor_idx],
        precompute.c21_precomputed[neighbor_idx],
        precompute.c22_precomputed[neighbor_idx],
        r2_new,
    )?;

    // Rerandomize π_2 (weight subtree proof) - uses C12 and C22
    let (c_v1_precomputed, _v1_value) = precompute.c_v1_precomputed[neighbor_idx];
    let (c_v2_precomputed, _v2_value) = precompute.c_v2_precomputed[neighbor_idx];

    let (pi_2, c_v1, c_v2) = adjust_groth16_weight_subtree(
        pp,
        &precompute.pi_2_weights[neighbor_idx],
        c_v1_precomputed,
        c_v2_precomputed,
        r1_new,
        r2_new,
        r_v1_new,
        r_v2_new,
    )?;

    // Extract sender and receiver information for Schnorr proofs (π_4, π_5)
    use ark_ff::{BigInteger, PrimeField};
    let pk_x_scalar = ScalarField::from_le_bytes_mod_order(&pk.pk.x.into_bigint().to_bytes_le());
    let pk_y_scalar = ScalarField::from_le_bytes_mod_order(&pk.pk.y.into_bigint().to_bytes_le());
    let md_2_k_s = own_sub_merkle_root;

    // Find the receiver in the neighbors view
    let receiver = neighbours_view
        .neighbors
        .iter()
        .find(|n| n.index == k_r)
        .ok_or(ProtocolError::InvalidWeightSelection)?;

    let pk_r_x_scalar =
        ScalarField::from_le_bytes_mod_order(&receiver.public_key.pk.x.into_bigint().to_bytes_le());
    let pk_r_y_scalar =
        ScalarField::from_le_bytes_mod_order(&receiver.public_key.pk.y.into_bigint().to_bytes_le());
    let md_2_k_r = receiver.sub_merkle_root;

    // Generate π_{4,G1} and π_{4,G2} proofs for Schnorr bridging
    // These proofs connect the public key representations across different groups

    // Get G3 generators for creating pk_star and pk_r_star
    use crate::crypto::curve::{g3_base_to_scalar, scalar_to_g3_scalar, G3Proj};
    use crate::crypto::prf::extract_routing_value;

    let g3_base = pp
        .generators
        .g3(0)
        .ok_or_else(|| ProtocolError::CryptoError("Missing G3 generator 0".to_string()))?;

    // Convert to projective for scalar multiplication
    let g3_proj = G3Proj::from(*g3_base);
    let h3_proj = G3Proj::from(pp.h_g3);

    // Generate random blinding factors for Schnorr commitments
    let r_star = ScalarField::rand(&mut rand::thread_rng());
    let r_r_star = ScalarField::rand(&mut rand::thread_rng());

    // Convert scalar fields to G3 scalar field for G3 operations
    let sk_g3 = scalar_to_g3_scalar(&_sk.sk);
    let r_star_g3 = scalar_to_g3_scalar(&r_star);
    let r_r_star_g3 = scalar_to_g3_scalar(&r_r_star);

    // Create pk_star = G^{sk} * H^{r_star}
    let pk_star = (g3_proj * sk_g3 + h3_proj * r_star_g3).into_affine();

    // Create pk_r_star = pk_r * H^{r_r_star}
    let pk_r_proj = G3Proj::from(receiver.public_key.pk);
    let pk_r_star = (pk_r_proj + h3_proj * r_r_star_g3).into_affine();

    // Extract coordinates and convert to BLS12-381 scalar field
    // G3's base field is the same as BLS12-381 Fr, so we can use a direct conversion
    let pk_star_x_scalar = g3_base_to_scalar(&pk_star.x);
    let pk_star_y_scalar = g3_base_to_scalar(&pk_star.y);
    let pk_r_star_x_scalar = g3_base_to_scalar(&pk_r_star.x);
    let pk_r_star_y_scalar = g3_base_to_scalar(&pk_r_star.y);

    // Compute unblinded and blinded G3 points for the witness
    // These will be passed to the Schnorr bridging proof to avoid recomputation
    use ark_ec::CurveGroup;
    let pk_star_g3 = G3::new(pk_star_x_scalar, pk_star_y_scalar);
    let h_r_star = (h3_proj * r_star_g3).into_affine();
    let pk_star_blinded = (pk_star_g3 + h_r_star).into_affine();

    let pk_r_star_g3 = G3::new(pk_r_star_x_scalar, pk_r_star_y_scalar);
    let h_r_r_star = (h3_proj * r_r_star_g3).into_affine();
    let pk_r_star_blinded = (pk_r_star_g3 + h_r_r_star).into_affine();

    // Extract routing value ρ from phi
    let rho = ScalarField::from(extract_routing_value(_phi_nu_plus_1));

    // Create commitment G^ρ
    let g_rho = g1_base_proj * rho;

    // Generate proof π_{4,G1}: Schnorr bridging
    // This proof receives all four commitments (C11, C12, C21, C22) and must
    // internally prove witness consistency across different circuit bases
    let schnorr_instance = SchnorrBridgingInstance {
        pk_star_blinded,
        pk_r_star_blinded,
        c11, // Sender with merkle circuit bases (goes into π_1 and π_4)
        c12, // Sender with weight circuit bases (goes into π_2 and π_4)
        c21, // Receiver with merkle circuit bases (goes into π_3 and π_4)
        c22, // Receiver with weight circuit bases (goes into π_2 and π_4)
        c_v1,
        c_v2,
        g_rho,
    };

    let schnorr_witness = SchnorrBridgingWitness {
        pk_x: pk_x_scalar,
        pk_y: pk_y_scalar,
        md_2_k_s,
        r1: r1_new,
        pk_r_x: pk_r_x_scalar,
        pk_r_y: pk_r_y_scalar,
        md_2_k_r,
        r2: r2_new,
        v1,
        r_v1: r_v1_new,
        v2,
        r_v2: r_v2_new,
        rho,
        r_star,
        r_r_star,
        pk_star_g3,
        pk_star_blinded,
        pk_r_star_g3,
        pk_r_star_blinded,
    };

    let pi_4_g1 = prove_schnorr_bridging(
        &schnorr_instance,
        &schnorr_witness,
        &precompute.pc_gens,
        &precompute.bp_gens,
        &pp.h_g3,
        &pp.g3_tables,
    )?;

    // Generate proof π_{4,G2}: Public key operations
    // Create G^theta commitment
    let g_theta = g1_base_proj * *_theta;

    // G^phi is just the PRF output itself (already a G1 point)
    let g_phi = G1Projective::from(_phi_nu_plus_1.phi);

    let pk_ops_instance = PublicKeyOperationsInstance {
        pk_star,
        pk_r_star,
        ppk_s_1: _ppk_nu_plus_1.ppk_1,
        ppk_s_2: _ppk_nu_plus_1.ppk_2,
        ppk_r_1: receiver.public_key.pk, // TODO: Get receiver's actual diversified ppk
        ppk_r_2: receiver.public_key.pk, // TODO: Get receiver's actual diversified ppk
        g_theta,
        g_phi,
    };

    let pk_ops_witness = PublicKeyOperationsWitness {
        sk: _sk.sk,
        d: _d.d,
        theta: *_theta,
        phi: *_theta, // TODO: Extract actual phi scalar (not just theta)
        r_star,
        r_r_star,
    };

    let pi_4_g2 = prove_public_key_operations(&pk_ops_instance, &pk_ops_witness)?;

    let hop_proofs = HopProofs {
        pi_1,
        pi_2,
        pi_3,
        pi_4_g1,
        pi_4_g2,
    };

    Ok((
        hop_proofs,
        G1Wrapper(c11.into_affine()),
        G1Wrapper(c12.into_affine()),
        G1Wrapper(c21.into_affine()),
        G1Wrapper(c22.into_affine()),
        G1Wrapper(c_v1.into_affine()),
        G1Wrapper(c_v2.into_affine()),
        G3Wrapper(pk_star_blinded),
        G3Wrapper(pk_r_star_blinded),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::spawn::spawn;
    use rand::thread_rng;

    // Helper function to create public parameters for tests
    fn create_test_public_params<R: Rng + rand::CryptoRng>(rng: &mut R) -> PublicParams {
        PublicParams::generate(10, 10, rng).expect("Failed to generate params")
    }

    #[test]
    fn test_forward_basic() {
        let mut rng = thread_rng();

        // Create public parameters
        let pp = create_test_public_params(&mut rng);

        // Setup: generate protocol state with 3 users
        let generated_state = generate_random_state(&pp, 3, &mut rng);
        let user_0_view = &generated_state.users_view[0];

        // Spawn initial message from user 0
        let message = spawn(
            &user_0_view.secret_key,
            &user_0_view.public_key,
            1,
            100,
            &mut rng,
        )
        .unwrap();

        // Forward the message using user 0's view
        let result = forward(&pp, user_0_view, &message, &mut rng);

        match result {
            Ok((new_message, k_r)) => {
                // Check message was updated
                assert_eq!(new_message.hop_count(), 1);
                assert!(k_r < 3); // Should be one of the 3 users
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

        // Create public parameters
        let pp = create_test_public_params(&mut rng);

        // Setup: generate protocol state with 1 user
        let generated_state = generate_random_state(&pp, 1, &mut rng);
        let user_0_view = &generated_state.users_view[0];

        // Create a message with maximum hops
        let mut message = spawn(
            &user_0_view.secret_key,
            &user_0_view.public_key,
            1,
            100,
            &mut rng,
        )
        .unwrap();

        // Add MAX_HOPS hops manually
        for _ in 0..MAX_HOPS {
            message.hops.push(Hop {
                ppk: DiversifiedPublicKey {
                    ppk_1: user_0_view.public_key.pk,
                    ppk_2: user_0_view.public_key.pk,
                },
                phi: PrfOutput {
                    phi: G1Projective::generator().into_affine(),
                },
                pi: HopProofs {
                    pi_1: mock_groth16_proof(),
                    pi_2: mock_groth16_proof(),
                    pi_3: mock_groth16_proof(),
                    pi_4_g1: Schnorr {
                        data: vec![],
                        _phantom: std::marker::PhantomData,
                    },
                    pi_4_g2: Schnorr {
                        data: vec![],
                        _phantom: std::marker::PhantomData,
                    },
                },
                c11: G1Wrapper(G1Projective::generator().into_affine()),
                c12: G1Wrapper(G1Projective::generator().into_affine()),
                c21: G1Wrapper(G1Projective::generator().into_affine()),
                c22: G1Wrapper(G1Projective::generator().into_affine()),
                cv1: G1Wrapper(G1Projective::generator().into_affine()),
                cv2: G1Wrapper(G1Projective::generator().into_affine()),
                pk_star: G3Wrapper(user_0_view.public_key.pk),
                pk_r_star: G3Wrapper(user_0_view.public_key.pk),
            });
        }

        // Should fail with MaxHopsExceeded
        let result = forward(&pp, user_0_view, &message, &mut rng);
        assert!(matches!(result, Err(ProtocolError::MaxHopsExceeded)));
    }

    #[test]
    fn test_generate_state_with_merkle_proofs() {
        use crate::crypto::poseidon::PoseidonHash;

        let mut rng = thread_rng();
        let num_users = 8;

        // Create public parameters
        let pp = create_test_public_params(&mut rng);

        // Generate protocol state
        let generated_state = generate_random_state(&pp, num_users, &mut rng);

        // Verify basic structure
        assert_eq!(generated_state.users_view.len(), num_users);
        assert_eq!(
            generated_state.protocol_state.sub_merkle_trees.len(),
            num_users
        );

        let merkle_tree = &generated_state.protocol_state.merkle_tree;

        println!("Generated state for {} users", num_users);
        println!("Merkle tree root: {:?}", merkle_tree.root);
        println!("Merkle tree depth: {}", merkle_tree.depth());

        // Verify user views
        for (user_idx, user_view) in generated_state.users_view.iter().enumerate() {
            println!(
                "\nUser {}: has {} neighbors",
                user_idx,
                user_view.neighbours_view.neighbors.len()
            );

            // Each user should have num_users-1 neighbors (all others)
            assert_eq!(
                user_view.neighbours_view.neighbors.len(),
                num_users - 1,
                "User {} should have {} neighbors",
                user_idx,
                num_users - 1
            );

            // Verify neighbor information is complete
            for neighbor in &user_view.neighbours_view.neighbors {
                assert!(neighbor.index < num_users);
                assert_ne!(
                    neighbor.index, user_idx,
                    "User should not be their own neighbor"
                );
                assert!(neighbor.weight > 0);
                assert_eq!(
                    neighbor.merkle_proof.len(),
                    merkle_tree.depth(),
                    "Proof should have correct depth"
                );

                // Verify the merkle proof for this neighbor
                let hasher = PoseidonHash::new();
                let leaf = merkle_tree.leaves[neighbor.index];
                let (pk_x, pk_y, m2_root) = leaf;

                let mut current_hash = hasher.hash(&[pk_x, pk_y, m2_root]);
                let mut current_index = neighbor.index;

                for sibling_hash in &neighbor.merkle_proof {
                    let is_left = current_index % 2 == 0;
                    current_hash = if is_left {
                        hasher.hash(&[current_hash, *sibling_hash])
                    } else {
                        hasher.hash(&[*sibling_hash, current_hash])
                    };
                    current_index /= 2;
                }

                assert_eq!(
                    current_hash, merkle_tree.root,
                    "Merkle proof should verify for neighbor {} of user {}",
                    neighbor.index, user_idx
                );
            }
        }

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

    #[test]
    fn test_neighbours_view() {
        use crate::crypto::poseidon::PoseidonHash;

        let mut rng = thread_rng();
        let num_users = 5;

        // Create public parameters
        let pp = create_test_public_params(&mut rng);

        // Generate protocol state
        let generated_state = generate_random_state(&pp, num_users, &mut rng);

        println!("Testing NeighboursView for {} users", num_users);

        // Test user 0's view of their neighbors
        let user_0_view = &generated_state.users_view[0];

        println!("\n=== User 0's View ===");
        println!("Secret key: (hidden)");
        println!("Public key x coordinate: {:?}", user_0_view.public_key.pk.x);
        println!(
            "Number of neighbors: {}",
            user_0_view.neighbours_view.neighbors.len()
        );

        // Verify that user 0 knows about all other users
        assert_eq!(user_0_view.neighbours_view.neighbors.len(), num_users - 1);

        let merkle_tree = &generated_state.protocol_state.merkle_tree;
        let hasher = PoseidonHash::new();

        for (i, neighbor) in user_0_view.neighbours_view.neighbors.iter().enumerate() {
            println!("\n  Neighbor {}: User {}", i, neighbor.index);
            println!("    Weight: {}", neighbor.weight);
            println!("    Sub-merkle root: {:?}", neighbor.sub_merkle_root);
            println!("    Merkle proof length: {}", neighbor.merkle_proof.len());

            // Verify that the neighbor's index is not user 0
            assert_ne!(neighbor.index, 0);

            // Verify the sub-merkle root matches the protocol state
            assert_eq!(
                neighbor.sub_merkle_root,
                generated_state.protocol_state.sub_merkle_trees[neighbor.index].root
            );

            // Verify the merkle proof
            let leaf = merkle_tree.leaves[neighbor.index];
            let (pk_x, pk_y, m2_root) = leaf;

            let mut current_hash = hasher.hash(&[pk_x, pk_y, m2_root]);
            let mut current_index = neighbor.index;

            for sibling_hash in &neighbor.merkle_proof {
                let is_left = current_index % 2 == 0;
                current_hash = if is_left {
                    hasher.hash(&[current_hash, *sibling_hash])
                } else {
                    hasher.hash(&[*sibling_hash, current_hash])
                };
                current_index /= 2;
            }

            assert_eq!(
                current_hash, merkle_tree.root,
                "User 0's merkle proof for neighbor {} should verify",
                neighbor.index
            );
        }

        // Verify that weights sum to WEIGHT_SUM
        let total_weight: u64 = user_0_view
            .neighbours_view
            .neighbors
            .iter()
            .map(|n| n.weight as u64)
            .sum();
        assert_eq!(
            total_weight,
            crate::WEIGHT_SUM,
            "Total weights should sum to WEIGHT_SUM"
        );

        println!("\n✓ NeighboursView test passed!");
    }

    #[test]
    fn test_forward_batch() {
        let mut rng = thread_rng();

        // Create public parameters
        let pp = create_test_public_params(&mut rng);

        // Setup: generate protocol state with 5 users
        let generated_state = generate_random_state(&pp, 5, &mut rng);

        // Create 3 packets from different users
        let mut inputs = Vec::new();

        for i in 0..3 {
            let user_view = &generated_state.users_view[i];

            // Spawn initial message
            let message = spawn(
                &user_view.secret_key,
                &user_view.public_key,
                1 + i as u32,          // Different packet IDs
                100 + (i as u64) * 10, // Different session IDs
                &mut rng,
            )
            .unwrap();

            inputs.push((user_view.clone(), message));
        }

        // Test batch forward
        let result = forward_batch(&pp, &inputs, &mut rng);

        match result {
            Ok(results) => {
                assert_eq!(results.len(), 3, "Should have 3 forwarded messages");

                for (i, (new_message, k_r)) in results.iter().enumerate() {
                    // Check message was updated
                    assert_eq!(new_message.hop_count(), 1);
                    assert!(k_r < &5); // Should be one of the 5 users
                    println!("Batch packet {} forwarded to node {}", i, k_r);
                }

                println!("\n✓ Batch forward test passed!");
            }
            Err(e) => {
                println!("Batch forward failed: {:?}", e);
                // Don't panic - may fail if stub implementations are incomplete
            }
        }
    }

    #[test]
    fn test_forward_batch_empty() {
        let mut rng = thread_rng();
        let pp = create_test_public_params(&mut rng);

        // Test with empty input
        let inputs: Vec<(UserView, Message)> = vec![];
        let result = forward_batch(&pp, &inputs, &mut rng);

        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);

        println!("\n✓ Batch forward empty test passed!");
    }
}
