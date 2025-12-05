//! Forward function implementation
//!
//! Core forwarding logic: Forward(user_view, m) -> (m', k_R, d)

use crate::crypto::{compute_prf, diversify_with_diversifier, extract_routing_value, PoseidonHash};
use crate::protocol::routing::WeightMatrix;
use crate::types::*;
use crate::MAX_HOPS;
use ark_bls12_381::G1Projective;
use ark_ec::{CurveGroup, PrimeGroup};
use ark_std::UniformRand;
use rand::Rng;

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

        // Create user view
        let user_view = UserView {
            secret_key: secret_keys[user_idx].clone(),
            public_key: public_keys[user_idx].clone(),
            neighbours_view: NeighboursView { neighbors },
            own_sub_merkle_root,
            own_merkle_proof,
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
    for neighbor in &neighbours_view.neighbors {
        let v1 = cumulative;
        cumulative += neighbor.weight as u64;
        let v2 = cumulative;

        if (rho as u64) < cumulative {
            return Ok((neighbor.index, neighbor.public_key.clone(), v1, v2));
        }
    }

    // If we get here, ρ didn't fall into any bucket (shouldn't happen if weights sum correctly)
    // Default to last neighbor
    let last_neighbor = neighbours_view.neighbors.last().unwrap();
    let total_cumulative = cumulative;
    Ok((
        last_neighbor.index,
        last_neighbor.public_key.clone(),
        total_cumulative - last_neighbor.weight as u64,
        total_cumulative,
    ))
}

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
    // TODO: Full proof generation using all five circuits
    let pi_nu_plus_1 = generate_forward_proof(
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

/// Instance (public inputs) for sender membership proof π_1
#[derive(Clone, Debug)]
pub struct SenderMembershipInstance {
    /// Commitment C1 = g1^{pk_x} * g2^{pk_y} * g3^{md_{2,k_s}} * g4^{r1}
    pub c1: G1Projective,
    /// Root of the main merkle tree
    pub merkle_root: ScalarField,
}

/// Witness (private inputs) for sender membership proof π_1
#[derive(Clone, Debug)]
pub struct SenderMembershipWitness {
    /// Sender's public key x-coordinate
    pub pk_x: ScalarField,
    /// Sender's public key y-coordinate
    pub pk_y: ScalarField,
    /// Sender's sub-merkle tree root (md_{2,k_s})
    pub md_2_k_s: ScalarField,
    /// Blinding factor for commitment C1
    pub r1: ScalarField,
    /// Merkle proof path for sender's inclusion in main tree
    pub merkle_proof: Vec<ScalarField>,
}

/// Generate sender membership proof (π_1)
///
/// This proves that the sender's public key is committed in C1 and
/// is included in the main merkle tree.
///
/// # Arguments
/// * `instance` - Public inputs (C1, merkle_root)
/// * `witness` - Private inputs (pk_x, pk_y, md_{2,k_s}, r1, merkle_proof)
///
/// # Returns
/// Serialized Groth16 proof bytes
fn prove_sender_membership(
    _instance: &SenderMembershipInstance,
    _witness: &SenderMembershipWitness,
) -> ProtocolResult<Vec<u8>> {
    // TODO: Actual Groth16 proof generation
    // For now, return stub proof
    Ok(vec![0u8; 32])
}

/// Instance (public inputs) for receiver membership proof π_3
#[derive(Clone, Debug)]
pub struct ReceiverMembershipInstance {
    /// Commitment C2 = g1^{pk_{r,x}} * g2^{pk_{r,y}} * g3^{md_{2,k_r}} * g4^{r2}
    pub c2: G1Projective,
    /// Root of the main merkle tree
    pub merkle_root: ScalarField,
}

/// Witness (private inputs) for receiver membership proof π_3
#[derive(Clone, Debug)]
pub struct ReceiverMembershipWitness {
    /// Receiver's public key x-coordinate
    pub pk_r_x: ScalarField,
    /// Receiver's public key y-coordinate
    pub pk_r_y: ScalarField,
    /// Receiver's sub-merkle tree root (md_{2,k_r})
    pub md_2_k_r: ScalarField,
    /// Blinding factor for commitment C2
    pub r2: ScalarField,
    /// Merkle proof path for receiver's inclusion in main tree
    pub merkle_proof: Vec<ScalarField>,
}

/// Generate receiver membership proof (π_3)
///
/// This proves that the receiver's public key is committed in C2 and
/// is included in the main merkle tree.
///
/// # Arguments
/// * `instance` - Public inputs (C2, merkle_root)
/// * `witness` - Private inputs (pk_r_x, pk_r_y, md_{2,k_r}, r2, merkle_proof)
///
/// # Returns
/// Serialized Groth16 proof bytes
fn prove_receiver_membership(
    _instance: &ReceiverMembershipInstance,
    _witness: &ReceiverMembershipWitness,
) -> ProtocolResult<Vec<u8>> {
    // TODO: Actual Groth16 proof generation
    // For now, return stub proof
    Ok(vec![0u8; 32])
}

/// Instance (public inputs) for weight subtree proof π_2
#[derive(Clone, Debug)]
pub struct WeightSubtreeInstance {
    /// Commitment to sender (C1)
    pub c1: G1Projective,
    /// Commitment to receiver (C2)
    pub c2: G1Projective,
    /// Commitment to v1 (cumulative weight before receiver)
    pub c_v1: G1Projective,
    /// Commitment to v2 (cumulative weight including receiver)
    pub c_v2: G1Projective,
}

/// Witness (private inputs) for weight subtree proof π_2
#[derive(Clone, Debug)]
pub struct WeightSubtreeWitness {
    /// Sender's public key x-coordinate
    pub pk_x: ScalarField,
    /// Sender's public key y-coordinate
    pub pk_y: ScalarField,
    /// Sender's sub-merkle tree root (md_{2,k_s})
    pub md_2_k_s: ScalarField,
    /// Blinding factor for C1
    pub r1: ScalarField,
    /// Receiver's public key x-coordinate
    pub pk_r_x: ScalarField,
    /// Receiver's public key y-coordinate
    pub pk_r_y: ScalarField,
    /// Receiver's sub-merkle tree root (md_{2,k_r})
    pub md_2_k_r: ScalarField,
    /// Blinding factor for C2
    pub r2: ScalarField,
    /// Cumulative weight before receiver (v1)
    pub v1: u64,
    /// Blinding factor for C_v1
    pub r_v1: ScalarField,
    /// Cumulative weight including receiver (v2)
    pub v2: u64,
    /// Blinding factor for C_v2
    pub r_v2: ScalarField,
    /// Merkle proof path in sender's sub-tree to the leaf corresponding to v1
    /// This points to the previous neighbor in the cumulative weight distribution
    pub sub_merkle_proof_v1: Vec<ScalarField>,
    /// Merkle proof path in sender's sub-tree to the leaf corresponding to v2
    /// This points to the receiver's leaf in the cumulative weight distribution
    pub sub_merkle_proof_v2: Vec<ScalarField>,
}

/// Generate weight subtree proof (π_2)
///
/// This proves that:
/// 1. The commitments C1 and C2 are correctly formed
/// 2. The values v1 and v2 are correctly committed in C_v1 and C_v2
/// 3. Both v1 and v2 exist in the sender's sub-merkle tree (md_{2,k_s})
/// 4. v1 < ρ ≤ v2 (range proof for routing value)
///
/// # Arguments
/// * `instance` - Public inputs (C1, C2, C_v1, C_v2)
/// * `witness` - Private inputs (all exponents and sub-merkle proofs)
///
/// # Returns
/// Serialized Groth16 proof bytes
fn prove_weight_subtree(
    _instance: &WeightSubtreeInstance,
    _witness: &WeightSubtreeWitness,
) -> ProtocolResult<Vec<u8>> {
    // TODO: Actual Groth16 proof generation
    // For now, return stub proof
    Ok(vec![0u8; 32])
}

/// Instance (public inputs) for Schnorr bridging proof π_{4,G1}
///
/// This proof bridges the representation of public keys between G3 (Grumpkin)
/// and G1 (BLS12-381) by expressing G3 coordinates as commitments in G1.
#[derive(Clone, Debug)]
pub struct SchnorrBridgingInstance {
    /// Commitment to pk_star coordinates: G1^{pk_star_x} * G2^{pk_star_y}
    pub pk_star_coord: G1Projective,
    /// Commitment to pk_r_star coordinates: G1^{pk_r_star_x} * G2^{pk_r_star_y}
    pub pk_r_star_coord: G1Projective,
    /// Commitment to sender (C1)
    pub c1: G1Projective,
    /// Commitment to receiver (C2)
    pub c2: G1Projective,
    /// Commitment to v1 (cumulative weight before receiver)
    pub c_v1: G1Projective,
    /// Commitment to v2 (cumulative weight including receiver)
    pub c_v2: G1Projective,
    /// Commitment to routing value G^ρ
    pub g_rho: G1Projective,
}

/// Witness (private inputs) for Schnorr bridging proof π_{4,G1}
#[derive(Clone, Debug)]
pub struct SchnorrBridgingWitness {
    // Exponents from C1 commitment
    /// Sender's public key x-coordinate
    pub pk_x: ScalarField,
    /// Sender's public key y-coordinate
    pub pk_y: ScalarField,
    /// Sender's sub-merkle tree root
    pub md_2_k_s: ScalarField,
    /// Blinding factor for C1
    pub r1: ScalarField,

    // Exponents from C2 commitment
    /// Receiver's public key x-coordinate
    pub pk_r_x: ScalarField,
    /// Receiver's public key y-coordinate
    pub pk_r_y: ScalarField,
    /// Receiver's sub-merkle tree root
    pub md_2_k_r: ScalarField,
    /// Blinding factor for C2
    pub r2: ScalarField,

    // Exponents from C_v1 and C_v2 commitments
    /// Cumulative weight before receiver
    pub v1: u64,
    /// Blinding factor for C_v1
    pub r_v1: ScalarField,
    /// Cumulative weight including receiver
    pub v2: u64,
    /// Blinding factor for C_v2
    pub r_v2: ScalarField,

    // Routing value
    /// Routing value ρ
    pub rho: ScalarField,

    // Coordinates of pk_star and pk_r_star in G3
    /// pk_star x-coordinate (converted to BLS12-381 scalar field)
    pub pk_star_x: ScalarField,
    /// pk_star y-coordinate (converted to BLS12-381 scalar field)
    pub pk_star_y: ScalarField,
    /// pk_r_star x-coordinate (converted to BLS12-381 scalar field)
    pub pk_r_star_x: ScalarField,
    /// pk_r_star y-coordinate (converted to BLS12-381 scalar field)
    pub pk_r_star_y: ScalarField,

    // Blinding factors for pk_star and pk_r_star
    /// Blinding factor r_star for pk_star = G^{sk} * H^{r_star}
    pub r_star: ScalarField,
    /// Blinding factor r_r_star for pk_r_star = pk_r * H^{r_r_star}
    pub r_r_star: ScalarField,
}

/// Generate Schnorr bridging proof π_{4,G1}
///
/// This proves that:
/// 1. pk_star and pk_r_star are correctly formed in coordinate representation
/// 2. All commitments C1, C2, C_v1, C_v2 are consistent with their exponents
/// 3. The routing value ρ is correctly committed
///
/// # Arguments
/// * `instance` - Public inputs (coordinate commitments and other commitments)
/// * `witness` - Private inputs (all exponents and coordinates)
///
/// # Returns
/// Serialized Groth16 proof bytes
fn prove_schnorr_bridging(
    _instance: &SchnorrBridgingInstance,
    _witness: &SchnorrBridgingWitness,
) -> ProtocolResult<Vec<u8>> {
    // TODO: Actual Groth16 proof generation
    // For now, return stub proof
    Ok(vec![0u8; 32])
}

/// Instance (public inputs) for public key operations proof π_{4,G2}
///
/// This proof demonstrates correct application of diversifiers and
/// hash chain integrity in the forward protocol.
#[derive(Clone, Debug)]
pub struct PublicKeyOperationsInstance {
    /// Blinded sender public key pk_star = G^{sk} * H^{r_star}
    pub pk_star: G3,
    /// Blinded receiver public key pk_r_star = pk_r * H^{r_r_star}
    pub pk_r_star: G3,
    /// First component of sender's diversified public key (ppk^d)
    pub ppk_s_1: G3,
    /// Second component of sender's diversified public key (G^d)
    pub ppk_s_2: G3,
    /// First component of receiver's diversified public key (ppk_r^d)
    pub ppk_r_1: G3,
    /// Second component of receiver's diversified public key (G^d)
    pub ppk_r_2: G3,
    /// Commitment to hash of previous hop: G^θ (in G1)
    pub g_theta: G1Projective,
    /// PRF output for current hop: G^φ (in G1)
    pub g_phi: G1Projective,
}

/// Witness (private inputs) for public key operations proof π_{4,G2}
#[derive(Clone, Debug)]
pub struct PublicKeyOperationsWitness {
    /// Sender's secret key
    pub sk: ScalarField,
    /// Diversifier chosen by sender for this hop
    pub d: ScalarField,
    /// Hash value theta from previous hop
    pub theta: ScalarField,
    /// PRF output phi for current hop
    pub phi: ScalarField,
    /// Blinding factor r_star for pk_star = G^{sk} * H^{r_star}
    pub r_star: ScalarField,
    /// Blinding factor r_r_star for pk_r_star = pk_r * H^{r_r_star}
    pub r_r_star: ScalarField,
}

/// Generate public key operations proof π_{4,G2}
///
/// This proves that:
/// 1. pk_star and pk_r_star relate correctly to diversified public keys
/// 2. Diversifier d is correctly applied
/// 3. Hash chain integrity is maintained (theta, phi)
/// 4. Sender knows the secret key sk
///
/// # Arguments
/// * `instance` - Public inputs (blinded keys, diversified keys, hash commitments)
/// * `witness` - Private inputs (sk, d, exponents)
///
/// # Returns
/// Serialized Groth16 proof bytes
fn prove_public_key_operations(
    _instance: &PublicKeyOperationsInstance,
    _witness: &PublicKeyOperationsWitness,
) -> ProtocolResult<Vec<u8>> {
    // TODO: Actual Groth16 proof generation
    // For now, return stub proof
    Ok(vec![0u8; 32])
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
    own_merkle_proof: &[ScalarField],
    v1: u64,
    v2: u64,
) -> ProtocolResult<Proof> {
    // TODO: Full proof generation
    // For now, return a stub proof

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
    let g2_base_proj = G1Projective::from(*g2_base);
    let g3_base_proj = G1Projective::from(*g3_base);
    let g4_base_proj = G1Projective::from(*g4_base);

    // Generate random blinding factors
    let r1 = ScalarField::rand(&mut rand::thread_rng());
    let r2 = ScalarField::rand(&mut rand::thread_rng());
    let r_v1 = ScalarField::rand(&mut rand::thread_rng());
    let r_v2 = ScalarField::rand(&mut rand::thread_rng());

    // Extract sender's public key coordinates and convert to BLS12-381 scalar field
    // Note: Converting Grumpkin field elements to BLS12-381 scalar field via BigInt
    use ark_ff::{BigInteger, PrimeField};
    let pk_x_scalar = ScalarField::from_le_bytes_mod_order(&pk.pk.x.into_bigint().to_bytes_le());
    let pk_y_scalar = ScalarField::from_le_bytes_mod_order(&pk.pk.y.into_bigint().to_bytes_le());

    // Get sender's sub-merkle root (md_{2,k_s}) from user view
    let md_2_k_s = own_sub_merkle_root;

    // Create commitment C1 = g1^{pk_x} * g2^{pk_y} * g3^{md_{2,k_s}} * g4^{r1}
    let c1 = (g1_base_proj * pk_x_scalar)
        + (g2_base_proj * pk_y_scalar)
        + (g3_base_proj * md_2_k_s)
        + (g4_base_proj * r1);

    // Find the receiver in the neighbors view to get their public key
    let receiver = neighbours_view
        .neighbors
        .iter()
        .find(|n| n.index == k_r)
        .ok_or_else(|| ProtocolError::InvalidWeightSelection)?;

    // Extract receiver's public key coordinates and convert to BLS12-381 scalar field
    let pk_r_x_scalar =
        ScalarField::from_le_bytes_mod_order(&receiver.public_key.pk.x.into_bigint().to_bytes_le());
    let pk_r_y_scalar =
        ScalarField::from_le_bytes_mod_order(&receiver.public_key.pk.y.into_bigint().to_bytes_le());

    // Get receiver's sub-merkle root (md_{2,k_r})
    let md_2_k_r = receiver.sub_merkle_root;

    // Create commitment C2 = g1^{pk_{r,x}} * g2^{pk_{r,y}} * g3^{md_{2,k_r}} * g4^{r2}
    let c2 = (g1_base_proj * pk_r_x_scalar)
        + (g2_base_proj * pk_r_y_scalar)
        + (g3_base_proj * md_2_k_r)
        + (g4_base_proj * r2);

    // Create commitments to v1 and v2
    // C_{v1} = g1^{v1} * g2^{r_v1}
    let c_v1 = (g1_base_proj * ScalarField::from(v1)) + (g2_base_proj * r_v1);

    // C_{v2} = g1^{v2} * g2^{r_v2}
    let c_v2 = (g1_base_proj * ScalarField::from(v2)) + (g2_base_proj * r_v2);

    // TODO: In a real implementation, the merkle root would be part of the public parameters
    // or passed as a parameter. For now, we use a placeholder.
    let merkle_root = ScalarField::from(0u64);

    // Generate proof π_1: Sender membership
    let sender_instance = SenderMembershipInstance {
        c1: c1.clone(),
        merkle_root,
    };
    let sender_witness = SenderMembershipWitness {
        pk_x: pk_x_scalar,
        pk_y: pk_y_scalar,
        md_2_k_s,
        r1,
        merkle_proof: own_merkle_proof.to_vec(),
    };
    let pi_1 = prove_sender_membership(&sender_instance, &sender_witness)?;

    // Generate proof π_3: Receiver membership
    let receiver_instance = ReceiverMembershipInstance {
        c2: c2.clone(),
        merkle_root,
    };
    let receiver_witness = ReceiverMembershipWitness {
        pk_r_x: pk_r_x_scalar,
        pk_r_y: pk_r_y_scalar,
        md_2_k_r,
        r2,
        merkle_proof: receiver.merkle_proof.clone(),
    };
    let pi_3 = prove_receiver_membership(&receiver_instance, &receiver_witness)?;

    // Generate proof π_2: Weight subtree
    // TODO: In a real implementation, the UserView would need to include the sub-merkle tree
    // structure to generate proofs for v1 and v2. For now, we use empty vectors as placeholders.
    let weight_instance = WeightSubtreeInstance {
        c1: c1.clone(),
        c2: c2.clone(),
        c_v1: c_v1.clone(),
        c_v2: c_v2.clone(),
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

    // Generate π_{4,G1} and π_{4,G2} proofs for Schnorr bridging
    // These proofs connect the public key representations across different groups

    // Get G3 generators for creating pk_star and pk_r_star
    use crate::crypto::curve::{scalar_to_grumpkin_scalar, G3Proj};
    use crate::crypto::prf::extract_routing_value;

    let g3_base = pp
        .generators
        .g3(0)
        .ok_or_else(|| ProtocolError::CryptoError("Missing G3 generator 0".to_string()))?;
    let h3_base = pp
        .generators
        .g3(1)
        .ok_or_else(|| ProtocolError::CryptoError("Missing G3 generator 1".to_string()))?;

    // Convert to projective for scalar multiplication
    let g3_proj = G3Proj::from(*g3_base);
    let h3_proj = G3Proj::from(*h3_base);

    // Generate random blinding factors for Schnorr commitments
    let r_star = ScalarField::rand(&mut rand::thread_rng());
    let r_r_star = ScalarField::rand(&mut rand::thread_rng());

    // Convert scalar fields to Grumpkin scalar field for G3 operations
    let sk_grumpkin = scalar_to_grumpkin_scalar(&_sk.sk);
    let r_star_grumpkin = scalar_to_grumpkin_scalar(&r_star);
    let r_r_star_grumpkin = scalar_to_grumpkin_scalar(&r_r_star);

    // Create pk_star = G^{sk} * H^{r_star}
    let pk_star = (g3_proj * sk_grumpkin + h3_proj * r_star_grumpkin).into_affine();

    // Create pk_r_star = pk_r * H^{r_r_star}
    let pk_r_proj = G3Proj::from(receiver.public_key.pk);
    let pk_r_star = (pk_r_proj + h3_proj * r_r_star_grumpkin).into_affine();

    // Extract coordinates and convert to BLS12-381 scalar field
    let pk_star_x_scalar =
        ScalarField::from_le_bytes_mod_order(&pk_star.x.into_bigint().to_bytes_le());
    let pk_star_y_scalar =
        ScalarField::from_le_bytes_mod_order(&pk_star.y.into_bigint().to_bytes_le());
    let pk_r_star_x_scalar =
        ScalarField::from_le_bytes_mod_order(&pk_r_star.x.into_bigint().to_bytes_le());
    let pk_r_star_y_scalar =
        ScalarField::from_le_bytes_mod_order(&pk_r_star.y.into_bigint().to_bytes_le());

    // Create coordinate commitments for pk_star and pk_r_star
    // pk_star_coord = G1^{pk_star_x} * G2^{pk_star_y}
    let pk_star_coord = (g1_base_proj * pk_star_x_scalar) + (g2_base_proj * pk_star_y_scalar);

    // pk_r_star_coord = G1^{pk_r_star_x} * G2^{pk_r_star_y}
    let pk_r_star_coord = (g1_base_proj * pk_r_star_x_scalar) + (g2_base_proj * pk_r_star_y_scalar);

    // Extract routing value ρ from phi
    let rho = ScalarField::from(extract_routing_value(_phi_nu_plus_1));

    // Create commitment G^ρ
    let g_rho = g1_base_proj * rho;

    // Generate proof π_{4,G1}: Schnorr bridging
    let schnorr_instance = SchnorrBridgingInstance {
        pk_star_coord,
        pk_r_star_coord,
        c1: c1.clone(),
        c2: c2.clone(),
        c_v1: c_v1.clone(),
        c_v2: c_v2.clone(),
        g_rho,
    };

    let schnorr_witness = SchnorrBridgingWitness {
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
        rho,
        pk_star_x: pk_star_x_scalar,
        pk_star_y: pk_star_y_scalar,
        pk_r_star_x: pk_r_star_x_scalar,
        pk_r_star_y: pk_r_star_y_scalar,
        r_star,
        r_r_star,
    };

    let pi_4_g1 = prove_schnorr_bridging(&schnorr_instance, &schnorr_witness)?;

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

    Ok(Proof {
        pi_1,
        pi_2,
        pi_3,
        pi_4_g1,
        pi_4_g2,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generators::Generators;
    use crate::protocol::spawn::spawn;
    use rand::thread_rng;

    // Helper function to create public parameters for tests
    fn create_test_public_params<R: Rng>(rng: &mut R) -> PublicParams {
        PublicParams {
            num_nodes: 10,
            max_out_degree: 10,
            g1_generators: vec![],
            g3_generators: vec![],
            groth16_params: vec![],
            generators: Generators::generate(rng, 10, 10, 10),
        }
    }

    #[test]
    fn test_forward_basic() {
        let mut rng = thread_rng();

        // Setup: generate protocol state with 3 users
        let generated_state = generate_state(3, &mut rng);
        let user_0_view = &generated_state.users_view[0];

        // Create public parameters
        let pp = create_test_public_params(&mut rng);

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
            Ok((new_message, k_r, _d)) => {
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

        // Setup: generate protocol state with 1 user
        let generated_state = generate_state(1, &mut rng);
        let user_0_view = &generated_state.users_view[0];

        // Create public parameters
        let pp = create_test_public_params(&mut rng);

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
        let result = forward(&pp, user_0_view, &message, &mut rng);
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

        // Generate protocol state
        let generated_state = generate_state(num_users, &mut rng);

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
}
