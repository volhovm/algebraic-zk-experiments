//! Circuit definitions and proof generation for the Forward protocol
//!
//! This module defines the instance/witness structures and stub proof generation
//! functions for the five proof components mentioned in the spec:
//! - π_1: Merkle tree membership for sender public key
//! - π_2: Weight sub-tree proofs (Catalano-Fiore variant)
//! - π_3: Merkle tree membership for receiver public key
//! - π_{4,G1}: Lightweight Schnorr bridging proof in G1
//! - π_{4,G2}: Public key operations proof in G2

use crate::types::{ProofGroth16, ProtocolResult, ScalarField, Schnorr, G1, G3};
use ark_bls12_381::G1Projective;
use ark_ec::CurveGroup;
use ark_std::UniformRand;

/// Create a mock Groth16 proof with random group elements
///
/// This generates a proof with random elements a, b, c for testing purposes.
/// The proof structure is: (a: G1Affine, b: G2Affine, c: G1Affine)
pub fn mock_groth16_proof() -> ProofGroth16 {
    use crate::crypto::curve::PairingEngine;
    use ark_ec::pairing::Pairing;
    let mut rng = ark_std::test_rng();

    ProofGroth16 {
        a: <PairingEngine as Pairing>::G1::rand(&mut rng).into_affine(),
        b: <PairingEngine as Pairing>::G2::rand(&mut rng).into_affine(),
        c: <PairingEngine as Pairing>::G1::rand(&mut rng).into_affine(),
    }
}

// =============================================================================
// π_1 and π_3: Merkle Membership Proof (unified for sender and receiver)
// =============================================================================

/// Instance (public inputs) for merkle membership proof (π_1 or π_3)
///
/// This is a unified structure used for both sender membership (π_1) and
/// receiver membership (π_3), as they use the same circuit and CRS.
#[derive(Clone, Debug)]
pub struct MerkleMembershipInstance {
    /// Commitment to public key: C = gamma_abc_g1[1]^{pk_x} * gamma_abc_g1[2]^{pk_y} * gamma_abc_g1[3]^{md_2} * hs[0]^{r}
    pub c: G1Projective,
    /// Root of the main merkle tree
    pub merkle_root: ScalarField,
}

/// Witness (private inputs) for merkle membership proof (π_1 or π_3)
///
/// This is a unified structure used for both sender and receiver membership proofs.
#[derive(Clone, Debug)]
pub struct MerkleMembershipWitness {
    /// Public key x-coordinate
    pub pk_x: ScalarField,
    /// Public key y-coordinate
    pub pk_y: ScalarField,
    /// Sub-merkle tree root (md_2)
    pub md_2: ScalarField,
    /// Blinding factor for commitment
    pub r: ScalarField,
    /// Merkle proof path for inclusion in main tree
    pub merkle_proof: Vec<ScalarField>,
}

/// Generate merkle membership proof (π_1 for sender or π_3 for receiver)
///
/// This proves that a public key is committed in C and is included in the main merkle tree.
///
/// # Arguments
/// * `instance` - Public inputs (C, merkle_root)
/// * `witness` - Private inputs (pk_x, pk_y, md_2, r, merkle_proof)
///
/// # Returns
/// Groth16 proof
pub fn prove_merkle_membership(
    _instance: &MerkleMembershipInstance,
    _witness: &MerkleMembershipWitness,
) -> ProtocolResult<ProofGroth16> {
    // TODO: Actual Groth16 proof generation
    // For now, return mock proof with random elements
    Ok(mock_groth16_proof())
}

// Legacy aliases for backward compatibility during transition
pub type SenderMembershipInstance = MerkleMembershipInstance;
pub type SenderMembershipWitness = MerkleMembershipWitness;
pub type ReceiverMembershipInstance = MerkleMembershipInstance;
pub type ReceiverMembershipWitness = MerkleMembershipWitness;

/// Legacy function for sender membership - redirects to unified function
pub fn prove_sender_membership(
    instance: &SenderMembershipInstance,
    witness: &SenderMembershipWitness,
) -> ProtocolResult<ProofGroth16> {
    prove_merkle_membership(instance, witness)
}

/// Legacy function for receiver membership - redirects to unified function
pub fn prove_receiver_membership(
    instance: &ReceiverMembershipInstance,
    witness: &ReceiverMembershipWitness,
) -> ProtocolResult<ProofGroth16> {
    prove_merkle_membership(instance, witness)
}

// =============================================================================
// π_2: Weight Subtree Proof
// =============================================================================

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
/// Groth16 proof
pub fn prove_weight_subtree(
    _instance: &WeightSubtreeInstance,
    _witness: &WeightSubtreeWitness,
) -> ProtocolResult<ProofGroth16> {
    // TODO: Actual Groth16 proof generation
    // For now, return mock proof with random elements
    Ok(mock_groth16_proof())
}

// =============================================================================
// π_{4,G1}: Schnorr Bridging Proof
// =============================================================================

/// Instance (public inputs) for Schnorr bridging proof π_{4,G1}
///
/// This proof bridges the representation of public keys between G3 (Grumpkin)
/// and G1 (BLS12-381) by expressing G3 coordinates as commitments in G1.
///
/// Note: This proof receives 4 commitments (C11, C12, C21, C22) and must
/// internally prove that C11 and C12 open to the same witness (sender),
/// and that C21 and C22 open to the same witness (receiver).
#[derive(Clone, Debug)]
pub struct SchnorrBridgingInstance {
    /// Commitment to pk_star coordinates: G1^{pk_star_x} * G2^{pk_star_y}
    pub pk_star_coord: G1Projective,
    /// Commitment to pk_r_star coordinates: G1^{pk_r_star_x} * G2^{pk_r_star_y}
    pub pk_r_star_coord: G1Projective,
    /// Commitment to sender with merkle circuit bases (C11)
    pub c11: G1Projective,
    /// Commitment to sender with weight circuit bases (C12)
    pub c12: G1Projective,
    /// Commitment to receiver with merkle circuit bases (C21)
    pub c21: G1Projective,
    /// Commitment to receiver with weight circuit bases (C22)
    pub c22: G1Projective,
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
/// 2. All commitments C11, C12, C21, C22, C_v1, C_v2 are consistent with their exponents
/// 3. C11 and C12 open to the same witness (pk_x, pk_y, md_2_k_s, r1)
/// 4. C21 and C22 open to the same witness (pk_r_x, pk_r_y, md_2_k_r, r2)
/// 5. The routing value ρ is correctly committed
///
/// # Arguments
/// * `instance` - Public inputs (coordinate commitments and other commitments)
/// * `witness` - Private inputs (all exponents and coordinates)
///
/// # Returns
/// Schnorr proof in G1
pub fn prove_schnorr_bridging(
    _instance: &SchnorrBridgingInstance,
    _witness: &SchnorrBridgingWitness,
) -> ProtocolResult<Schnorr<G1>> {
    // TODO: Actual Schnorr proof generation
    // TODO: This proof must internally prove that:
    //       - C11 and C12 open to the same witness values (pk_x, pk_y, md_2_k_s)
    //         where C11 uses merkle circuit bases (gamma_abc_g1[1,2,3], hs[0])
    //         and C12 uses weight circuit bases (gamma_abc_g1[1,2,3], hs[1])
    //       - C21 and C22 open to the same witness values (pk_r_x, pk_r_y, md_2_k_r)
    //         using the same respective bases
    //       This ensures consistency of committed values across different circuit bases.
    // For now, return stub proof
    Ok(Schnorr {
        data: vec![0u8; 32],
        _phantom: std::marker::PhantomData,
    })
}

// =============================================================================
// π_{4,G2}: Public Key Operations Proof
// =============================================================================

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
/// Schnorr proof in G3 (Grumpkin)
pub fn prove_public_key_operations(
    _instance: &PublicKeyOperationsInstance,
    _witness: &PublicKeyOperationsWitness,
) -> ProtocolResult<Schnorr<G3>> {
    // TODO: Actual Schnorr proof generation
    // For now, return stub proof
    Ok(Schnorr {
        data: vec![0u8; 32],
        _phantom: std::marker::PhantomData,
    })
}

// =============================================================================
// Dummy Circuits for Groth16 Setup
// =============================================================================

use ark_ff::Field;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// Dummy circuit for merkle membership proof (π_1 and π_3)
///
/// This circuit is used for both sender membership (π_1) and receiver membership (π_3)
/// proofs, as they share the same structure and CRS.
#[derive(Clone)]
pub struct MerkleMembershipCircuit<F: Field> {
    pub _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> ConstraintSynthesizer<F> for MerkleMembershipCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Allocate 3 public inputs to ensure gamma_abc_g1 has at least 4 elements (indices 0,1,2,3)
        // These correspond to: pk_x, pk_y, md_2
        let _inp1 = cs.new_input_variable(|| Ok(F::ONE))?;
        let _inp2 = cs.new_input_variable(|| Ok(F::ONE))?;
        let _inp3 = cs.new_input_variable(|| Ok(F::ONE))?;
        Ok(())
    }
}

// Legacy aliases for backward compatibility
pub type SenderMembershipCircuit<F> = MerkleMembershipCircuit<F>;
pub type ReceiverMembershipCircuit<F> = MerkleMembershipCircuit<F>;

/// Dummy circuit for weight subtree proof (π_2)
#[derive(Clone)]
pub struct WeightSubtreeCircuit<F: Field> {
    pub _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> ConstraintSynthesizer<F> for WeightSubtreeCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Allocate 3 public inputs to ensure gamma_abc_g1 has at least 4 elements (indices 0,1,2,3)
        // These correspond to: pk_x, pk_y, md_2 (same structure as merkle membership)
        let _inp1 = cs.new_input_variable(|| Ok(F::ONE))?;
        let _inp2 = cs.new_input_variable(|| Ok(F::ONE))?;
        let _inp3 = cs.new_input_variable(|| Ok(F::ONE))?;
        Ok(())
    }
}
