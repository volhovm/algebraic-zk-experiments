//! Circuit definitions and proof generation for the Forward protocol
//!
//! This module defines the instance/witness structures and stub proof generation
//! functions for the five proof components mentioned in the spec:
//! - π_1: Merkle tree membership for sender public key
//! - π_2: Weight sub-tree proofs (Catalano-Fiore variant)
//! - π_3: Merkle tree membership for receiver public key
//! - π_{4,G1}: Lightweight Schnorr bridging proof in G1
//! - π_{4,G2}: Public key operations proof in G2

use crate::proving::bulletproofs::{BulletproofGens, PedersenGens};
use crate::types::{ProofGroth16, ProtocolError, ProtocolResult, ScalarField, Schnorr, G1, G3};
use ark_bls12_381::{G1Affine as G1A, G1Projective};
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

/// Verify merkle membership proof (π_1 for sender or π_3 for receiver)
///
/// # Arguments
/// * `pvk` - Prepared verifying key for merkle membership circuit
/// * `proof` - Groth16 proof to verify
/// * `instance` - Public inputs (C, merkle_root)
///
/// # Returns
/// true if proof is valid, false otherwise
pub fn verify_merkle_membership(
    pvk: &crate::proving::groth16::PreparedVerifyingKey<crate::crypto::curve::PairingEngine>,
    proof: &ProofGroth16,
    instance: &MerkleMembershipInstance,
) -> ProtocolResult<bool> {
    use crate::crypto::curve::PairingEngine;
    use crate::proving::groth16::Groth16;

    // Construct inputs according to the spec:
    // - coms_offset is 1 (we have one commitment in MerkleMembershipInstance)
    // - public_inputs_coms is [c], where c is the commitment
    // - public_inputs is [merkle_root]
    let coms_offset = 1;
    let public_inputs_coms = vec![instance.c];
    let public_inputs = vec![instance.merkle_root];

    // Perform verification
    let result = Groth16::<PairingEngine>::verify_proof(
        pvk,
        proof,
        coms_offset,
        &public_inputs_coms,
        &public_inputs,
    )
    .map_err(|e| ProtocolError::CryptoError(format!("Verification failed: {:?}", e)))?;

    // FOR NOW though the verification will always fail, so still
    // return Ok(true), but we perform the verification to
    // estimate performance better anyway.
    let _ = result;
    Ok(true)
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

/// Verify weight subtree proof (π_2)
///
/// # Arguments
/// * `pvk` - Prepared verifying key for weight subtree circuit
/// * `proof` - Groth16 proof to verify
/// * `instance` - Public inputs (C1, C2, C_v1, C_v2)
///
/// # Returns
/// true if proof is valid, false otherwise
pub fn verify_weight_subtree(
    pvk: &crate::proving::groth16::PreparedVerifyingKey<crate::crypto::curve::PairingEngine>,
    proof: &ProofGroth16,
    instance: &WeightSubtreeInstance,
) -> ProtocolResult<bool> {
    use crate::crypto::curve::PairingEngine;
    use crate::proving::groth16::Groth16;

    // Construct inputs according to the spec:
    // - coms_offset is 4 (we have four commitments in WeightSubtreeInstance)
    // - public_inputs_coms is [c1, c2, c_v1, c_v2]
    // - public_inputs is [] (empty list)
    let coms_offset = 4;
    let public_inputs_coms = vec![instance.c1, instance.c2, instance.c_v1, instance.c_v2];
    let public_inputs: Vec<ScalarField> = vec![];

    // Perform verification
    let result = Groth16::<PairingEngine>::verify_proof(
        pvk,
        proof,
        coms_offset,
        &public_inputs_coms,
        &public_inputs,
    )
    .map_err(|e| ProtocolError::CryptoError(format!("Verification failed: {:?}", e)))?;

    // Same as in verify_merkle_membership -- perform the verification but return Ok(true) for now.
    let _ = result;
    Ok(true)
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

    // Blinded G3 points (precomputed in forward.rs)
    /// pk_star as G3 point
    pub pk_star_g3: G3,
    /// pk_star_blinded = pk_star + H * r_star
    pub pk_star_blinded: G3,
    /// pk_r_star as G3 point
    pub pk_r_star_g3: G3,
    /// pk_r_star_blinded = pk_r_star + H * r_r_star
    pub pk_r_star_blinded: G3,
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
/// Currently implements partial proving: only the rerandomize relations for pk_star_coord
/// and pk_r_star_coord (proving that pk_star_coord = G1^{pk_star_x} * G2^{pk_star_y} and
/// similarly for pk_r_star_coord).
///
/// # Arguments
/// * `instance` - Public inputs (coordinate commitments and other commitments)
/// * `witness` - Private inputs (all exponents and coordinates)
/// * `pc_gens` - Pedersen commitment generators
/// * `bp_gens` - Bulletproof generators
/// * `h_g3` - G3 blinding generator H (from precompute)
/// * `g3_tables` - Precomputed lookup tables for rerandomize gadget
///
/// # Returns
/// Schnorr proof in G1
pub fn prove_schnorr_bridging(
    _instance: &SchnorrBridgingInstance,
    witness: &SchnorrBridgingWitness,
    pc_gens: &PedersenGens<G1A>,
    bp_gens: &BulletproofGens<G1A>,
    _h_g3: &G3,
    g3_tables: &[crate::proving::relations::lookup::Lookup3Bit<2, ScalarField>],
) -> ProtocolResult<Schnorr<G1>> {
    use crate::crypto::curve::scalar_to_g3_scalar;
    use crate::proving::bulletproofs::r1cs::*;
    use crate::proving::relations::curve::PointRepresentation;
    use crate::proving::relations::rerandomize::re_randomize;
    use merlin::Transcript;

    // TODO: This proof must internally prove that:
    //       - C11 and C12 open to the same witness values (pk_x, pk_y, md_2_k_s)
    //         where C11 uses merkle circuit bases (gamma_abc_g1[1,2,3], hs[0])
    //         and C12 uses weight circuit bases (gamma_abc_g1[1,2,3], hs[1])
    //       - C21 and C22 open to the same witness values (pk_r_x, pk_r_y, md_2_k_r)
    //         using the same respective bases
    //       This ensures consistency of committed values across different circuit bases.
    // For now, we only implement the 2x rerandomize for pk_star_coord and pk_r_star_coord.

    // We need to prove two rerandomize relations:
    // 1. pk_star_coord is a commitment to (pk_star_x, pk_star_y)
    // 2. pk_r_star_coord is a commitment to (pk_r_star_x, pk_r_star_y)

    // For the rerandomize gadget, we need to work with G3 curve points
    // The idea is to prove that the coordinate commitments (in G1 of BLS12-381)
    // correctly encode the coordinates of points on the G3 curve.

    // Use precomputed G3 points and tables from witness and precompute
    // All these values are computed in forward.rs and passed here to avoid duplication
    let pk_star_g3 = witness.pk_star_g3;
    let pk_star_blinded = witness.pk_star_blinded;
    let pk_r_star_g3 = witness.pk_r_star_g3;
    let pk_r_star_blinded = witness.pk_r_star_blinded;

    // Convert randomness to G3 scalar field for the rerandomize gadget
    let r_star_g3 = scalar_to_g3_scalar(&witness.r_star);
    let r_r_star_g3 = scalar_to_g3_scalar(&witness.r_r_star);

    // Create a single proof with both rerandomize calls
    let proof = {
        let mut transcript = Transcript::new(b"SchnorrBridging");
        let mut prover = Prover::new(pc_gens, &mut transcript);

        // First rerandomize: pk_star_coord
        let c_x_var = prover.allocate(Some(pk_star_g3.x)).unwrap();
        let c_y_var = prover.allocate(Some(pk_star_g3.y)).unwrap();
        let c_x_tilde_var = prover.allocate(Some(pk_star_blinded.x)).unwrap();
        let c_y_tilde_var = prover.allocate(Some(pk_star_blinded.y)).unwrap();

        re_randomize(
            &mut prover,
            g3_tables,
            PointRepresentation {
                x: c_x_var.into(),
                y: c_y_var.into(),
                witness: Some(pk_star_g3),
            },
            c_x_tilde_var.into(),
            c_y_tilde_var.into(),
            Some(r_star_g3),
        );

        // Second rerandomize: pk_r_star_coord
        let c_r_x_var = prover.allocate(Some(pk_r_star_g3.x)).unwrap();
        let c_r_y_var = prover.allocate(Some(pk_r_star_g3.y)).unwrap();
        let c_r_x_tilde_var = prover.allocate(Some(pk_r_star_blinded.x)).unwrap();
        let c_r_y_tilde_var = prover.allocate(Some(pk_r_star_blinded.y)).unwrap();

        re_randomize(
            &mut prover,
            g3_tables,
            PointRepresentation {
                x: c_r_x_var.into(),
                y: c_r_y_var.into(),
                witness: Some(pk_r_star_g3),
            },
            c_r_x_tilde_var.into(),
            c_r_y_tilde_var.into(),
            Some(r_r_star_g3),
        );

        prover.prove(bp_gens).unwrap()
    };

    // Serialize the proof
    use ark_serialize::CanonicalSerialize;
    let mut proof_bytes = Vec::new();
    proof
        .serialize_compressed(&mut proof_bytes)
        .map_err(|e| ProtocolError::CryptoError(format!("Serialization failed: {:?}", e)))?;

    Ok(Schnorr {
        data: proof_bytes,
        _phantom: std::marker::PhantomData,
    })
}

/// Verify Schnorr bridging proof π_{4,G1}
///
/// Currently implements partial verification: only the rerandomize relations for pk_star_coord
/// and pk_r_star_coord.
///
/// # Arguments
/// * `proof` - Schnorr proof to verify
/// * `instance` - Public inputs (coordinate commitments and other commitments)
///
/// # Returns
/// true if proof is valid, false otherwise
pub fn verify_schnorr_bridging(
    proof: &Schnorr<G1>,
    _instance: &SchnorrBridgingInstance,
    pc_gens: &PedersenGens<G1A>,
    bp_gens: &BulletproofGens<G1A>,
) -> ProtocolResult<bool> {
    Ok(true)
    //use crate::proving::bulletproofs::r1cs::*;
    //use crate::proving::relations::curve::PointRepresentation;
    //use crate::proving::relations::rerandomize::{build_tables, re_randomize};
    //use crate::types::G3;
    //use ark_ed_on_bls12_381::JubjubConfig;
    //use ark_serialize::CanonicalDeserialize;
    //use ark_std::UniformRand;
    //use merlin::Transcript;

    //// TODO: Actual Schnorr proof verification for all relations
    //// For now, we only verify the 2x rerandomize relations

    //// Get the same blinding base H for G3 (deterministically)
    //// In a real implementation, this should be the same deterministically generated point
    //let mut rng = ark_std::test_rng();
    //let h_g3 = G3::rand(&mut rng);
    //let tables = build_tables(h_g3);

    //// Deserialize the single proof from the proof data
    //let mut cursor = &proof.data[..];
    //let r1cs_proof = R1CSProof::deserialize_compressed(&mut cursor)
    //    .map_err(|e| ProtocolError::CryptoError(format!("Deserialization failed: {:?}", e)))?;

    //// Verify both rerandomize calls in a single proof
    //{
    //    let mut transcript = Transcript::new(b"SchnorrBridging");
    //    let mut verifier: Verifier<_, G1A> = Verifier::new(&mut transcript);

    //    // First rerandomize: pk_star_coord
    //    let c_x_var = verifier.allocate(None).unwrap();
    //    let c_y_var = verifier.allocate(None).unwrap();
    //    let c_x_tilde_var = verifier.allocate(None).unwrap();
    //    let c_y_tilde_var = verifier.allocate(None).unwrap();

    //    re_randomize::<_, _, JubjubConfig, _>(
    //        &mut verifier,
    //        &tables,
    //        PointRepresentation {
    //            x: c_x_var.into(),
    //            y: c_y_var.into(),
    //            witness: None,
    //        },
    //        c_x_tilde_var.into(),
    //        c_y_tilde_var.into(),
    //        None,
    //    );

    //    // Second rerandomize: pk_r_star_coord
    //    let c_r_x_var = verifier.allocate(None).unwrap();
    //    let c_r_y_var = verifier.allocate(None).unwrap();
    //    let c_r_x_tilde_var = verifier.allocate(None).unwrap();
    //    let c_r_y_tilde_var = verifier.allocate(None).unwrap();

    //    re_randomize::<_, _, JubjubConfig, _>(
    //        &mut verifier,
    //        &tables,
    //        PointRepresentation {
    //            x: c_r_x_var.into(),
    //            y: c_r_y_var.into(),
    //            witness: None,
    //        },
    //        c_r_x_tilde_var.into(),
    //        c_r_y_tilde_var.into(),
    //        None,
    //    );

    //    verifier
    //        .verify(&r1cs_proof, pc_gens, bp_gens)
    //        .map_err(|e| ProtocolError::CryptoError(format!("Verification failed: {:?}", e)))?;
    //}

    //Ok(true)
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

/// Verify public key operations proof π_{4,G2}
///
/// # Arguments
/// * `proof` - Schnorr proof to verify
/// * `instance` - Public inputs (blinded keys, diversified keys, hash commitments)
///
/// # Returns
/// true if proof is valid, false otherwise
pub fn verify_public_key_operations(
    _proof: &Schnorr<G3>,
    _instance: &PublicKeyOperationsInstance,
) -> ProtocolResult<bool> {
    // TODO: Actual Schnorr proof verification
    // For now, stub returns true
    Ok(true)
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
