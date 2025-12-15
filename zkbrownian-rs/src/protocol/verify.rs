//! Verify function implementation
//!
//! Verifies message validity: Verify(m, h, C, P) -> {0, 1}

use crate::types::*;

/// Verify a batch of messages
///
/// This is a mock implementation that verifies each message individually.
/// In a production system, this could be optimized using batch verification techniques
/// for the underlying cryptographic primitives (e.g., batch Groth16 verification).
///
/// # Arguments
/// * `messages` - Slice of messages to verify
/// * `weight_commitment` - Committed weight matrix
/// * `all_public_keys` - List of all node public keys
/// * `params` - Public parameters for the system
///
/// # Returns
/// true if all messages are valid, false if any message is invalid
pub fn verify_batch(
    messages: &[Message],
    weight_commitment: &WeightCommitment,
    all_public_keys: &[PublicKey],
    params: &PublicParams,
) -> ProtocolResult<bool> {
    // TODO Implement proper batch verification
    for message in messages {
        let hop_count = message.hop_count();
        let is_valid = verify(
            message,
            hop_count,
            weight_commitment,
            all_public_keys,
            params,
        )?;
        if !is_valid {
            return Ok(false);
        }
    }

    Ok(true)
}

/// Verify function: Verify(m, h, C, P) -> bool
///
/// Verifies a message after h hops to be consistent with:
/// - Weight matrix C
/// - Public keys of all nodes P
///
/// # Algorithm (from spec)
/// 1. Verify π_0 w.r.t. ppk_0
/// 2. For each i, verify π_i with respect to ppk_i, ppk_{i-1}, ...
///
/// # Arguments
/// * `message` - Message to verify
/// * `hop_count` - Expected number of hops h
/// * `weight_commitment` - Committed weight matrix C
/// * `all_public_keys` - List of all node public keys P
/// * `params` - Public parameters for the system
///
/// # Returns
/// true if message is valid, false otherwise
pub fn verify(
    message: &Message,
    hop_count: usize,
    _weight_commitment: &WeightCommitment,
    _all_public_keys: &[PublicKey],
    params: &PublicParams,
) -> ProtocolResult<bool> {
    // Check hop count matches
    if message.hop_count() != hop_count {
        return Ok(false);
    }

    // Step 1: Verify π_0 w.r.t. ppk_0
    if !verify_spawn_proof(message)? {
        return Ok(false);
    }

    // Step 2: Verify each hop proof π_i
    for (i, hop) in message.hops.iter().enumerate() {
        if !verify_hop_proof(message, i, hop, params)? {
            return Ok(false);
        }
    }

    Ok(true)
}

/// Verify the spawn proof π_0
fn verify_spawn_proof(_message: &Message) -> ProtocolResult<bool> {
    // TODO: Implement actual verification
    // For now, stub returns true
    Ok(true)
}

/// Verify a single hop proof π_i
///
/// Verifies:
/// 1. Ownership of previous hop's ppk_{i-1}
/// 2. Correct selection of next hop according to weight matrix
/// 3. Correct derivation of ppk_i
/// 4. Correct derivation of PRF output φ_i
fn verify_hop_proof(
    message: &Message,
    hop_index: usize,
    hop: &Hop,
    params: &PublicParams,
) -> ProtocolResult<bool> {
    use crate::proving::circuits::*;
    use crate::proving::groth16::prepare_verifying_key;
    #[allow(unused_imports)]
    use ark_ec::CurveGroup;

    // Prepare the verifying keys
    let pvk_merkle = prepare_verifying_key(&params.pk_merkle_membership.vk);
    let pvk_weight = prepare_verifying_key(&params.pk_weight_subtree.vk);

    // Get the merkle root from the weight commitment
    // TODO: Extract actual merkle root from weight_commitment once structure is finalized
    let merkle_root = crate::types::ScalarField::from(0u64); // Placeholder

    // Construct π_1 instance: Sender membership proof
    let pi_1_instance = MerkleMembershipInstance {
        c: hop.c11.0.into_group(),
        merkle_root,
    };

    // Verify π_1
    if !verify_merkle_membership(&pvk_merkle, &hop.pi.pi_1, &pi_1_instance)? {
        return Ok(false);
    }

    // Construct π_2 instance: Weight subtree proof
    let pi_2_instance = WeightSubtreeInstance {
        c1: hop.c12.0.into_group(),
        c2: hop.c22.0.into_group(),
        c_v1: hop.cv1.0.into_group(),
        c_v2: hop.cv2.0.into_group(),
    };

    // Verify π_2
    if !verify_weight_subtree(&pvk_weight, &hop.pi.pi_2, &pi_2_instance)? {
        return Ok(false);
    }

    // Construct π_3 instance: Receiver membership proof
    let pi_3_instance = MerkleMembershipInstance {
        c: hop.c21.0.into_group(),
        merkle_root,
    };

    // Verify π_3
    if !verify_merkle_membership(&pvk_merkle, &hop.pi.pi_3, &pi_3_instance)? {
        return Ok(false);
    }

    // Derive theta from previous hop's phi
    // For the first hop (index 0), use a default value
    let g_theta = if hop_index == 0 {
        // Use generator or derive from initial state
        crate::types::G1::generator().into_group()
    } else {
        // Derive from previous hop's phi
        // theta = H(phi_{i-1})
        message.hops[hop_index - 1].phi.phi.into_group()
    };

    // Derive rho from phi (first 32 bits)
    // For now, use phi as rho
    let g_rho = hop.phi.phi.into_group();

    // Get previous hop's ppk (ppk_{i-1})
    let (ppk_s_1, ppk_s_2) = if hop_index == 0 {
        // For first hop, use ppk_0
        (message.ppk_0.ppk_1, message.ppk_0.ppk_2)
    } else {
        // Use previous hop's ppk
        let prev_hop = &message.hops[hop_index - 1];
        (prev_hop.ppk.ppk_1, prev_hop.ppk.ppk_2)
    };

    // Construct coordinate commitments for Schnorr bridging
    // pk_star_coord = commitment to pk_star coordinates in G1
    // pk_r_star_coord = commitment to pk_r_star coordinates in G1
    // These would need to be computed from pk_star and pk_r_star coordinates
    // For now, use placeholder commitments
    use ark_ec::AffineRepr;
    let pk_star_coord = {
        let (_x, _y) = hop
            .pk_star
            .0
            .xy()
            .unwrap_or((ark_grumpkin::Fq::from(0u64), ark_grumpkin::Fq::from(0u64)));
        // Convert to G1 commitment: would need actual commitment computation
        crate::types::G1::generator().into_group()
    };

    let pk_r_star_coord = {
        let (_x, _y) = hop
            .pk_r_star
            .0
            .xy()
            .unwrap_or((ark_grumpkin::Fq::from(0u64), ark_grumpkin::Fq::from(0u64)));
        // Convert to G1 commitment: would need actual commitment computation
        crate::types::G1::generator().into_group()
    };

    // Construct π_{4,G1} instance: Schnorr bridging proof
    let pi_4_g1_instance = SchnorrBridgingInstance {
        pk_star_coord,
        pk_r_star_coord,
        c11: hop.c11.0.into_group(),
        c12: hop.c12.0.into_group(),
        c21: hop.c21.0.into_group(),
        c22: hop.c22.0.into_group(),
        c_v1: hop.cv1.0.into_group(),
        c_v2: hop.cv2.0.into_group(),
        g_rho,
    };

    // Verify π_{4,G1}
    if !verify_schnorr_bridging(&hop.pi.pi_4_g1, &pi_4_g1_instance)? {
        return Ok(false);
    }

    // Construct π_{4,G2} instance: Public key operations proof
    let pi_4_g2_instance = PublicKeyOperationsInstance {
        pk_star: hop.pk_star.0,
        pk_r_star: hop.pk_r_star.0,
        ppk_s_1,
        ppk_s_2,
        ppk_r_1: hop.ppk.ppk_1,
        ppk_r_2: hop.ppk.ppk_2,
        g_theta,
        g_phi: hop.phi.phi.into_group(),
    };

    // Verify π_{4,G2}
    if !verify_public_key_operations(&hop.pi.pi_4_g2, &pi_4_g2_instance)? {
        return Ok(false);
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::curve_ops::keygen;
    use crate::protocol::spawn::spawn;
    use rand::thread_rng;

    #[test]
    fn test_verify_spawn() {
        let mut rng = thread_rng();
        let (sk, pk) = keygen(&mut rng);

        let message = spawn(&sk, &pk, 1, 100, &mut rng).unwrap();

        let all_pks = vec![pk];
        let weight_commitment = WeightCommitment {
            commitment: vec![],
            metadata: vec![],
        };
        let params = PublicParams::generate(10, 10, &mut rng).unwrap();

        let result = verify(&message, 0, &weight_commitment, &all_pks, &params).unwrap();
        assert!(result);
    }

    #[test]
    fn test_verify_wrong_hop_count() {
        let mut rng = thread_rng();
        let (sk, pk) = keygen(&mut rng);

        let message = spawn(&sk, &pk, 1, 100, &mut rng).unwrap();

        let all_pks = vec![pk];
        let weight_commitment = WeightCommitment {
            commitment: vec![],
            metadata: vec![],
        };
        let params = PublicParams::generate(10, 10, &mut rng).unwrap();

        // Verify with wrong hop count
        let result = verify(&message, 5, &weight_commitment, &all_pks, &params).unwrap();
        assert!(!result);
    }
}
