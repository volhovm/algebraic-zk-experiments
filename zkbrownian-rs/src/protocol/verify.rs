//! Verify function implementation
//!
//! Verifies message validity: Verify(m, h, C, P) -> {0, 1}

use crate::types::*;

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
///
/// # Returns
/// true if message is valid, false otherwise
pub fn verify(
    message: &Message,
    hop_count: usize,
    _weight_commitment: &WeightCommitment,
    _all_public_keys: &[PublicKey],
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
        if !verify_hop_proof(message, i, hop)? {
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
fn verify_hop_proof(_message: &Message, _hop_index: usize, _hop: &Hop) -> ProtocolResult<bool> {
    // TODO: Implement actual verification of all five proof components
    // - Verify π_1 (sender membership)
    // - Verify π_2 (weight subtree)
    // - Verify π_3 (receiver membership)
    // - Verify π_{4,G1} (Schnorr bridging)
    // - Verify π_{4,G2} (public key operations)

    // For now, stub returns true
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

        let result = verify(&message, 0, &weight_commitment, &all_pks).unwrap();
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

        // Verify with wrong hop count
        let result = verify(&message, 5, &weight_commitment, &all_pks).unwrap();
        assert!(!result);
    }
}
