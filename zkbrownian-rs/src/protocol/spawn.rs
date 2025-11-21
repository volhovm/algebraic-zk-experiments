//! Spawn function implementation
//!
//! Creates initial messages: Spawn(sk, pid, sid) -> m

use crate::crypto::curve_ops::diversify_with_diversifier;
use crate::crypto::PoseidonHash;
use crate::types::*;
use rand::Rng;

/// Spawn function: Spawn(pk, sk, pid, sid) -> m
///
/// Creates a new message to send into the network.
///
/// # Algorithm (from spec)
/// 1. Generate ppk_0 ← Hash(pid, sid)^sk
/// 2. Generate π_0, attesting to:
///    - ppk_0 is indeed derived as public hash to secret key exponent
///    - Secret key corresponds to public key which is member of full list
/// 3. m ← (pid, sid, {}, ppk_0, π_0)
///
/// # Arguments
/// * `sk` - Secret key of the spawner
/// * `pk` - Public key of the spawner
/// * `pid` - Packet ID
/// * `sid` - Session ID
///
/// # Returns
/// Initial message m
pub fn spawn<R: Rng>(
    sk: &SecretKey,
    pk: &PublicKey,
    pid: PacketId,
    sid: SessionId,
    _rng: &mut R,
) -> ProtocolResult<Message> {
    // Step 1: Generate ppk_0
    // ppk_0 ← Hash(pid, sid)^sk
    //
    // Interpretation: Hash(pid, sid) gives a point, then we exponentiate by sk
    // For ElGamal-style diversified key, we treat Hash as a deterministic diversifier

    let hasher = PoseidonHash::new();

    // Hash pid and sid to get a "deterministic diversifier"
    let diversifier_scalar = hasher.hash(&[ScalarField::from(pid as u64), ScalarField::from(sid)]);

    let diversifier = Diversifier {
        d: diversifier_scalar,
    };

    let (ppk_0, _) = diversify_with_diversifier(pk, &diversifier);

    // Step 2: Generate π_0
    // π_0 proves:
    // 1. ppk_0 is correctly derived from Hash(pid, sid) and sk
    // 2. pk (corresponding to sk) is in the list of all public keys
    let pi_0 = generate_spawn_proof(sk, pk, pid, sid, &ppk_0)?;

    // Step 3: Create message
    let message = Message {
        pid,
        sid,
        hops: Vec::new(), // No hops yet
        ppk_0,
        pi_0,
    };

    Ok(message)
}

/// Generate the spawn proof π_0
///
/// Proves:
/// 1. ppk_0 is derived correctly from Hash(pid, sid) and sk
/// 2. pk (corresponding to sk) is in the list of all public keys
fn generate_spawn_proof(
    _sk: &SecretKey,
    _pk: &PublicKey,
    _pid: PacketId,
    _sid: SessionId,
    _ppk_0: &DiversifiedPublicKey,
) -> ProtocolResult<Proof> {
    // TODO: Full proof generation
    // For now, return stub

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
    use rand::thread_rng;

    #[test]
    fn test_spawn() {
        let mut rng = thread_rng();
        let (sk, pk) = keygen(&mut rng);

        let message = spawn(&sk, &pk, 42, 1000, &mut rng).unwrap();

        assert_eq!(message.pid, 42);
        assert_eq!(message.sid, 1000);
        assert_eq!(message.hop_count(), 0);
    }

    #[test]
    fn test_spawn_deterministic_ppk() {
        let mut rng = thread_rng();
        let (sk, pk) = keygen(&mut rng);

        // Same pid, sid should give same ppk_0
        let msg1 = spawn(&sk, &pk, 42, 1000, &mut rng).unwrap();
        let msg2 = spawn(&sk, &pk, 42, 1000, &mut rng).unwrap();

        assert_eq!(msg1.ppk_0.ppk_1, msg2.ppk_0.ppk_1);
        assert_eq!(msg1.ppk_0.ppk_2, msg2.ppk_0.ppk_2);
    }

    #[test]
    fn test_spawn_different_sessions() {
        let mut rng = thread_rng();
        let (sk, pk) = keygen(&mut rng);

        // Different sid should give different ppk_0
        let msg1 = spawn(&sk, &pk, 42, 1000, &mut rng).unwrap();
        let msg2 = spawn(&sk, &pk, 42, 2000, &mut rng).unwrap();

        assert_ne!(msg1.ppk_0.ppk_1, msg2.ppk_0.ppk_1);
    }
}
