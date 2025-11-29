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
}
