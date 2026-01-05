//! PRF (Pseudorandom Function) operations
//!
//! Implements φ_{ν+1} = G^{1/(θ+sk)}

use crate::crypto::curve_ops::compute_prf_exponent;
use crate::types::{G1Point, PrfOutput, ScalarField, SecretKey};
use ark_bls12_381::G1Projective;
use ark_ec::CurveGroup;

#[cfg(test)]
use ark_ec::PrimeGroup;

/// Compute PRF output: φ = G^{1/(θ+sk)}
///
/// # Arguments
/// * `theta` - Hash of previous PRF output and message metadata
/// * `sk` - Secret key of the forwarder
/// * `generator` - Generator point in G1 (typically G)
///
/// # Returns
/// PRF output φ or None if θ + sk = 0 (extremely unlikely)
pub fn compute_prf(theta: &ScalarField, sk: &SecretKey, generator: &G1Point) -> Option<PrfOutput> {
    // Compute exponent: 1/(θ + sk)
    let exponent = compute_prf_exponent(theta, &sk.sk)?;

    // Compute G^exponent
    let generator_proj = G1Projective::from(*generator);
    let phi_point = (generator_proj * exponent).into_affine();

    Some(PrfOutput { phi: phi_point })
}

/// Extract first 32 bits from PRF output for routing selection
///
/// This converts the PRF output φ (a G1 point) to a 32-bit value ρ
/// which is then used with the weight matrix to select the next hop
pub fn extract_routing_value(phi: &PrfOutput) -> u32 {
    // TODO can we do this without SHA256..? Just taking x or y coordinate? Is this uniform enough?

    // Hash the point to get a uniformly distributed u32
    use ark_serialize::CanonicalSerialize;
    use sha2::{Digest, Sha256};

    // Serialize the entire point (not just x-coordinate)
    let mut bytes = Vec::new();
    phi.phi
        .serialize_compressed(&mut bytes)
        .expect("Serialization should not fail");

    // Hash to get uniform distribution
    let hash = Sha256::digest(&bytes);

    // Take first 4 bytes of hash as u32
    u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::curve_ops::keygen;
    use rand::thread_rng;

    #[test]
    fn test_compute_prf() {
        let mut rng = thread_rng();
        let (sk, _pk) = keygen(&mut rng);

        let theta = ScalarField::from(42u64);
        let generator = G1Projective::generator().into_affine();

        let phi = compute_prf(&theta, &sk, &generator);
        assert!(phi.is_some());
    }

    #[test]
    fn test_extract_routing_value() {
        let mut rng = thread_rng();
        let (sk, _pk) = keygen(&mut rng);

        let theta = ScalarField::from(123u64);
        let generator = G1Projective::generator().into_affine();

        let phi = compute_prf(&theta, &sk, &generator).unwrap();
        let rho = extract_routing_value(&phi);

        // Just check it produces a value (any value for now)
        println!("Routing value ρ: {}", rho);
    }

    #[test]
    fn test_prf_deterministic() {
        let mut rng = thread_rng();
        let (sk, _pk) = keygen(&mut rng);

        let theta = ScalarField::from(999u64);
        let generator = G1Projective::generator().into_affine();

        let phi1 = compute_prf(&theta, &sk, &generator).unwrap();
        let phi2 = compute_prf(&theta, &sk, &generator).unwrap();

        // Same inputs should give same output
        assert_eq!(phi1.phi, phi2.phi);
    }
}
