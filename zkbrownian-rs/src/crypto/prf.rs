//! PRF (Pseudorandom Function) operations
//!
//! Implements φ_{ν+1} = G^{1/(θ+sk)}

use crate::types::{PrfOutput, ScalarField, SecretKey, G1Point};
use crate::crypto::curve_ops::compute_prf_exponent;
use ark_ec::{AffineRepr, CurveGroup};
use ark_bls12_381::G1Projective;

#[cfg(test)]
use ark_ec::Group;

/// Compute PRF output: φ = G^{1/(θ+sk)}
///
/// # Arguments
/// * `theta` - Hash of previous PRF output and message metadata
/// * `sk` - Secret key of the forwarder
/// * `generator` - Generator point in G1 (typically G)
///
/// # Returns
/// PRF output φ or None if θ + sk = 0 (extremely unlikely)
pub fn compute_prf(
    theta: &ScalarField,
    sk: &SecretKey,
    generator: &G1Point,
) -> Option<PrfOutput> {
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
    // Convert the x-coordinate of the point to bytes
    // Take first 4 bytes as u32
    let x_coord = phi.phi.x();

    // Serialize the x-coordinate
    // For now, use a simple hash of the serialized bytes
    // TODO: Implement proper deterministic extraction
    let bytes = x_coord
        .expect("Point should have x-coordinate")
        .to_string()
        .as_bytes()
        .to_vec();

    if bytes.len() >= 4 {
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    } else {
        // Fallback if serialization is too short
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::curve_ops::keygen;
    use crate::crypto::poseidon::PoseidonHash;
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
