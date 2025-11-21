//! Curve operations for BLS12-381
//!
//! Operations on G1 and G2 groups

use crate::types::{Diversifier, DiversifiedPublicKey, PublicKey, ScalarField, SecretKey};
use ark_ec::{CurveGroup, Group};
use ark_ff::Field;
use ark_bls12_381::G2Projective;
use ark_std::UniformRand;
use rand::Rng;

/// Key generation: generate (sk, pk) pair where pk = G^sk in G2
pub fn keygen<R: Rng>(rng: &mut R) -> (SecretKey, PublicKey) {
    let sk = ScalarField::rand(rng);
    let generator = G2Projective::generator();
    let pk = (generator * sk).into_affine();

    (SecretKey { sk }, PublicKey { pk })
}

/// Diversify public key: ppk = (pk^d, G^d)
pub fn diversify<R: Rng>(pk: &PublicKey, rng: &mut R) -> (DiversifiedPublicKey, Diversifier) {
    let d = ScalarField::rand(rng);
    diversify_with_diversifier(pk, &Diversifier { d })
}

/// Diversify with specific diversifier
pub fn diversify_with_diversifier(
    pk: &PublicKey,
    diversifier: &Diversifier,
) -> (DiversifiedPublicKey, Diversifier) {
    let generator = G2Projective::generator();
    let pk_proj = G2Projective::from(pk.pk);

    let ppk_1 = (pk_proj * diversifier.d).into_affine();
    let ppk_2 = (generator * diversifier.d).into_affine();

    (
        DiversifiedPublicKey { ppk_1, ppk_2 },
        diversifier.clone(),
    )
}

/// Check if diversified public key is valid for a given secret key
/// Checks if ppk_2^sk = ppk_1 (for receiver detection)
pub fn check_diversified_ownership(sk: &SecretKey, ppk: &DiversifiedPublicKey) -> bool {
    let ppk_2_proj = G2Projective::from(ppk.ppk_2);
    let expected = (ppk_2_proj * sk.sk).into_affine();
    expected == ppk.ppk_1
}

/// Scalar field operations

/// Compute modular inverse in scalar field
/// Returns 1/x
pub fn scalar_inverse(x: &ScalarField) -> Option<ScalarField> {
    x.inverse()
}

/// Compute 1/(θ + sk)
pub fn compute_prf_exponent(theta: &ScalarField, sk: &ScalarField) -> Option<ScalarField> {
    let sum = *theta + sk;
    scalar_inverse(&sum)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_keygen() {
        let mut rng = thread_rng();
        let (sk, pk) = keygen(&mut rng);

        // Verify pk = G^sk
        let generator = G2Projective::generator();
        let expected_pk = (generator * sk.sk).into_affine();
        assert_eq!(pk.pk, expected_pk);
    }

    #[test]
    fn test_diversify() {
        let mut rng = thread_rng();
        let (sk, pk) = keygen(&mut rng);
        let (ppk, _diversifier) = diversify(&pk, &mut rng);

        // Check ownership
        assert!(check_diversified_ownership(&sk, &ppk));
    }

    #[test]
    fn test_scalar_inverse() {
        let x = ScalarField::from(42u64);
        let x_inv = scalar_inverse(&x).unwrap();
        let product = x * x_inv;
        assert_eq!(product, ScalarField::from(1u64));
    }

    #[test]
    fn test_prf_exponent() {
        let theta = ScalarField::from(10u64);
        let sk = ScalarField::from(5u64);
        let exponent = compute_prf_exponent(&theta, &sk).unwrap();

        // Verify (θ + sk) * exponent = 1
        let sum = theta + sk;
        let product = sum * exponent;
        assert_eq!(product, ScalarField::from(1u64));
    }
}
