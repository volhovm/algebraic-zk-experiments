//! Curve type aliases for BLS12-381 and G3
//!
//! This module provides a centralized location for all curve-related type definitions:
//! - G1: BLS12-381 G1 group (used for PRF outputs, commitments)
//! - G2: BLS12-381 G2 group (kept for backward compatibility, not used for public keys)
//! - GT: BLS12-381 target group (for pairings)
//! - G3: Embedded curve over BLS12-381 (used for public keys)

use ark_bls12_381::{Bls12_381, Fq, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::pairing::Pairing;
use ark_ed_on_bls12_381::{SWAffine as JubJubAffine, SWProjective as JubJubProjective};

// ============================================================================
// BLS12-381 G1 Group
// ============================================================================

/// G1 curve point in affine coordinates (BLS12-381)
/// Used for: PRF outputs, commitments, Groth16 proof elements
pub type G1 = G1Affine;

/// G1 curve point in projective coordinates (BLS12-381)
/// Used for: Efficient curve arithmetic
pub type G1Proj = G1Projective;

// ============================================================================
// BLS12-381 G2 Group
// ============================================================================

/// G2 curve point in affine coordinates (BLS12-381)
/// Kept for backward compatibility, not used for public keys anymore
pub type G2 = G2Affine;

/// G2 curve point in projective coordinates (BLS12-381)
/// Used for: Efficient curve arithmetic
pub type G2Proj = G2Projective;

// ============================================================================
// BLS12-381 Target Group (GT)
// ============================================================================

/// Target group element from pairing operation
/// GT = e(G1, G2) where e is the pairing function
pub type GT = <Bls12_381 as Pairing>::TargetField;

// ============================================================================
// G3 Curve (Embedded curve over BLS12-381)
// ============================================================================

/// G3 curve point in affine coordinates
/// Used for: Public keys, diversified public keys
/// G3 has BLS12-381 scalar field (Fr) as its base field
pub type G3 = JubJubAffine;

/// G3 curve point in projective coordinates
/// Used for: Efficient curve arithmetic
pub type G3Proj = JubJubProjective;

// ============================================================================
// Scalar Fields
// ============================================================================

/// Scalar field for BLS12-381 (Fr)
/// Also serves as the base field for G3
/// Used for: Secret keys, diversifiers, general scalar arithmetic
pub type ScalarField = Fr;

/// Scalar field for G3 curve (Fr)
/// Note: G3's scalar field is ark_ed_on_bls12_381::Fr
/// Used for: Scalar multiplication on G3 curve
pub type G3ScalarField = ark_ed_on_bls12_381::Fr;

/// Base field for BLS12-381 (Fq)
pub type BaseField = Fq;

// ============================================================================
// Pairing Engine
// ============================================================================

/// BLS12-381 pairing engine
pub type PairingEngine = Bls12_381;

// ============================================================================
// Utility Functions
// ============================================================================

/// Convert BLS12-381 Fr to G3 scalar field (Fr)
/// This is needed for scalar multiplication on G3 curve
///
/// Note: Since BLS12-381 Fr is G3's base field, we need to convert
/// to G3's scalar field for curve operations
pub fn scalar_to_g3_scalar(scalar: &ScalarField) -> G3ScalarField {
    use ark_ff::{BigInteger, PrimeField};
    let bigint = scalar.into_bigint();

    // Try direct conversion first
    if let Some(result) = G3ScalarField::from_bigint(bigint) {
        return result;
    }

    // If direct conversion fails, convert via bytes with modular reduction
    let mut bytes = [0u8; 32];
    let bigint_bytes = bigint.to_bytes_le();
    let copy_len = std::cmp::min(bytes.len(), bigint_bytes.len());
    bytes[..copy_len].copy_from_slice(&bigint_bytes[..copy_len]);

    // from_le_bytes_mod_order performs modular reduction automatically
    G3ScalarField::from_le_bytes_mod_order(&bytes)
}

/// Convert G3 base field element to BLS12-381 Fr (ScalarField)
///
/// Since G3's base field (ark_ed_on_bls12_381::Fq) is the same as BLS12-381 Fr,
/// this conversion should be straightforward. We use the bigint representation
/// for conversion.
pub fn g3_base_to_scalar(base: &ark_ed_on_bls12_381::Fq) -> ScalarField {
    use ark_ff::{BigInteger, PrimeField};
    let bigint = base.into_bigint();

    // Try direct conversion first
    if let Some(result) = ScalarField::from_bigint(bigint) {
        return result;
    }

    // If direct conversion fails, convert via bytes with modular reduction
    ScalarField::from_le_bytes_mod_order(&bigint.to_bytes_le())
}
