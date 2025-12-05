//! Curve type aliases for BLS12-381 and Grumpkin
//!
//! This module provides a centralized location for all curve-related type definitions:
//! - G1: BLS12-381 G1 group (used for PRF outputs, commitments)
//! - G2: BLS12-381 G2 group (kept for backward compatibility, not used for public keys)
//! - GT: BLS12-381 target group (for pairings)
//! - G3: Grumpkin curve (used for public keys)

use ark_bls12_381::{Bls12_381, Fq, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::pairing::Pairing;
use ark_grumpkin::{Affine as GrumpkinAffine, Projective as GrumpkinProjective};

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
// Grumpkin Curve (G3)
// ============================================================================

/// G3 curve point in affine coordinates (Grumpkin)
/// Used for: Public keys, diversified public keys
pub type G3 = GrumpkinAffine;

/// G3 curve point in projective coordinates (Grumpkin)
/// Used for: Efficient curve arithmetic
pub type G3Proj = GrumpkinProjective;

// ============================================================================
// Scalar Fields
// ============================================================================

/// Scalar field for BLS12-381 (Fr)
/// Also serves as the base field for Grumpkin
/// Used for: Secret keys, diversifiers, general scalar arithmetic
pub type ScalarField = Fr;

/// Scalar field for Grumpkin (Fr)
/// Note: Grumpkin's scalar field = BLS12-381's base field (Fq)
/// Used for: Scalar multiplication on Grumpkin curve
pub type GrumpkinScalarField = ark_grumpkin::Fr;

/// Base field for BLS12-381 (Fq)
/// Also serves as the scalar field for Grumpkin
pub type BaseField = Fq;

// ============================================================================
// Pairing Engine
// ============================================================================

/// BLS12-381 pairing engine
pub type PairingEngine = Bls12_381;

// ============================================================================
// Utility Functions
// ============================================================================

/// Convert BLS12-381 Fr to Grumpkin Fr (scalar field)
/// This is needed because BLS12-381 Fr = Grumpkin base field,
/// but we need Grumpkin's scalar field for curve operations
///
/// Note: The two fields have different moduli, so we reduce modulo Grumpkin's field
pub fn scalar_to_grumpkin_scalar(scalar: &ScalarField) -> GrumpkinScalarField {
    use ark_ff::{BigInteger, PrimeField};
    let bigint = scalar.into_bigint();

    // Try direct conversion first
    if let Some(result) = GrumpkinScalarField::from_bigint(bigint) {
        return result;
    }

    // If direct conversion fails, convert via bytes with modular reduction
    // This handles cases where BLS Fr > Grumpkin Fr
    let mut bytes = [0u8; 32];
    let bigint_bytes = bigint.to_bytes_le();
    let copy_len = std::cmp::min(bytes.len(), bigint_bytes.len());
    bytes[..copy_len].copy_from_slice(&bigint_bytes[..copy_len]);

    // from_le_bytes_mod_order performs modular reduction automatically
    GrumpkinScalarField::from_le_bytes_mod_order(&bytes)
}
