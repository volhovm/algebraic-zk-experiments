//! Poseidon hash implementation for BLS12-381 scalar field
//!
//! Used for:
//! - Deriving θ = Hash(φ_ν, sid, pid, ν)
//! - Hashing public keys
//! - General-purpose ZK-friendly hashing

use crate::types::{PacketId, ScalarField, SessionId};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use sha2::{Digest, Sha256};

/// Poseidon hasher (using SHA256 as a placeholder for now)
pub struct PoseidonHash {}

impl PoseidonHash {
    pub fn new() -> Self {
        Self {}
    }

    /// Hash arbitrary field elements
    pub fn hash(&self, inputs: &[ScalarField]) -> ScalarField {
        if inputs.is_empty() {
            return ScalarField::from(0u64);
        }

        // TODO FIXME USE POSEIDON or make sure the hash value is big enough so that `mod` Fp is uniform.
        // Serialize all inputs and hash with SHA256
        let mut hasher = Sha256::new();
        for input in inputs {
            let mut bytes = Vec::new();
            input
                .serialize_compressed(&mut bytes)
                .expect("Serialization should not fail");
            hasher.update(&bytes);
        }

        let hash = hasher.finalize();
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&hash);

        // Convert to scalar field element
        ScalarField::from_be_bytes_mod_order(&hash_bytes)
    }

    /// Hash theta derivation: θ = Hash(φ_ν, sid, pid, ν)
    pub fn hash_theta(
        &self,
        phi_prev: &ScalarField,
        sid: SessionId,
        pid: PacketId,
        nu: usize,
    ) -> ScalarField {
        let inputs = vec![
            *phi_prev,
            ScalarField::from(sid),
            ScalarField::from(pid as u64),
            ScalarField::from(nu as u64),
        ];
        self.hash(&inputs)
    }
}

impl Default for PoseidonHash {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon_basic() {
        let hasher = PoseidonHash::new();
        let input = vec![ScalarField::from(1u64), ScalarField::from(2u64)];
        let output = hasher.hash(&input);
        assert_ne!(output, ScalarField::from(0u64));
    }

    #[test]
    fn test_hash_theta() {
        let hasher = PoseidonHash::new();
        let phi_prev = ScalarField::from(42u64);
        let theta = hasher.hash_theta(&phi_prev, 100, 5, 3);
        assert_ne!(theta, ScalarField::from(0u64));
    }
}
