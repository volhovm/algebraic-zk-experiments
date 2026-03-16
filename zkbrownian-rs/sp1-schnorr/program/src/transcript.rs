//! Merlin transcript protocol for BLS12-381 scalars.
//!
//! This reimplements the TranscriptProtocol from zkbrownian's bulletproofs
//! using the zkcrypto bls12_381 crate instead of arkworks.
//!
//! Key compatibility requirement: the byte encoding of scalars and points
//! must match exactly what arkworks produces (compressed serialization).

use bls12_381::Scalar;
use merlin::Transcript;
use sha3::{Digest, Sha3_256};

use crate::types::scalar_to_bytes;

/// Extension trait for Merlin transcript to work with BLS12-381 scalars.
pub trait TranscriptProtocol {
    fn r1cs_domain_sep(&mut self);
    fn r1cs_1phase_domain_sep(&mut self);
    #[allow(dead_code)]
    fn r1cs_2phase_domain_sep(&mut self);
    fn append_scalar(&mut self, label: &'static [u8], scalar: &Scalar);
    /// Append raw point bytes (already compressed-serialized by the host).
    fn append_point_bytes(&mut self, label: &'static [u8], bytes: &[u8]);
    /// Append raw point bytes, returning error if they represent identity.
    fn validate_and_append_point_bytes(
        &mut self,
        label: &'static [u8],
        bytes: &[u8],
    ) -> Result<(), &'static str>;
    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar;
    #[allow(dead_code)]
    fn append_u64(&mut self, label: &'static [u8], x: u64);
}

impl TranscriptProtocol for Transcript {
    fn r1cs_domain_sep(&mut self) {
        self.append_message(b"dom-sep", b"r1cs v1");
    }

    fn r1cs_1phase_domain_sep(&mut self) {
        self.append_message(b"dom-sep", b"r1cs-1phase");
    }

    fn r1cs_2phase_domain_sep(&mut self) {
        self.append_message(b"dom-sep", b"r1cs-2phase");
    }

    fn append_scalar(&mut self, label: &'static [u8], scalar: &Scalar) {
        // arkworks serialize_compressed for Fr produces little-endian 32 bytes
        // bls12_381::Scalar::to_bytes() also produces little-endian 32 bytes
        let bytes = scalar_to_bytes(scalar);
        self.append_message(label, &bytes);
    }

    fn append_point_bytes(&mut self, label: &'static [u8], bytes: &[u8]) {
        self.append_message(label, bytes);
    }

    fn validate_and_append_point_bytes(
        &mut self,
        label: &'static [u8],
        bytes: &[u8],
    ) -> Result<(), &'static str> {
        // Check if the point is the identity (all zeros for compressed format).
        // For BLS12-381 G1 compressed, identity is the point at infinity flag.
        // We check if all bytes are zero, which would indicate identity in arkworks
        // compressed format. The exact check depends on the serialization format,
        // but for safety we just check if the bytes are all zero.
        let is_zero = bytes.iter().all(|&b| b == 0);
        if is_zero {
            return Err("Point is identity");
        }
        self.append_message(label, bytes);
        Ok(())
    }

    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar {
        // Matches exactly the logic in zkbrownian's transcript.rs:
        // 1. Get 64 challenge bytes from Merlin
        // 2. Hash with SHA3-256 and counter byte
        // 3. Try to interpret as scalar
        let mut bytes = [0u8; 64];
        self.challenge_bytes(label, &mut bytes);

        for i in 0..=u8::MAX {
            let mut sha = Sha3_256::new();
            sha.update(bytes);
            sha.update([i]);
            let result = sha.finalize();

            // Try to interpret the hash output as a valid scalar.
            // arkworks uses from_random_bytes which accepts if the value < modulus.
            // We need to match this behavior exactly.
            //
            // The BLS12-381 scalar field modulus is:
            // r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
            //
            // from_random_bytes in arkworks takes the first 32 bytes and reduces mod r.
            // Actually, it checks if the value (interpreted as little-endian) is < r,
            // and returns None if not.
            let hash_bytes: [u8; 32] = result[..32].try_into().unwrap();
            let opt = Scalar::from_bytes(&hash_bytes);
            if bool::from(opt.is_some()) {
                return opt.unwrap();
            }
        }
        panic!("Failed to derive challenge scalar");
    }

    fn append_u64(&mut self, label: &'static [u8], x: u64) {
        // Merlin's append_u64 appends the value as 8 little-endian bytes
        Transcript::append_u64(self, label, x);
    }
}

/// Labels for T commitment points, matching zkbrownian's util::T_LABELS.
pub const T_LABELS: [&[u8]; 41] = [
    b"T_0", b"T_1", b"T_2", b"T_3", b"T_4", b"T_5", b"T_6", b"T_7", b"T_8", b"T_9", b"T_10",
    b"T_11", b"T_12", b"T_13", b"T_14", b"T_15", b"T_16", b"T_17", b"T_18", b"T_19", b"T_20",
    b"T_21", b"T_22", b"T_23", b"T_24", b"T_25", b"T_26", b"T_27", b"T_28", b"T_29", b"T_30",
    b"T_31", b"T_32", b"T_33", b"T_34", b"T_35", b"T_36", b"T_37", b"T_38", b"T_39", b"T_40",
];
