use serde::{Deserialize, Serialize};

/// Data for a single R1CS proof that the guest needs to verify.
/// All fields are serialized as raw bytes to avoid coupling to any specific
/// curve library.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofData {
    /// Compressed serialization of proof point A_I1 (G1Affine)
    pub a_i1_bytes: Vec<u8>,
    /// Compressed serialization of proof point A_O1 (G1Affine)
    pub a_o1_bytes: Vec<u8>,
    /// Compressed serialization of proof point S1 (G1Affine)
    pub s1_bytes: Vec<u8>,
    /// Compressed serialization of proof point A_I2 (G1Affine)
    pub a_i2_bytes: Vec<u8>,
    /// Compressed serialization of proof point A_O2 (G1Affine)
    pub a_o2_bytes: Vec<u8>,
    /// Compressed serialization of proof point S2 (G1Affine)
    pub s2_bytes: Vec<u8>,
    /// Compressed serialization of T commitment points (Vec<G1Affine>)
    /// Each point is 48 bytes compressed.
    pub t_points_bytes: Vec<Vec<u8>>,
    /// Scalar t_x as 32 bytes (little-endian)
    pub t_x: [u8; 32],
    /// Scalar t_x_blinding as 32 bytes
    pub t_x_blinding: [u8; 32],
    /// Scalar e_blinding as 32 bytes
    pub e_blinding: [u8; 32],
    /// l_vec: Vec of scalars as 32-byte arrays
    pub l_vec: Vec<[u8; 32]>,
    /// r_vec: Vec of scalars as 32-byte arrays
    pub r_vec: Vec<[u8; 32]>,
}

/// Instance data for one Schnorr bridging proof.
/// Contains the blinded point coordinates (BLS12-381 scalar field elements).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InstanceData {
    /// pk_star_blinded.x as 32 bytes
    pub pk_star_blinded_x: [u8; 32],
    /// pk_star_blinded.y as 32 bytes
    pub pk_star_blinded_y: [u8; 32],
    /// pk_r_star_blinded.x as 32 bytes
    pub pk_r_star_blinded_x: [u8; 32],
    /// pk_r_star_blinded.y as 32 bytes
    pub pk_r_star_blinded_y: [u8; 32],
}

/// Lookup table data: 3-bit windows for the re_randomize gadget.
/// Each table has 2 rows (x, y coords) of 8 elements each.
/// Elements are BLS12-381 scalar field elements (32 bytes each).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LookupTableData {
    /// elems[row][col] as 32-byte field elements
    /// row 0 = x coordinates, row 1 = y coordinates
    /// Each row has 8 elements (3-bit window)
    pub elems: [[[u8; 32]; 8]; 2],
}

/// Input to the SP1 guest program.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuestInput {
    /// Number of proofs in the batch
    pub num_proofs: u32,
    /// Per-proof data
    pub proofs: Vec<ProofData>,
    /// Per-proof instance data
    pub instances: Vec<InstanceData>,
    /// Lookup tables for the re_randomize gadget (shared across all proofs)
    pub lookup_tables: Vec<LookupTableData>,
    /// Random scalars for batch combination (one per proof after the first).
    /// These are provided by the host to make the guest deterministic.
    pub batch_random_scalars: Vec<[u8; 32]>,
    /// Random scalar r used in verification_scalars_and_points for each proof.
    pub r_scalars: Vec<[u8; 32]>,
}

/// Output from the SP1 guest program.
/// Contains a hash of the verification scalars for the host to verify.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuestOutput {
    /// SHA256 hash of the serialized verification output.
    /// The host independently computes the same scalars and verifies this hash.
    pub output_hash: [u8; 32],
    /// Padded n (number of variable pairs in the constraint system).
    pub padded_n: u32,
}
