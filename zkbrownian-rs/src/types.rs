//! Core data structures for the ZK Brownian protocol

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

// Re-export curve types for backward compatibility and convenience
pub use crate::crypto::curve::{
    BaseField, PairingEngine, ScalarField, G1, G1 as G1Point, G2, G2 as G2Point, G3,
    G3 as GrumpkinPoint,
};

/// Wrapper type for G1 to enable Serde serialization
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct G1Wrapper(pub G1);

impl Serialize for G1Wrapper {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = Vec::new();
        self.0
            .serialize_compressed(&mut bytes)
            .map_err(|e| serde::ser::Error::custom(format!("Serialization error: {}", e)))?;
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de> Deserialize<'de> for G1Wrapper {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        let g1 = G1::deserialize_compressed(&bytes[..])
            .map_err(|e| DeError::custom(format!("Deserialization error: {}", e)))?;
        Ok(G1Wrapper(g1))
    }
}

/// Wrapper type for G3 to enable Serde serialization
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct G3Wrapper(pub G3);

impl Serialize for G3Wrapper {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = Vec::new();
        self.0
            .serialize_compressed(&mut bytes)
            .map_err(|e| serde::ser::Error::custom(format!("Serialization error: {}", e)))?;
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de> Deserialize<'de> for G3Wrapper {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        let g3 = G3::deserialize_compressed(&bytes[..])
            .map_err(|e| DeError::custom(format!("Deserialization error: {}", e)))?;
        Ok(G3Wrapper(g3))
    }
}

/// Secret key (scalar in the field)
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SecretKey {
    pub sk: ScalarField,
}

/// Public key (G3/Grumpkin point)
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicKey {
    pub pk: G3,
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = Vec::new();
        self.pk
            .serialize_compressed(&mut bytes)
            .map_err(|e| serde::ser::Error::custom(format!("Serialization error: {}", e)))?;
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        let pk = G3::deserialize_compressed(&bytes[..])
            .map_err(|e| DeError::custom(format!("Deserialization error: {}", e)))?;
        Ok(PublicKey { pk })
    }
}

/// Diversified public key (ElGamal-style tuple)
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct DiversifiedPublicKey {
    /// pk^d component
    pub ppk_1: G3,
    /// G^d component
    pub ppk_2: G3,
}

impl Serialize for DiversifiedPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("DiversifiedPublicKey", 2)?;

        let mut bytes1 = Vec::new();
        self.ppk_1
            .serialize_compressed(&mut bytes1)
            .map_err(|e| serde::ser::Error::custom(format!("Serialization error: {}", e)))?;
        state.serialize_field("ppk_1", &bytes1)?;

        let mut bytes2 = Vec::new();
        self.ppk_2
            .serialize_compressed(&mut bytes2)
            .map_err(|e| serde::ser::Error::custom(format!("Serialization error: {}", e)))?;
        state.serialize_field("ppk_2", &bytes2)?;

        state.end()
    }
}

impl<'de> Deserialize<'de> for DiversifiedPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            ppk_1: Vec<u8>,
            ppk_2: Vec<u8>,
        }

        let helper = Helper::deserialize(deserializer)?;
        let ppk_1 = G3::deserialize_compressed(&helper.ppk_1[..])
            .map_err(|e| DeError::custom(format!("Deserialization error: {}", e)))?;
        let ppk_2 = G3::deserialize_compressed(&helper.ppk_2[..])
            .map_err(|e| DeError::custom(format!("Deserialization error: {}", e)))?;
        Ok(DiversifiedPublicKey { ppk_1, ppk_2 })
    }
}

/// Diversifier (random scalar)
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Diversifier {
    pub d: ScalarField,
}

/// PRF output φ (G1 point)
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PrfOutput {
    pub phi: G1,
}

impl Serialize for PrfOutput {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = Vec::new();
        self.phi
            .serialize_compressed(&mut bytes)
            .map_err(|e| serde::ser::Error::custom(format!("Serialization error: {}", e)))?;
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de> Deserialize<'de> for PrfOutput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        let phi = G1::deserialize_compressed(&bytes[..])
            .map_err(|e| DeError::custom(format!("Deserialization error: {}", e)))?;
        Ok(PrfOutput { phi })
    }
}

/// Groth16 proof type alias
pub type ProofGroth16 = crate::proving::groth16::Proof<crate::crypto::curve::PairingEngine>;

// Serde implementations for ProofGroth16 using ark_serialize
impl Serialize for ProofGroth16 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = Vec::new();
        self.serialize_compressed(&mut bytes)
            .map_err(|e| serde::ser::Error::custom(format!("Serialization error: {}", e)))?;
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de> Deserialize<'de> for ProofGroth16 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        ProofGroth16::deserialize_compressed(&bytes[..])
            .map_err(|e| DeError::custom(format!("Deserialization error: {}", e)))
    }
}

/// Schnorr proof stub (generic over group type)
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Schnorr<G: Send + Sync> {
    /// Stub data for Schnorr proof
    pub data: Vec<u8>,
    /// Phantom data for group type
    #[doc(hidden)]
    pub _phantom: std::marker::PhantomData<G>,
}

impl<G: Send + Sync> Serialize for Schnorr<G> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.data.serialize(serializer)
    }
}

impl<'de, G: Send + Sync> Deserialize<'de> for Schnorr<G> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let data = Vec::<u8>::deserialize(deserializer)?;
        Ok(Schnorr {
            data,
            _phantom: std::marker::PhantomData,
        })
    }
}

/// Proof component
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize)]
pub struct HopProofs {
    /// π_1: Sender membership proof (Groth16)
    pub pi_1: ProofGroth16,
    /// π_2: Weight subtree proof (Groth16)
    pub pi_2: ProofGroth16,
    /// π_3: Receiver membership proof (Groth16)
    pub pi_3: ProofGroth16,
    /// π_4_g1: Schnorr bridging proof in G1
    pub pi_4_g1: Schnorr<G1>,
    /// π_4_g2: Schnorr bridging proof in G3 (Grumpkin)
    pub pi_4_g2: Schnorr<G3>,
}

/// A single hop in the message history
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Hop {
    /// Diversified public key for this hop
    pub ppk: DiversifiedPublicKey,
    /// PRF output for this hop
    pub phi: PrfOutput,
    /// Proof of correct forwarding for this hop
    pub pi: HopProofs,
    /// Commitment to sender with merkle circuit bases (C11)
    pub c11: G1Wrapper,
    /// Commitment to sender with weight circuit bases (C12)
    pub c12: G1Wrapper,
    /// Commitment to receiver with merkle circuit bases (C21)
    pub c21: G1Wrapper,
    /// Commitment to receiver with weight circuit bases (C22)
    pub c22: G1Wrapper,
    /// Commitment to v1 (cumulative weight before receiver)
    pub cv1: G1Wrapper,
    /// Commitment to v2 (cumulative weight including receiver)
    pub cv2: G1Wrapper,
    /// Blinded sender public key pk_star = G^{sk} * H^{r_star}
    pub pk_star: G3Wrapper,
    /// Blinded receiver public key pk_r_star = pk_r * H^{r_r_star}
    pub pk_r_star: G3Wrapper,
}

/// Packet ID (identifies the packet/user)
pub type PacketId = u32;

/// Session/Epoch ID
pub type SessionId = u64;

/// Message structure
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message {
    /// Packet identifier
    pub pid: PacketId,
    /// Session identifier
    pub sid: SessionId,
    /// History of hops (grows with each forward)
    pub hops: Vec<Hop>,
    /// Initial diversified public key from Spawn
    pub ppk_0: DiversifiedPublicKey,
    /// Initial proof from Spawn
    pub pi_0: HopProofs,
}

impl Message {
    /// Get current hop count (ν)
    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }

    /// Get the most recent PRF output (φ_ν), or None if no hops yet
    pub fn latest_phi(&self) -> Option<&PrfOutput> {
        self.hops.last().map(|h| &h.phi)
    }

    /// Get the most recent diversified public key
    pub fn latest_ppk(&self) -> Option<&DiversifiedPublicKey> {
        self.hops.last().map(|h| &h.ppk)
    }
}

/// Weight entry for routing
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WeightEntry {
    /// Public key of the neighbor
    pub pk: PublicKey,
    /// Weight value (32-bit, all weights sum to 2^32)
    pub weight: u32,
}

/// Weight matrix commitment (placeholder)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WeightCommitment {
    /// Merkle root or commitment value
    pub commitment: Vec<u8>,
    /// Metadata (will be expanded with Merkle tree structure)
    pub metadata: Vec<u8>,
}

/// Public parameters for the system
#[derive(Clone, Debug)]
pub struct PublicParams {
    /// Number of nodes
    pub num_nodes: usize,
    /// Maximum out-degree
    pub max_out_degree: usize,
    /// Cryptographic generators for the protocol
    pub generators: crate::crypto::generators::Generators,
    /// Groth16 proving key for merkle membership proof (π_1 and π_3)
    /// Used for both sender and receiver membership proofs (same circuit, same CRS)
    pub pk_merkle_membership: crate::proving::groth16::ProvingKey<PairingEngine>,
    /// Groth16 proving key for weight subtree proof (π_2)
    pub pk_weight_subtree: crate::proving::groth16::ProvingKey<PairingEngine>,
    /// Bulletproof generators for Pedersen commitments
    pub pc_gens: crate::proving::bulletproofs::PedersenGens<ark_bls12_381::G1Affine>,
    /// Bulletproof generators for R1CS proofs
    pub bp_gens: crate::proving::bulletproofs::BulletproofGens<ark_bls12_381::G1Affine>,
    /// G3 blinding generator H (from pp.generators.g3(1))
    pub h_g3: G3,
    /// Precomputed lookup tables for rerandomize gadget
    pub g3_tables: Vec<crate::proving::relations::lookup::Lookup3Bit<2, ScalarField>>,
    /// Precomputed MSM tables for batch Schnorr proving
    /// Built once during setup, used for all prove_schnorr_bridging_batch calls
    pub batch_tables: crate::proving::bulletproofs::BatchProvingTables<ark_bls12_381::G1Affine>,
}

impl PublicParams {
    /// Generate public parameters with Groth16 setup
    ///
    /// # Arguments
    /// * `num_nodes` - Number of nodes in the network
    /// * `max_out_degree` - Maximum out-degree for routing
    /// * `rng` - Random number generator
    ///
    /// # Returns
    /// Initialized PublicParams with proving keys
    pub fn generate<R: rand::Rng + rand::CryptoRng>(
        num_nodes: usize,
        max_out_degree: usize,
        rng: &mut R,
    ) -> ProtocolResult<Self> {
        use crate::proving::bulletproofs::{BulletproofGens, PedersenGens};
        use crate::proving::circuits::{MerkleMembershipCircuit, WeightSubtreeCircuit};
        use crate::proving::groth16::Groth16;
        use ark_bls12_381::G1Affine as G1A;
        use ark_crypto_primitives::snark::SNARK;

        // Generate cryptographic generators
        let generators = crate::crypto::generators::Generators::generate(rng, 10, 10, 10);

        // Generate bulletproof generators
        // Increased size to 4096 to accommodate combined re_randomize proofs (2x ~1795 constraints)
        let pc_gens = PedersenGens::<G1A>::default();
        let bp_gens = BulletproofGens::<G1A>::new(4096, 1);

        // Generate G3 blinding generator H and precompute tables
        let h_g3 = *generators
            .g3(1)
            .ok_or_else(|| ProtocolError::CryptoError("Missing G3 generator 1".to_string()))?;
        let g3_tables = crate::proving::relations::rerandomize::build_tables(h_g3);

        // Generate proving keys using circuit_specific_setup
        // For merkle membership circuit (π_1 and π_3, shared circuit and CRS)
        let merkle_circuit = MerkleMembershipCircuit::<ScalarField> {
            _phantom: std::marker::PhantomData,
        };
        let (pk_merkle_membership, _vk) =
            Groth16::<PairingEngine>::circuit_specific_setup(merkle_circuit, rng)
                .map_err(|e| ProtocolError::CryptoError(format!("Setup failed: {:?}", e)))?;

        // For weight subtree circuit (π_2)
        let weight_circuit = WeightSubtreeCircuit::<ScalarField> {
            _phantom: std::marker::PhantomData,
        };
        let (pk_weight_subtree, _vk) =
            Groth16::<PairingEngine>::circuit_specific_setup(weight_circuit, rng)
                .map_err(|e| ProtocolError::CryptoError(format!("Setup failed: {:?}", e)))?;

        // Determine circuit size for batch tables
        // The Schnorr bridging circuit has exactly 1795 constraints per rerandomize,
        // and we have 2 rerandomize operations, so n1 = 1795
        // We currently have no second phase constraints (n2 = 0)
        // Note: n1 must match the actual circuit size, not be rounded up
        let n1 = 1795; // Exact size to match the actual Schnorr bridging circuit
        let n2 = 0; // Currently no 2nd phase in Schnorr bridging

        let batch_tables = crate::proving::bulletproofs::BatchProvingTables::new(
            &pc_gens, &bp_gens, n1, n2, 8, // window_bits=8 for balanced memory/performance
        );

        Ok(PublicParams {
            num_nodes,
            max_out_degree,
            generators,
            pk_merkle_membership,
            pk_weight_subtree,
            pc_gens,
            bp_gens,
            h_g3,
            g3_tables,
            batch_tables,
        })
    }
}

/// Sub-Merkle tree (M2) for a single user's weight distribution
/// Fixed depth 4, allowing for up to 16 neighbors
#[derive(Clone, Debug)]
pub struct SubMerkleTree {
    /// Root of the sub-merkle tree (scalar field element)
    pub root: ScalarField,
    /// Leaves: [(cumulative_weight, pk_x, pk_y)]
    /// 0-th leaf is always (0, 0, 0)
    /// j-th leaf (j>0) is (cumulative_weight_up_to_j, pk_j_x, pk_j_y)
    pub leaves: Vec<(ScalarField, ScalarField, ScalarField)>,
    /// Internal nodes for proof generation (optional, can be recomputed)
    pub internal_nodes: Vec<Vec<ScalarField>>,
}

impl SubMerkleTree {
    /// Fixed depth of the sub-merkle tree (allows 2^4 = 16 leaves)
    pub const DEPTH: usize = 4;
    pub const MAX_LEAVES: usize = 1 << Self::DEPTH; // 16

    /// Build a sub-merkle tree for a user's weights to neighbors
    ///
    /// # Arguments
    /// * `neighbor_weights` - List of (neighbor_pk, weight) pairs
    ///
    /// # Returns
    /// SubMerkleTree with cumulative weights
    pub fn build(neighbor_weights: &[(PublicKey, u32)]) -> Self {
        use crate::crypto::poseidon::PoseidonHash;
        use ark_ec::AffineRepr;
        use ark_ff::PrimeField;

        let hasher = PoseidonHash::new();
        let mut leaves = Vec::new();

        // 0-th leaf is (0, 0, 0)
        leaves.push((
            ScalarField::from(0u64),
            ScalarField::from(0u64),
            ScalarField::from(0u64),
        ));

        // Build cumulative weight leaves
        let mut cumulative_weight = 0u64;
        for (neighbor_pk, weight) in neighbor_weights.iter() {
            cumulative_weight += *weight as u64;

            // Extract x and y coordinates from the Grumpkin point (G3)
            // Grumpkin coordinates are in Grumpkin's base field (BN254 Fq), convert to BLS ScalarField (Fr)
            let pk_point = neighbor_pk.pk;
            let (pk_x_base, pk_y_base) = pk_point.xy().unwrap_or_else(|| {
                // Handle point at infinity (shouldn't happen with valid keys)
                (ark_bls12_381::Fr::from(0u64), ark_bls12_381::Fr::from(0u64))
            });

            // Convert Grumpkin BaseField to BLS ScalarField via big integer representation
            let pk_x = ScalarField::from_bigint(pk_x_base.into_bigint())
                .unwrap_or_else(|| ScalarField::from(0u64));
            let pk_y = ScalarField::from_bigint(pk_y_base.into_bigint())
                .unwrap_or_else(|| ScalarField::from(0u64));

            leaves.push((ScalarField::from(cumulative_weight), pk_x, pk_y));
        }

        // Pad with (0, 0, 0) to reach MAX_LEAVES
        while leaves.len() < Self::MAX_LEAVES {
            leaves.push((
                ScalarField::from(0u64),
                ScalarField::from(0u64),
                ScalarField::from(0u64),
            ));
        }

        // Build the tree bottom-up
        let mut current_level: Vec<ScalarField> = leaves
            .iter()
            .map(|(w, x, y)| {
                // Hash each leaf: H(w, x, y)
                hasher.hash(&[*w, *x, *y])
            })
            .collect();

        let mut internal_nodes = Vec::new();
        internal_nodes.push(current_level.clone());

        // Build tree level by level
        for _ in 0..Self::DEPTH {
            let mut next_level = Vec::new();
            for i in (0..current_level.len()).step_by(2) {
                let left = current_level[i];
                let right = if i + 1 < current_level.len() {
                    current_level[i + 1]
                } else {
                    ScalarField::from(0u64)
                };
                let parent = hasher.hash(&[left, right]);
                next_level.push(parent);
            }
            current_level = next_level;
            internal_nodes.push(current_level.clone());
        }

        let root = current_level[0];

        SubMerkleTree {
            root,
            leaves,
            internal_nodes,
        }
    }
}

/// Main Merkle tree for the protocol state
/// Each leaf contains (pk_x, pk_y, M2_root) for one user
#[derive(Clone, Debug)]
pub struct MerkleTree {
    /// Root of the main merkle tree (scalar field element)
    pub root: ScalarField,
    /// Leaves: [(pk_x, pk_y, M2_root)]
    pub leaves: Vec<(ScalarField, ScalarField, ScalarField)>,
    /// Internal nodes for proof generation
    pub internal_nodes: Vec<Vec<ScalarField>>,
}

impl MerkleTree {
    /// Build the main merkle tree from public keys and their sub-merkle trees
    ///
    /// # Arguments
    /// * `users` - List of (public_key, sub_merkle_tree) pairs
    ///
    /// # Returns
    /// Main MerkleTree containing all users
    pub fn build(users: &[(PublicKey, SubMerkleTree)]) -> Self {
        use crate::crypto::poseidon::PoseidonHash;
        use ark_ec::AffineRepr;
        use ark_ff::PrimeField;

        let hasher = PoseidonHash::new();
        let mut leaves = Vec::new();

        // Build leaves from user data
        for (pk, sub_tree) in users.iter() {
            let pk_point = pk.pk;
            let (pk_x_base, pk_y_base) = pk_point
                .xy()
                .unwrap_or_else(|| (ark_bls12_381::Fr::from(0u64), ark_bls12_381::Fr::from(0u64)));

            // Convert Grumpkin BaseField to BLS ScalarField via big integer representation
            let pk_x = ScalarField::from_bigint(pk_x_base.into_bigint())
                .unwrap_or_else(|| ScalarField::from(0u64));
            let pk_y = ScalarField::from_bigint(pk_y_base.into_bigint())
                .unwrap_or_else(|| ScalarField::from(0u64));

            leaves.push((pk_x, pk_y, sub_tree.root));
        }

        // Ensure we have at least one leaf
        if leaves.is_empty() {
            leaves.push((
                ScalarField::from(0u64),
                ScalarField::from(0u64),
                ScalarField::from(0u64),
            ));
        }

        // Make the tree a complete binary tree by padding to next power of 2
        let target_size = leaves.len().next_power_of_two();
        while leaves.len() < target_size {
            leaves.push((
                ScalarField::from(0u64),
                ScalarField::from(0u64),
                ScalarField::from(0u64),
            ));
        }

        // Build the tree bottom-up
        let mut current_level: Vec<ScalarField> = leaves
            .iter()
            .map(|(x, y, m2)| {
                // Hash each leaf: H(pk_x, pk_y, M2_root)
                hasher.hash(&[*x, *y, *m2])
            })
            .collect();

        let mut internal_nodes = Vec::new();
        internal_nodes.push(current_level.clone());

        // Build tree level by level
        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            for i in (0..current_level.len()).step_by(2) {
                let left = current_level[i];
                let right = if i + 1 < current_level.len() {
                    current_level[i + 1]
                } else {
                    ScalarField::from(0u64)
                };
                let parent = hasher.hash(&[left, right]);
                next_level.push(parent);
            }
            current_level = next_level;
            internal_nodes.push(current_level.clone());
        }

        let root = current_level[0];

        MerkleTree {
            root,
            leaves,
            internal_nodes,
        }
    }

    /// Get the depth of the tree
    pub fn depth(&self) -> usize {
        self.internal_nodes.len() - 1
    }

    /// Get a Merkle proof for a specific leaf index
    pub fn get_proof(&self, leaf_index: usize) -> Option<Vec<ScalarField>> {
        if leaf_index >= self.leaves.len() {
            return None;
        }

        let mut proof = Vec::new();
        let mut current_index = leaf_index;

        for level in 0..self.depth() {
            let sibling_index = current_index ^ 1;
            if sibling_index < self.internal_nodes[level].len() {
                proof.push(self.internal_nodes[level][sibling_index]);
            }
            current_index /= 2;
        }

        Some(proof)
    }
}

/// Protocol state containing the global Merkle tree of all users and their weights
#[derive(Clone, Debug)]
pub struct ProtocolState {
    /// Main merkle tree root (commitment to all public keys and weights)
    pub merkle_tree: MerkleTree,
    /// Sub-merkle trees for each user (indexed by user index)
    pub sub_merkle_trees: Vec<SubMerkleTree>,
}

/// Result type for protocol operations
pub type ProtocolResult<T> = Result<T, ProtocolError>;

/// Protocol errors
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("Maximum hop count exceeded")]
    MaxHopsExceeded,

    #[error("Invalid proof")]
    InvalidProof,

    #[error("Invalid weight selection")]
    InvalidWeightSelection,

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),
}
