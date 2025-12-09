//! Core data structures for the ZK Brownian protocol

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

// Re-export curve types for backward compatibility and convenience
pub use crate::crypto::curve::{
    BaseField, PairingEngine, ScalarField, G1, G1 as G1Point, G2, G2 as G2Point, G3,
    G3 as GrumpkinPoint,
};

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
pub struct Proof {
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
    pub pi: Proof,
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
    pub pi_0: Proof,
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
    /// Generators for G1
    pub g1_generators: Vec<G1>,
    /// Generators for G3 (Grumpkin curve, used for public keys)
    pub g3_generators: Vec<G3>,
    /// Groth16 proving/verifying keys (stub)
    pub groth16_params: Vec<u8>,
    /// Cryptographic generators for the protocol
    pub generators: crate::crypto::generators::Generators,
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
                (ark_grumpkin::Fq::from(0u64), ark_grumpkin::Fq::from(0u64))
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
                .unwrap_or_else(|| (ark_grumpkin::Fq::from(0u64), ark_grumpkin::Fq::from(0u64)));

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
