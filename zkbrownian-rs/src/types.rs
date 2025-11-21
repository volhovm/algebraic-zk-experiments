//! Core data structures for the ZK Brownian protocol

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::Error as DeError;

/// BLS12-381 scalar field element
pub type ScalarField = Fr;

/// G1 curve point (used for some commitments)
pub type G1Point = G1Affine;

/// G2 curve point (used for public keys)
pub type G2Point = G2Affine;

/// Pairing engine
pub type PairingEngine = Bls12_381;

/// Secret key (scalar in the field)
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SecretKey {
    pub sk: ScalarField,
}

/// Public key (G2 point)
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicKey {
    pub pk: G2Point,
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = Vec::new();
        self.pk.serialize_compressed(&mut bytes)
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
        let pk = G2Point::deserialize_compressed(&bytes[..])
            .map_err(|e| DeError::custom(format!("Deserialization error: {}", e)))?;
        Ok(PublicKey { pk })
    }
}

/// Diversified public key (ElGamal-style tuple)
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct DiversifiedPublicKey {
    /// pk^d component
    pub ppk_1: G2Point,
    /// G^d component
    pub ppk_2: G2Point,
}

impl Serialize for DiversifiedPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("DiversifiedPublicKey", 2)?;

        let mut bytes1 = Vec::new();
        self.ppk_1.serialize_compressed(&mut bytes1)
            .map_err(|e| serde::ser::Error::custom(format!("Serialization error: {}", e)))?;
        state.serialize_field("ppk_1", &bytes1)?;

        let mut bytes2 = Vec::new();
        self.ppk_2.serialize_compressed(&mut bytes2)
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
        let ppk_1 = G2Point::deserialize_compressed(&helper.ppk_1[..])
            .map_err(|e| DeError::custom(format!("Deserialization error: {}", e)))?;
        let ppk_2 = G2Point::deserialize_compressed(&helper.ppk_2[..])
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
    pub phi: G1Point,
}

impl Serialize for PrfOutput {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = Vec::new();
        self.phi.serialize_compressed(&mut bytes)
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
        let phi = G1Point::deserialize_compressed(&bytes[..])
            .map_err(|e| DeError::custom(format!("Deserialization error: {}", e)))?;
        Ok(PrfOutput { phi })
    }
}

/// Proof component (stub for now, will be expanded)
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize)]
pub struct Proof {
    /// Groth16 proof elements
    pub pi_1: Vec<u8>, // G1 proof
    pub pi_2: Vec<u8>, // G1 proof (weights)
    pub pi_3: Vec<u8>, // G1 proof
    pub pi_4_g1: Vec<u8>, // Schnorr in G1
    pub pi_4_g2: Vec<u8>, // Schnorr in G2
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
    pub g1_generators: Vec<G1Point>,
    /// Generators for G2
    pub g2_generators: Vec<G2Point>,
    /// Groth16 proving/verifying keys (stub)
    pub groth16_params: Vec<u8>,
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
