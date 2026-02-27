//! Binary serialization for PublicParams and UserView
//!
//! These types lack serde but their fields all implement `ark_serialize::CanonicalSerialize`.
//! We use a simple length-prefixed format for binary serialization.

use anyhow::{bail, Context, Result};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use zkbrownian::crypto::generators::Generators;
use zkbrownian::protocol::{NeighborInfo, NeighboursView, UserView};
use zkbrownian::proving::bulletproofs::{BatchProvingTables, BulletproofGens, PedersenGens};
use zkbrownian::proving::groth16::ProvingKey;
use zkbrownian::proving::relations::lookup::{Lookup3Bit, WINDOW_ELEMS};
use zkbrownian::types::{
    PairingEngine, ProofGroth16, PublicKey, PublicParams, ScalarField, SecretKey, G3,
};

use ark_bls12_381::{G1Affine, G1Projective};

// ============================================================================
// Writer helper
// ============================================================================

struct BinWriter {
    buf: Vec<u8>,
}

impl BinWriter {
    fn new() -> Self {
        Self { buf: Vec::new() }
    }

    fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    fn write_usize(&mut self, v: usize) {
        self.buf.extend_from_slice(&(v as u64).to_le_bytes());
    }

    fn write_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn write_u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn write_canonical<T: CanonicalSerialize>(&mut self, t: &T) {
        let mut bytes = Vec::new();
        t.serialize_compressed(&mut bytes)
            .expect("canonical serialize failed");
        self.write_usize(bytes.len());
        self.buf.extend_from_slice(&bytes);
    }

    fn write_vec_canonical<T: CanonicalSerialize>(&mut self, v: &[T]) {
        self.write_usize(v.len());
        for item in v {
            self.write_canonical(item);
        }
    }
}

// ============================================================================
// Reader helper
// ============================================================================

struct BinReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> BinReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.pos + n > self.data.len() {
            bail!(
                "unexpected EOF: need {} bytes, have {}",
                n,
                self.remaining()
            );
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    fn read_usize(&mut self) -> Result<usize> {
        let bytes = self.read_bytes(8)?;
        Ok(u64::from_le_bytes(bytes.try_into().unwrap()) as usize)
    }

    fn read_u32(&mut self) -> Result<u32> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn read_u64(&mut self) -> Result<u64> {
        let bytes = self.read_bytes(8)?;
        Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn read_canonical<T: CanonicalDeserialize>(&mut self) -> Result<T> {
        let len = self.read_usize()?;
        let bytes = self.read_bytes(len)?;
        T::deserialize_compressed(bytes).context("canonical deserialize failed")
    }

    fn read_vec_canonical<T: CanonicalDeserialize>(&mut self) -> Result<Vec<T>> {
        let len = self.read_usize()?;
        let mut v = Vec::with_capacity(len);
        for _ in 0..len {
            v.push(self.read_canonical()?);
        }
        Ok(v)
    }
}

// ============================================================================
// Generators serialization
// ============================================================================

fn write_generators(w: &mut BinWriter, g: &Generators) {
    w.write_canonical(&g.g1_base);
    w.write_canonical(&g.g2_base);
    w.write_canonical(&g.g3_base);
    w.write_vec_canonical(&g.g1_generators);
    w.write_vec_canonical(&g.g2_generators);
    w.write_vec_canonical(&g.g3_generators);
    w.write_vec_canonical(&g.h_commitment_bases);
}

fn read_generators(r: &mut BinReader) -> Result<Generators> {
    Ok(Generators {
        g1_base: r.read_canonical()?,
        g2_base: r.read_canonical()?,
        g3_base: r.read_canonical()?,
        g1_generators: r.read_vec_canonical()?,
        g2_generators: r.read_vec_canonical()?,
        g3_generators: r.read_vec_canonical()?,
        h_commitment_bases: r.read_vec_canonical()?,
    })
}

// ============================================================================
// PedersenGens serialization
// ============================================================================

fn write_pedersen_gens(w: &mut BinWriter, pg: &PedersenGens<G1Affine>) {
    w.write_canonical(&pg.B);
    w.write_canonical(&pg.B_blinding);
}

fn read_pedersen_gens(r: &mut BinReader) -> Result<PedersenGens<G1Affine>> {
    Ok(PedersenGens {
        B: r.read_canonical()?,
        B_blinding: r.read_canonical()?,
    })
}

// ============================================================================
// BulletproofGens serialization
//
// BulletproofGens are deterministically generated from labels+capacity,
// so we just serialize the parameters needed to reconstruct them.
// ============================================================================

fn write_bulletproof_gens(w: &mut BinWriter, bg: &BulletproofGens<G1Affine>) {
    w.write_usize(bg.gens_capacity);
    w.write_usize(bg.party_capacity);
    // Serialize actual generator points (not just reconstruction params)
    // to ensure cross-platform consistency.
    for party_g in bg.g_vec() {
        w.write_vec_canonical(party_g);
    }
    for party_h in bg.h_vec() {
        w.write_vec_canonical(party_h);
    }
}

fn read_bulletproof_gens(r: &mut BinReader) -> Result<BulletproofGens<G1Affine>> {
    let gens_capacity = r.read_usize()?;
    let party_capacity = r.read_usize()?;
    let mut g_vec = Vec::with_capacity(party_capacity);
    for _ in 0..party_capacity {
        g_vec.push(r.read_vec_canonical()?);
    }
    let mut h_vec = Vec::with_capacity(party_capacity);
    for _ in 0..party_capacity {
        h_vec.push(r.read_vec_canonical()?);
    }
    Ok(BulletproofGens::from_vecs(
        gens_capacity,
        party_capacity,
        g_vec,
        h_vec,
    ))
}

// ============================================================================
// FixedBaseMsmTable serialization
//
// These tables are huge (~40MB each) and expensive to recompute.
// We don't serialize them directly — instead we store enough info to
// reconstruct them. Since they are built from pc_gens + bp_gens + n1/n2,
// and those are deterministic, we can rebuild.
// However, we DO need to serialize the window_bits.
// For BatchProvingTables, we store (n1, n2, window_bits) and reconstruct.
// ============================================================================

fn write_batch_proving_tables(w: &mut BinWriter, bt: &BatchProvingTables<G1Affine>) {
    w.write_usize(bt.n1);
    w.write_usize(bt.n2);
    // Store window_bits from one of the tables
    w.write_usize(bt.a_i1_table.window_bits());
}

fn read_batch_proving_tables(
    r: &mut BinReader,
    pc_gens: &PedersenGens<G1Affine>,
    bp_gens: &BulletproofGens<G1Affine>,
) -> Result<BatchProvingTables<G1Affine>> {
    let n1 = r.read_usize()?;
    let n2 = r.read_usize()?;
    let window_bits = r.read_usize()?;
    Ok(BatchProvingTables::new(
        pc_gens,
        bp_gens,
        n1,
        n2,
        window_bits,
    ))
}

// ============================================================================
// Lookup3Bit serialization
// ============================================================================

fn write_lookup_tables(w: &mut BinWriter, tables: &[Lookup3Bit<2, ScalarField>]) {
    w.write_usize(tables.len());
    for table in tables {
        // Each Lookup3Bit<2, ScalarField> has elems: [[ScalarField; WINDOW_ELEMS]; 2]
        for row in &table.elems {
            for elem in row {
                w.write_canonical(elem);
            }
        }
    }
}

fn read_lookup_tables(r: &mut BinReader) -> Result<Vec<Lookup3Bit<2, ScalarField>>> {
    let len = r.read_usize()?;
    let mut tables = Vec::with_capacity(len);
    for _ in 0..len {
        let mut elems = [[ScalarField::default(); WINDOW_ELEMS]; 2];
        for row in elems.iter_mut() {
            for elem in row.iter_mut() {
                *elem = r.read_canonical()?;
            }
        }
        tables.push(Lookup3Bit { elems });
    }
    Ok(tables)
}

// ============================================================================
// PublicParams serialization
// ============================================================================

pub fn serialize_public_params(pp: &PublicParams) -> Vec<u8> {
    let mut w = BinWriter::new();

    w.write_usize(pp.num_nodes);
    w.write_usize(pp.max_out_degree);
    write_generators(&mut w, &pp.generators);
    w.write_canonical(&pp.pk_merkle_membership);
    w.write_canonical(&pp.pk_weight_subtree);
    write_pedersen_gens(&mut w, &pp.pc_gens);
    write_bulletproof_gens(&mut w, &pp.bp_gens);
    w.write_canonical(&pp.h_g3);
    write_lookup_tables(&mut w, &pp.g3_tables);
    write_batch_proving_tables(&mut w, &pp.batch_tables);

    w.into_bytes()
}

pub fn deserialize_public_params(bytes: &[u8]) -> Result<PublicParams> {
    let mut r = BinReader::new(bytes);

    let num_nodes = r.read_usize()?;
    let max_out_degree = r.read_usize()?;
    let generators = read_generators(&mut r)?;
    let pk_merkle_membership: ProvingKey<PairingEngine> = r.read_canonical()?;
    let pk_weight_subtree: ProvingKey<PairingEngine> = r.read_canonical()?;
    let pc_gens = read_pedersen_gens(&mut r)?;
    let bp_gens = read_bulletproof_gens(&mut r)?;
    let h_g3: G3 = r.read_canonical()?;
    let g3_tables = read_lookup_tables(&mut r)?;
    let batch_tables = read_batch_proving_tables(&mut r, &pc_gens, &bp_gens)?;

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

// ============================================================================
// NeighborInfo serialization
// ============================================================================

fn write_neighbor_info(w: &mut BinWriter, ni: &NeighborInfo) {
    w.write_usize(ni.index);
    w.write_canonical(&ni.public_key);
    w.write_canonical(&ni.sub_merkle_root);
    w.write_vec_canonical(&ni.merkle_proof);
    w.write_u32(ni.weight);
}

fn read_neighbor_info(r: &mut BinReader) -> Result<NeighborInfo> {
    Ok(NeighborInfo {
        index: r.read_usize()?,
        public_key: r.read_canonical()?,
        sub_merkle_root: r.read_canonical()?,
        merkle_proof: r.read_vec_canonical()?,
        weight: r.read_u32()?,
    })
}

// ============================================================================
// LocalPrecompute serialization
// ============================================================================

fn write_local_precompute(w: &mut BinWriter, lp: &zkbrownian::protocol::forward::LocalPrecompute) {
    // pi_1_sender
    w.write_canonical(&lp.pi_1_sender);

    // c11_precomputed, c12_precomputed (G1Projective)
    w.write_canonical(&lp.c11_precomputed);
    w.write_canonical(&lp.c12_precomputed);

    // pi_3_receivers
    w.write_usize(lp.pi_3_receivers.len());
    for p in &lp.pi_3_receivers {
        w.write_canonical(p);
    }

    // c21_precomputed, c22_precomputed
    w.write_vec_canonical(&lp.c21_precomputed);
    w.write_vec_canonical(&lp.c22_precomputed);

    // pi_2_weights
    w.write_usize(lp.pi_2_weights.len());
    for p in &lp.pi_2_weights {
        w.write_canonical(p);
    }

    // c_v1_precomputed: Vec<(G1Projective, u64)>
    w.write_usize(lp.c_v1_precomputed.len());
    for (point, val) in &lp.c_v1_precomputed {
        w.write_canonical(point);
        w.write_u64(*val);
    }

    // c_v2_precomputed: Vec<(G1Projective, u64)>
    w.write_usize(lp.c_v2_precomputed.len());
    for (point, val) in &lp.c_v2_precomputed {
        w.write_canonical(point);
        w.write_u64(*val);
    }

    // pc_gens and bp_gens
    write_pedersen_gens(w, &lp.pc_gens);
    write_bulletproof_gens(w, &lp.bp_gens);
}

fn read_local_precompute(
    r: &mut BinReader,
) -> Result<zkbrownian::protocol::forward::LocalPrecompute> {
    let pi_1_sender: ProofGroth16 = r.read_canonical()?;

    let c11_precomputed: G1Projective = r.read_canonical()?;
    let c12_precomputed: G1Projective = r.read_canonical()?;

    let pi_3_count = r.read_usize()?;
    let mut pi_3_receivers = Vec::with_capacity(pi_3_count);
    for _ in 0..pi_3_count {
        pi_3_receivers.push(r.read_canonical()?);
    }

    let c21_precomputed: Vec<G1Projective> = r.read_vec_canonical()?;
    let c22_precomputed: Vec<G1Projective> = r.read_vec_canonical()?;

    let pi_2_count = r.read_usize()?;
    let mut pi_2_weights = Vec::with_capacity(pi_2_count);
    for _ in 0..pi_2_count {
        pi_2_weights.push(r.read_canonical()?);
    }

    let c_v1_count = r.read_usize()?;
    let mut c_v1_precomputed = Vec::with_capacity(c_v1_count);
    for _ in 0..c_v1_count {
        let point: G1Projective = r.read_canonical()?;
        let val = r.read_u64()?;
        c_v1_precomputed.push((point, val));
    }

    let c_v2_count = r.read_usize()?;
    let mut c_v2_precomputed = Vec::with_capacity(c_v2_count);
    for _ in 0..c_v2_count {
        let point: G1Projective = r.read_canonical()?;
        let val = r.read_u64()?;
        c_v2_precomputed.push((point, val));
    }

    let pc_gens = read_pedersen_gens(r)?;
    let bp_gens = read_bulletproof_gens(r)?;

    Ok(zkbrownian::protocol::forward::LocalPrecompute {
        pi_1_sender,
        c11_precomputed,
        c12_precomputed,
        pi_3_receivers,
        c21_precomputed,
        c22_precomputed,
        pi_2_weights,
        c_v1_precomputed,
        c_v2_precomputed,
        pc_gens,
        bp_gens,
    })
}

// ============================================================================
// UserView serialization
// ============================================================================

pub fn serialize_user_view(uv: &UserView) -> Vec<u8> {
    let mut w = BinWriter::new();

    w.write_canonical(&uv.secret_key);
    w.write_canonical(&uv.public_key);

    // neighbours_view
    w.write_usize(uv.neighbours_view.neighbors.len());
    for ni in &uv.neighbours_view.neighbors {
        write_neighbor_info(&mut w, ni);
    }

    w.write_canonical(&uv.own_sub_merkle_root);
    w.write_vec_canonical(&uv.own_merkle_proof);

    write_local_precompute(&mut w, &uv.precompute);

    w.into_bytes()
}

pub fn deserialize_user_view(bytes: &[u8]) -> Result<UserView> {
    let mut r = BinReader::new(bytes);

    let secret_key: SecretKey = r.read_canonical()?;
    let public_key: PublicKey = r.read_canonical()?;

    let neighbor_count = r.read_usize()?;
    let mut neighbors = Vec::with_capacity(neighbor_count);
    for _ in 0..neighbor_count {
        neighbors.push(read_neighbor_info(&mut r)?);
    }
    let neighbours_view = NeighboursView { neighbors };

    let own_sub_merkle_root: ScalarField = r.read_canonical()?;
    let own_merkle_proof: Vec<ScalarField> = r.read_vec_canonical()?;

    let precompute = read_local_precompute(&mut r)?;

    Ok(UserView {
        secret_key,
        public_key,
        neighbours_view,
        own_sub_merkle_root,
        own_merkle_proof,
        precompute,
    })
}

// ============================================================================
// Verification data serialization (merkle_root + all_public_keys)
// ============================================================================

pub fn serialize_verification_data(
    merkle_root: &ScalarField,
    public_keys: &[PublicKey],
) -> Vec<u8> {
    let mut w = BinWriter::new();
    w.write_canonical(merkle_root);
    w.write_usize(public_keys.len());
    for pk in public_keys {
        w.write_canonical(pk);
    }
    w.into_bytes()
}

pub fn deserialize_verification_data(bytes: &[u8]) -> Result<(ScalarField, Vec<PublicKey>)> {
    let mut r = BinReader::new(bytes);
    let merkle_root: ScalarField = r.read_canonical()?;
    let count = r.read_usize()?;
    let mut public_keys = Vec::with_capacity(count);
    for _ in 0..count {
        public_keys.push(r.read_canonical()?);
    }
    Ok((merkle_root, public_keys))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_params_roundtrip() {
        let mut rng = rand::thread_rng();
        let pp = PublicParams::generate(3, 10, &mut rng).expect("Failed to generate params");

        let bytes = serialize_public_params(&pp);
        println!("PublicParams serialized to {} bytes", bytes.len());

        let pp2 = deserialize_public_params(&bytes).expect("Failed to deserialize");

        assert_eq!(pp.num_nodes, pp2.num_nodes);
        assert_eq!(pp.max_out_degree, pp2.max_out_degree);
        assert_eq!(pp.h_g3, pp2.h_g3);
        assert_eq!(pp.generators.g1_base, pp2.generators.g1_base);
        assert_eq!(pp.generators.g2_base, pp2.generators.g2_base);
        assert_eq!(pp.generators.g3_base, pp2.generators.g3_base);
    }

    #[test]
    fn test_user_view_roundtrip() {
        let mut rng = rand::thread_rng();
        let pp = PublicParams::generate(3, 10, &mut rng).expect("Failed to generate params");
        let state = zkbrownian::protocol::generate_random_state(&pp, 3, &mut rng);

        for (i, uv) in state.users_view.iter().enumerate() {
            let bytes = serialize_user_view(uv);
            println!("UserView[{}] serialized to {} bytes", i, bytes.len());

            let uv2 = deserialize_user_view(&bytes).expect("Failed to deserialize");

            assert_eq!(uv.secret_key.sk, uv2.secret_key.sk);
            assert_eq!(uv.public_key.pk, uv2.public_key.pk);
            assert_eq!(uv.own_sub_merkle_root, uv2.own_sub_merkle_root);
            assert_eq!(uv.own_merkle_proof, uv2.own_merkle_proof);
            assert_eq!(
                uv.neighbours_view.neighbors.len(),
                uv2.neighbours_view.neighbors.len()
            );
        }
    }
}
