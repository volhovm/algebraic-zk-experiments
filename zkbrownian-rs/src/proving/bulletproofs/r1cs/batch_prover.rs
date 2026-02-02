//! Batch proving for R1CS proofs using precomputed MSM tables
//!
//! This module implements batch proving for multiple R1CS proofs that share
//! the same generator bases. Instead of computing N×6 individual MSMs,
//! we collect scalars from all N provers and compute 6 batch MSMs.
//!
//! Expected speedup: 3-5× for N > 100 proofs

#![allow(non_snake_case)]

use super::*;
use crate::proving::bulletproofs::generators::{BatchProvingTables, BulletproofGens};
use ark_ec::AffineRepr;
use ark_std::Zero;
use core::borrow::BorrowMut;
use merlin::Transcript;

/// Batch prove multiple R1CS proofs using precomputed MSM tables
///
/// This function performs batch proving by:
/// 1. Collecting scalars from all provers (no MSMs)
/// 2. Computing 6 batch MSMs across all proofs
/// 3. Distributing results and completing each proof
///
/// # Arguments
///
/// * `provers` - Vector of Prover instances (one per proof)
/// * `bp_gens` - Bulletproof generators (must match table generators)
/// * `tables` - Precomputed MSM tables for the 6 commitment types
///
/// # Returns
///
/// Vector of completed R1CS proofs
///
/// # Panics
///
/// Panics if any prover has incorrect number of constraints for the tables
///
/// # Example
///
/// ```ignore
/// let provers: Vec<_> = witnesses.iter().map(|w| {
///     let mut transcript = Transcript::new(b"MyProtocol");
///     let mut prover = Prover::new(&pc_gens, &mut transcript);
///     setup_constraints(&mut prover, w);
///     prover
/// }).collect();
///
/// let proofs = prove_batch(provers, &bp_gens, &tables)?;
/// ```
pub fn prove_batch<C, T>(
    provers: Vec<Prover<'_, T, C>>,
    bp_gens: &BulletproofGens<C>,
    tables: &BatchProvingTables<C>,
) -> Result<Vec<R1CSProof<C>>, R1CSError>
where
    C: AffineRepr,
    T: BorrowMut<Transcript>,
{
    let num_proofs = provers.len();

    if num_proofs == 0 {
        return Ok(vec![]);
    }

    // Phase 1: Collect all scalars from all provers
    let (states, all_scalars): (Vec<_>, Vec<_>) = provers
        .into_iter()
        .map(|p| p.collect_scalars(bp_gens))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .unzip();

    // Phase 2: Batch MSM for each commitment type

    // A_I1 batch (parallel across all proofs)
    let a_i1_scalar_vecs: Vec<Vec<C::ScalarField>> =
        all_scalars.iter().map(|s| s.a_i1.clone()).collect();
    let a_i1_results = tables.a_i1_table.msm_batch(&a_i1_scalar_vecs);

    // A_O1 batch
    let a_o1_scalar_vecs: Vec<Vec<C::ScalarField>> =
        all_scalars.iter().map(|s| s.a_o1.clone()).collect();
    let a_o1_results = tables.a_o1_table.msm_batch(&a_o1_scalar_vecs);

    // S1 batch
    let s1_scalar_vecs: Vec<Vec<C::ScalarField>> =
        all_scalars.iter().map(|s| s.s1.clone()).collect();
    let s1_results = tables.s1_table.msm_batch(&s1_scalar_vecs);

    // A_I2 batch (handle empty case for n2=0)
    let a_i2_results = if tables.n2 > 0 {
        let a_i2_scalar_vecs: Vec<Vec<C::ScalarField>> =
            all_scalars.iter().map(|s| s.a_i2.clone()).collect();
        tables.a_i2_table.msm_batch(&a_i2_scalar_vecs)
    } else {
        vec![C::Group::zero(); num_proofs]
    };

    // A_O2 batch
    let a_o2_results = if tables.n2 > 0 {
        let a_o2_scalar_vecs: Vec<Vec<C::ScalarField>> =
            all_scalars.iter().map(|s| s.a_o2.clone()).collect();
        tables.a_o2_table.msm_batch(&a_o2_scalar_vecs)
    } else {
        vec![C::Group::zero(); num_proofs]
    };

    // S2 batch
    let s2_results = if tables.n2 > 0 {
        let s2_scalar_vecs: Vec<Vec<C::ScalarField>> =
            all_scalars.iter().map(|s| s.s2.clone()).collect();
        tables.s2_table.msm_batch(&s2_scalar_vecs)
    } else {
        vec![C::Group::zero(); num_proofs]
    };

    // Phase 3: Complete proofs with computed commitments
    states
        .into_iter()
        .enumerate()
        .map(|(i, state)| {
            state.complete_with_commitments(
                a_i1_results[i].into(),
                a_o1_results[i].into(),
                s1_results[i].into(),
                a_i2_results[i].into(),
                a_o2_results[i].into(),
                s2_results[i].into(),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proving::bulletproofs::generators::{BulletproofGens, PedersenGens};
    use ark_bls12_381::G1Affine as G1A;
    use merlin::Transcript;

    #[test]
    fn test_batch_prove_empty() {
        let pc_gens = PedersenGens::<G1A>::default();
        let bp_gens = BulletproofGens::<G1A>::new(128, 1);
        let tables = BatchProvingTables::new(&pc_gens, &bp_gens, 64, 0, 8);

        let provers: Vec<Prover<'_, &mut Transcript, G1A>> = vec![];
        let proofs = prove_batch(provers, &bp_gens, &tables).unwrap();

        assert_eq!(proofs.len(), 0);
    }

    // Note: More comprehensive tests would require setting up actual constraints
    // and witnesses. The batch prover is tested through integration tests in
    // the circuits module (test_schnorr_bridging_completeness tests the full flow).
}
