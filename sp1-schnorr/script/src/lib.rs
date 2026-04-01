//! Library for SP1 Schnorr batch verification host-side logic.
//!
//! Contains helpers for serialization, test data generation, guest input
//! preparation, and MSM verification. Used by both the CLI binary and tests.

#![allow(non_snake_case)]
#![allow(clippy::type_complexity)]
#![allow(clippy::too_many_arguments)]

use ark_bls12_381::G1Affine as G1A;
use ark_ec::short_weierstrass::Affine as SWAffine;
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
use ark_ec::VariableBaseMSM;
use ark_ed_on_bls12_381::SWAffine as G3;
use ark_ff::UniformRand;
use ark_ff::Zero;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use sha2::{Digest, Sha256};
use sp1_sdk::prelude::*;

pub use sp1_schnorr_lib::{GuestInput, GuestOutput, InstanceData, LookupTableData, ProofData};

use zkbrownian::proving::bulletproofs::r1cs::R1CSProof;
use zkbrownian::proving::bulletproofs::{BulletproofGens, PedersenGens};
use zkbrownian::proving::circuits::{
    prove_schnorr_bridging, SchnorrBridgingInstance, SchnorrBridgingWitness,
};
use zkbrownian::proving::relations::rerandomize::build_tables;

pub const ELF: Elf = include_elf!("sp1-schnorr-program");

/// Serialize a G1Affine point to compressed bytes.
pub fn point_to_bytes(p: &G1A) -> Vec<u8> {
    let mut buf = Vec::new();
    p.serialize_compressed(&mut buf).unwrap();
    buf
}

/// Serialize a scalar to 32 bytes (little-endian).
pub fn scalar_to_bytes(s: &ark_bls12_381::Fr) -> [u8; 32] {
    let mut buf = [0u8; 32];
    s.serialize_compressed(&mut buf[..]).unwrap();
    buf
}

/// Deserialize a scalar from 32 bytes.
pub fn scalar_from_bytes(bytes: &[u8; 32]) -> ark_bls12_381::Fr {
    ark_bls12_381::Fr::deserialize_compressed(&bytes[..]).unwrap()
}

/// Convert R1CSProof fields into ProofData for the guest.
pub fn proof_to_data(proof: &R1CSProof<G1A>) -> ProofData {
    ProofData {
        a_i1_bytes: point_to_bytes(&proof.A_I1),
        a_o1_bytes: point_to_bytes(&proof.A_O1),
        s1_bytes: point_to_bytes(&proof.S1),
        a_i2_bytes: point_to_bytes(&proof.A_I2),
        a_o2_bytes: point_to_bytes(&proof.A_O2),
        s2_bytes: point_to_bytes(&proof.S2),
        t_points_bytes: proof.T.iter().map(point_to_bytes).collect(),
        t_x: scalar_to_bytes(&proof.t_x),
        t_x_blinding: scalar_to_bytes(&proof.t_x_blinding),
        e_blinding: scalar_to_bytes(&proof.e_blinding),
        l_vec: proof.l_vec.iter().map(scalar_to_bytes).collect(),
        r_vec: proof.r_vec.iter().map(scalar_to_bytes).collect(),
    }
}

/// Convert lookup tables from arkworks to serialized format for the guest.
pub fn tables_to_data(
    tables: &[zkbrownian::proving::relations::lookup::Lookup3Bit<2, ark_bls12_381::Fr>],
) -> Vec<LookupTableData> {
    tables
        .iter()
        .map(|table| {
            let mut elems = [[[0u8; 32]; 8]; 2];
            for (row_idx, row) in table.elems.iter().enumerate() {
                for (col_idx, elem) in row.iter().enumerate() {
                    elem.serialize_compressed(&mut elems[row_idx][col_idx][..])
                        .unwrap();
                }
            }
            LookupTableData { elems }
        })
        .collect()
}

/// Convert instance to serialized format.
pub fn instance_to_data(instance: &SchnorrBridgingInstance) -> InstanceData {
    let pk_star = instance.pk_star_blinded;
    let pk_r_star = instance.pk_r_star_blinded;

    let SWAffine { x, y, .. } = pk_star;
    let (pk_star_x, pk_star_y) = (x, y);
    let SWAffine { x, y, .. } = pk_r_star;
    let (pk_r_star_x, pk_r_star_y) = (x, y);

    InstanceData {
        pk_star_blinded_x: scalar_to_bytes(&pk_star_x),
        pk_star_blinded_y: scalar_to_bytes(&pk_star_y),
        pk_r_star_blinded_x: scalar_to_bytes(&pk_r_star_x),
        pk_r_star_blinded_y: scalar_to_bytes(&pk_r_star_y),
    }
}

/// Generate test proofs using zkbrownian.
pub fn generate_test_data(
    num_proofs: usize,
) -> (
    Vec<R1CSProof<G1A>>,
    Vec<SchnorrBridgingInstance>,
    Vec<zkbrownian::proving::relations::lookup::Lookup3Bit<2, ark_bls12_381::Fr>>,
    PedersenGens<G1A>,
    BulletproofGens<G1A>,
) {
    use zkbrownian::crypto::curve::scalar_to_g3_scalar;

    let mut rng = ark_std::test_rng();

    let pc_gens = PedersenGens::<G1A>::default();
    let bp_gens = BulletproofGens::<G1A>::new(2048, 1);

    let h_g3 = G3::rand(&mut rng);
    let g3_tables = build_tables(h_g3);

    let mut r1cs_proofs = Vec::with_capacity(num_proofs);
    let mut instances = Vec::with_capacity(num_proofs);

    for _ in 0..num_proofs {
        let pk_x = ark_bls12_381::Fr::rand(&mut rng);
        let pk_y = ark_bls12_381::Fr::rand(&mut rng);
        let md_2_k_s = ark_bls12_381::Fr::rand(&mut rng);
        let r1 = ark_bls12_381::Fr::rand(&mut rng);

        let pk_r_x = ark_bls12_381::Fr::rand(&mut rng);
        let pk_r_y = ark_bls12_381::Fr::rand(&mut rng);
        let md_2_k_r = ark_bls12_381::Fr::rand(&mut rng);
        let r2 = ark_bls12_381::Fr::rand(&mut rng);

        let v1 = 100u64;
        let r_v1 = ark_bls12_381::Fr::rand(&mut rng);
        let v2 = 200u64;
        let r_v2 = ark_bls12_381::Fr::rand(&mut rng);

        let rho = ark_bls12_381::Fr::rand(&mut rng);
        let r_star = ark_bls12_381::Fr::rand(&mut rng);
        let r_r_star = ark_bls12_381::Fr::rand(&mut rng);

        let pk_star_g3 = G3::rand(&mut rng);
        let pk_r_star_g3 = G3::rand(&mut rng);

        let r_star_g3 = scalar_to_g3_scalar(&r_star);
        let r_r_star_g3 = scalar_to_g3_scalar(&r_r_star);
        let pk_star_blinded = (pk_star_g3 + h_g3 * r_star_g3).into_affine();
        let pk_r_star_blinded = (pk_r_star_g3 + h_g3 * r_r_star_g3).into_affine();

        let witness = SchnorrBridgingWitness {
            pk_x,
            pk_y,
            md_2_k_s,
            r1,
            pk_r_x,
            pk_r_y,
            md_2_k_r,
            r2,
            v1,
            r_v1,
            v2,
            r_v2,
            rho,
            r_star,
            r_r_star,
            pk_star_g3,
            pk_star_blinded,
            pk_r_star_g3,
            pk_r_star_blinded,
        };

        let c11 = ark_bls12_381::G1Projective::rand(&mut rng);
        let c12 = ark_bls12_381::G1Projective::rand(&mut rng);
        let c21 = ark_bls12_381::G1Projective::rand(&mut rng);
        let c22 = ark_bls12_381::G1Projective::rand(&mut rng);
        let c_v1_proj = ark_bls12_381::G1Projective::rand(&mut rng);
        let c_v2_proj = ark_bls12_381::G1Projective::rand(&mut rng);
        let g_rho = ark_bls12_381::G1Projective::rand(&mut rng);

        let instance = SchnorrBridgingInstance {
            pk_star_blinded,
            pk_r_star_blinded,
            c11,
            c12,
            c21,
            c22,
            c_v1: c_v1_proj,
            c_v2: c_v2_proj,
            g_rho,
        };

        let schnorr_proof =
            prove_schnorr_bridging(&instance, &witness, &pc_gens, &bp_gens, &h_g3, &g3_tables)
                .expect("Proof generation should succeed");

        let r1cs_proof = R1CSProof::<G1A>::deserialize_compressed(&schnorr_proof.data[..])
            .expect("Failed to deserialize R1CS proof");

        r1cs_proofs.push(r1cs_proof);
        instances.push(instance);
    }

    (r1cs_proofs, instances, g3_tables, pc_gens, bp_gens)
}

/// Verify proofs natively (host-side) to confirm test data validity.
pub fn verify_natively(
    r1cs_proofs: &[R1CSProof<G1A>],
    instances: &[SchnorrBridgingInstance],
    pc_gens: &PedersenGens<G1A>,
    bp_gens: &BulletproofGens<G1A>,
    g3_tables: &[zkbrownian::proving::relations::lookup::Lookup3Bit<2, ark_bls12_381::Fr>],
) {
    use zkbrownian::proving::circuits::verify_schnorr_bridging;
    for (i, (r1cs_proof, instance)) in r1cs_proofs.iter().zip(instances.iter()).enumerate() {
        let schnorr_proof = {
            let mut buf = Vec::new();
            r1cs_proof.serialize_compressed(&mut buf).unwrap();
            zkbrownian::types::Schnorr::<G1A> {
                data: buf,
                _phantom: std::marker::PhantomData,
            }
        };
        let result = verify_schnorr_bridging(&schnorr_proof, instance, pc_gens, bp_gens, g3_tables);
        match result {
            Ok(true) => println!("  Proof {} verified natively OK", i),
            other => panic!("  Proof {} native verification FAILED: {:?}", i, other),
        }
    }
}

/// Prepare GuestInput from test data.
///
/// Returns (input, r_scalars_bytes, batch_random_scalars_bytes) so the host
/// can later recompute the same scalars for hash verification.
pub fn prepare_guest_input(
    r1cs_proofs: &[R1CSProof<G1A>],
    instances: &[SchnorrBridgingInstance],
    g3_tables: &[zkbrownian::proving::relations::lookup::Lookup3Bit<2, ark_bls12_381::Fr>],
    num_proofs: usize,
) -> (GuestInput, Vec<[u8; 32]>, Vec<[u8; 32]>) {
    let proof_data: Vec<ProofData> = r1cs_proofs.iter().map(proof_to_data).collect();
    let instance_data: Vec<InstanceData> = instances.iter().map(instance_to_data).collect();
    let table_data = tables_to_data(g3_tables);

    let mut rng = rand::thread_rng();
    let batch_random_scalars: Vec<[u8; 32]> = (0..num_proofs.saturating_sub(1))
        .map(|_| scalar_to_bytes(&ark_bls12_381::Fr::rand(&mut rng)))
        .collect();
    let r_scalars: Vec<[u8; 32]> = (0..num_proofs)
        .map(|_| scalar_to_bytes(&ark_bls12_381::Fr::rand(&mut rng)))
        .collect();

    let input = GuestInput {
        num_proofs: num_proofs as u32,
        proofs: proof_data,
        instances: instance_data,
        lookup_tables: table_data,
        batch_random_scalars: batch_random_scalars.clone(),
        r_scalars: r_scalars.clone(),
    };

    (input, r_scalars, batch_random_scalars)
}

/// Recompute the same verification scalars the guest computes, hash them,
/// and return the hash along with the points/scalars needed for MSM.
pub fn compute_host_output_hash(
    r1cs_proofs: &[R1CSProof<G1A>],
    instances: &[SchnorrBridgingInstance],
    g3_tables: &[zkbrownian::proving::relations::lookup::Lookup3Bit<2, ark_bls12_381::Fr>],
    r_scalars_bytes: &[[u8; 32]],
    batch_random_scalars_bytes: &[[u8; 32]],
) -> (
    [u8; 32],
    Vec<G1A>,
    Vec<ark_bls12_381::Fr>,
    Vec<ark_bls12_381::Fr>,
    usize,
) {
    // 1. Convert byte scalars to arkworks Fr
    let r_scalars: Vec<ark_bls12_381::Fr> = r_scalars_bytes.iter().map(scalar_from_bytes).collect();
    let batch_random_scalars: Vec<ark_bls12_381::Fr> = batch_random_scalars_bytes
        .iter()
        .map(scalar_from_bytes)
        .collect();

    // 2. Build (Schnorr, Instance) pairs for zkbrownian
    let proofs_and_instances: Vec<_> = r1cs_proofs
        .iter()
        .zip(instances.iter())
        .map(|(proof, instance)| {
            let mut buf = Vec::new();
            proof.serialize_compressed(&mut buf).unwrap();
            let schnorr = zkbrownian::types::Schnorr::<G1A> {
                data: buf,
                _phantom: std::marker::PhantomData,
            };
            (schnorr, instance.clone())
        })
        .collect();

    // 3. Compute scalars via zkbrownian
    let (proof_points, proof_scalars, fixed_scalars, padded_n) =
        zkbrownian::proving::circuits::compute_schnorr_bridging_batch_scalars(
            &proofs_and_instances,
            g3_tables,
            &r_scalars,
            &batch_random_scalars,
        )
        .expect("scalar computation failed");

    // 4. Hash in same order as guest:
    //    proof_point_bytes || proof_scalar_bytes || fixed_scalar_bytes || padded_n_le
    let mut hasher = Sha256::new();
    for point in &proof_points {
        hasher.update(point_to_bytes(point));
    }
    for scalar in &proof_scalars {
        hasher.update(scalar_to_bytes(scalar));
    }
    for scalar in &fixed_scalars {
        hasher.update(scalar_to_bytes(scalar));
    }
    hasher.update((padded_n as u32).to_le_bytes());
    let hash: [u8; 32] = hasher.finalize().into();

    (hash, proof_points, proof_scalars, fixed_scalars, padded_n)
}

/// Verify the guest's output hash matches the host's independent computation,
/// then perform the MSM check.
pub fn verify_output_hash_and_msm(
    output: &GuestOutput,
    r1cs_proofs: &[R1CSProof<G1A>],
    instances: &[SchnorrBridgingInstance],
    g3_tables: &[zkbrownian::proving::relations::lookup::Lookup3Bit<2, ark_bls12_381::Fr>],
    r_scalars: &[[u8; 32]],
    batch_random_scalars: &[[u8; 32]],
    pc_gens: &PedersenGens<G1A>,
    bp_gens: &BulletproofGens<G1A>,
) -> bool {
    let (host_hash, proof_points, proof_scalars, fixed_scalars, padded_n) =
        compute_host_output_hash(
            r1cs_proofs,
            instances,
            g3_tables,
            r_scalars,
            batch_random_scalars,
        );

    // Check hash
    if output.output_hash != host_hash {
        println!("ERROR: output hash mismatch!");
        println!("  guest: {:?}", output.output_hash);
        println!("  host:  {:?}", host_hash);
        return false;
    }
    assert_eq!(output.padded_n, padded_n as u32);

    // MSM check
    let gens = bp_gens.share(0);
    let fixed_points: Vec<G1A> = std::iter::once(pc_gens.B)
        .chain(std::iter::once(pc_gens.B_blinding))
        .chain(gens.G(padded_n).copied())
        .chain(gens.H(padded_n).copied())
        .collect();

    let all_points: Vec<G1A> = proof_points.into_iter().chain(fixed_points).collect();
    let all_scalars: Vec<ark_bls12_381::Fr> =
        proof_scalars.into_iter().chain(fixed_scalars).collect();
    let result = <G1A as AffineRepr>::Group::msm_unchecked(&all_points, &all_scalars);

    result.is_zero()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sp1_sdk::ProverClient;

    /// Shared helper: generate test data, execute SP1 guest, verify hash+MSM.
    /// Returns the cycle count.
    async fn run_batch_execute(num_proofs: usize) -> u64 {
        println!("Generating {} test proof(s)...", num_proofs);
        let (r1cs_proofs, instances, g3_tables, pc_gens, bp_gens) = generate_test_data(num_proofs);
        println!("Test data generated.");

        println!("Verifying natively...");
        verify_natively(&r1cs_proofs, &instances, &pc_gens, &bp_gens, &g3_tables);
        println!("Native verification passed.");

        let (input, r_scalars, batch_random_scalars) =
            prepare_guest_input(&r1cs_proofs, &instances, &g3_tables, num_proofs);
        println!("Serialized GuestInput: {} proofs", input.num_proofs);

        let client = ProverClient::builder().cpu().build().await;
        let mut stdin = SP1Stdin::new();
        stdin.write(&input);

        println!("Executing SP1 guest...");
        let (mut public_values, report) =
            client.execute(ELF, stdin).await.expect("execution failed");
        let cycles = report.total_instruction_count();
        println!("Execution complete. Cycles: {}", cycles);

        let output: GuestOutput = public_values.read();
        println!(
            "Guest output: padded_n={}, hash={:?}",
            output.padded_n,
            &output.output_hash[..8]
        );

        println!("Verifying hash+MSM on host...");
        assert!(
            verify_output_hash_and_msm(
                &output,
                &r1cs_proofs,
                &instances,
                &g3_tables,
                &r_scalars,
                &batch_random_scalars,
                &pc_gens,
                &bp_gens
            ),
            "Hash+MSM check FAILED"
        );
        println!("Hash+MSM check PASSED!");

        cycles
    }

    #[tokio::test]
    async fn test_batch_1_proof() {
        let cycles = run_batch_execute(1).await;
        println!("==> 1 proof: {} cycles", cycles);
    }

    #[tokio::test]
    async fn test_batch_3_proofs() {
        let cycles = run_batch_execute(3).await;
        println!("==> 3 proofs: {} cycles", cycles);
    }

    #[tokio::test]
    async fn test_profile_1_proof() {
        println!("Generating 1 test proof for profiling...");
        let (r1cs_proofs, instances, g3_tables, pc_gens, bp_gens) = generate_test_data(1);

        println!("Verifying natively...");
        verify_natively(&r1cs_proofs, &instances, &pc_gens, &bp_gens, &g3_tables);

        let (input, r_scalars, batch_random_scalars) =
            prepare_guest_input(&r1cs_proofs, &instances, &g3_tables, 1);

        let client = ProverClient::builder().cpu().build().await;
        let mut stdin = SP1Stdin::new();
        stdin.write(&input);

        println!("Executing SP1 guest with profiling...");
        let (mut public_values, report) =
            client.execute(ELF, stdin).await.expect("execution failed");

        let output: GuestOutput = public_values.read();

        // Verify correctness
        assert!(
            verify_output_hash_and_msm(
                &output,
                &r1cs_proofs,
                &instances,
                &g3_tables,
                &r_scalars,
                &batch_random_scalars,
                &pc_gens,
                &bp_gens
            ),
            "Hash+MSM check FAILED"
        );
        println!("Hash+MSM check PASSED.");

        // Print cycle tracker breakdown
        println!("\n=== Cycle Tracker Breakdown ===");
        let mut cycle_entries: Vec<_> = report.cycle_tracker.iter().collect();
        cycle_entries.sort_by(|a, b| b.1.cmp(a.1));
        let total_cycles = report.total_instruction_count();
        for (label, cycles) in &cycle_entries {
            let pct = (**cycles as f64 / total_cycles as f64) * 100.0;
            println!("  {:<30} {:>12} cycles ({:>5.1}%)", label, cycles, pct);
        }
        println!("  {:<30} {:>12} cycles", "TOTAL", total_cycles);

        // Print top opcode counts
        println!("\n=== Top Opcode Counts ===");
        let mut opcode_entries: Vec<_> = report.opcode_counts.iter().collect();
        opcode_entries.sort_by(|a, b| b.1.cmp(a.1));
        for (opcode, count) in opcode_entries.iter().take(15) {
            let pct = (**count as f64 / total_cycles as f64) * 100.0;
            println!(
                "  {:<30} {:>12} ({:>5.1}%)",
                format!("{:?}", opcode),
                count,
                pct
            );
        }

        println!("\n==> Total cycles: {}", total_cycles);
    }

    #[tokio::test]
    #[ignore] // ~5 min
    async fn test_batch_10_proofs() {
        let cycles = run_batch_execute(10).await;
        println!("==> 10 proofs: {} cycles", cycles);
    }

    #[tokio::test]
    #[ignore] // very expensive — generates a real SP1 core proof
    async fn test_sp1_core_proof() {
        println!("Generating 1 test proof...");
        let (r1cs_proofs, instances, g3_tables, pc_gens, bp_gens) = generate_test_data(1);

        println!("Verifying natively...");
        verify_natively(&r1cs_proofs, &instances, &pc_gens, &bp_gens, &g3_tables);

        let (input, r_scalars, batch_random_scalars) =
            prepare_guest_input(&r1cs_proofs, &instances, &g3_tables, 1);

        let client = ProverClient::builder().cpu().build().await;
        let pk = client.setup(ELF).await.expect("setup failed");

        let mut stdin = SP1Stdin::new();
        stdin.write(&input);

        println!("Generating SP1 compressed proof...");
        let proof = client
            .prove(&pk, stdin)
            .compressed()
            .await
            .expect("proof generation failed");

        println!("Verifying SP1 compressed proof...");
        client
            .verify(&proof, pk.verifying_key(), None)
            .expect("proof verification failed");
        println!("SP1 compressed proof verified successfully!");

        // Also verify hash+MSM from the proof's public values
        let mut public_values = proof.public_values.clone();
        let output: GuestOutput = public_values.read();
        assert!(
            verify_output_hash_and_msm(
                &output,
                &r1cs_proofs,
                &instances,
                &g3_tables,
                &r_scalars,
                &batch_random_scalars,
                &pc_gens,
                &bp_gens
            ),
            "Hash+MSM check on core proof FAILED"
        );
        println!("Hash+MSM check on core proof PASSED!");
    }
}
