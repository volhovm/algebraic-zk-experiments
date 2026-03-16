//! Host driver for SP1 Schnorr batch verification.
//!
//! This script:
//! 1. Generates test proofs using zkbrownian
//! 2. Serializes them into GuestInput
//! 3. Executes the SP1 guest
//! 4. Reads GuestOutput
//! 5. Performs the final MSM check using arkworks

#![allow(non_snake_case)]

use ark_bls12_381::G1Affine as G1A;
use ark_ec::short_weierstrass::Affine as SWAffine;
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
use ark_ec::VariableBaseMSM;
use ark_ed_on_bls12_381::EdwardsAffine as G3;
use ark_ff::PrimeField;
use ark_ff::UniformRand;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use sp1_sdk::prelude::*;
use sp1_sdk::ProverClient;

use sp1_schnorr_lib::{GuestInput, GuestOutput, InstanceData, LookupTableData, ProofData};

use zkbrownian::proving::bulletproofs::r1cs::R1CSProof;
use zkbrownian::proving::bulletproofs::{BulletproofGens, PedersenGens};
use zkbrownian::proving::circuits::{
    prove_schnorr_bridging, SchnorrBridgingInstance, SchnorrBridgingWitness,
};
use zkbrownian::proving::relations::rerandomize::build_tables;

pub const ELF: Elf = include_elf!("sp1-schnorr-program");

/// Serialize a G1Affine point to compressed bytes.
fn point_to_bytes(p: &G1A) -> Vec<u8> {
    let mut buf = Vec::new();
    p.serialize_compressed(&mut buf).unwrap();
    buf
}

/// Serialize a scalar to 32 bytes (little-endian).
fn scalar_to_bytes(s: &ark_bls12_381::Fr) -> [u8; 32] {
    let mut buf = [0u8; 32];
    s.serialize_compressed(&mut buf[..]).unwrap();
    buf
}

/// Deserialize a scalar from 32 bytes.
fn scalar_from_bytes(bytes: &[u8; 32]) -> ark_bls12_381::Fr {
    ark_bls12_381::Fr::deserialize_compressed(&bytes[..]).unwrap()
}

/// Convert R1CSProof fields into ProofData for the guest.
fn proof_to_data(proof: &R1CSProof<G1A>) -> ProofData {
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
fn tables_to_data(
    tables: &[zkbrownian::proving::relations::lookup::Lookup3Bit<2, ark_bls12_381::Fr>],
) -> Vec<LookupTableData> {
    tables
        .iter()
        .map(|table| {
            let mut elems: [[Vec<u8>; 8]; 2] = Default::default();
            for (row_idx, row) in table.elems.iter().enumerate() {
                for (col_idx, elem) in row.iter().enumerate() {
                    elems[row_idx][col_idx] = {
                        let mut buf = Vec::new();
                        elem.serialize_compressed(&mut buf).unwrap();
                        buf
                    };
                }
            }
            LookupTableData { elems }
        })
        .collect()
}

/// Convert instance to serialized format.
fn instance_to_data(instance: &SchnorrBridgingInstance) -> InstanceData {
    // The pk_star_blinded and pk_r_star_blinded are G3 (ed-on-bls12-381) points.
    // Their x/y coordinates are BLS12-381 Fr scalars.
    let pk_star = instance.pk_star_blinded;
    let pk_r_star = instance.pk_r_star_blinded;

    // Extract x/y from the SWAffine representation
    let (pk_star_x, pk_star_y) = match pk_star {
        SWAffine { x, y, .. } => (x, y),
    };
    let (pk_r_star_x, pk_r_star_y) = match pk_r_star {
        SWAffine { x, y, .. } => (x, y),
    };

    InstanceData {
        pk_star_blinded_x: scalar_to_bytes(&pk_star_x),
        pk_star_blinded_y: scalar_to_bytes(&pk_star_y),
        pk_r_star_blinded_x: scalar_to_bytes(&pk_r_star_x),
        pk_r_star_blinded_y: scalar_to_bytes(&pk_r_star_y),
    }
}

/// Generate test proofs using zkbrownian.
fn generate_test_data(
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
        // Generate random witness values
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

        use ark_ec::Group;
        let c11 = <G1A as AffineRepr>::Group::rand(&mut rng);
        let c12 = <G1A as AffineRepr>::Group::rand(&mut rng);
        let c21 = <G1A as AffineRepr>::Group::rand(&mut rng);
        let c22 = <G1A as AffineRepr>::Group::rand(&mut rng);
        let c_v1_proj = <G1A as AffineRepr>::Group::rand(&mut rng);
        let c_v2_proj = <G1A as AffineRepr>::Group::rand(&mut rng);
        let g_rho = <G1A as AffineRepr>::Group::rand(&mut rng);

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

        // Deserialize the R1CS proof from the Schnorr proof wrapper
        let r1cs_proof = R1CSProof::<G1A>::deserialize_compressed(&schnorr_proof.data[..])
            .expect("Failed to deserialize R1CS proof");

        r1cs_proofs.push(r1cs_proof);
        instances.push(instance);
    }

    (r1cs_proofs, instances, g3_tables, pc_gens, bp_gens)
}

/// Perform the MSM verification on host side.
fn verify_msm(
    output: &GuestOutput,
    pc_gens: &PedersenGens<G1A>,
    bp_gens: &BulletproofGens<G1A>,
) -> bool {
    let padded_n = output.padded_n as usize;

    // Deserialize proof points
    let proof_points: Vec<G1A> = output
        .proof_points_bytes
        .iter()
        .map(|bytes| G1A::deserialize_compressed(&bytes[..]).unwrap())
        .collect();

    // Deserialize proof scalars
    let proof_scalars: Vec<ark_bls12_381::Fr> =
        output.proof_scalars.iter().map(scalar_from_bytes).collect();

    // Deserialize fixed scalars
    let fixed_scalars: Vec<ark_bls12_381::Fr> =
        output.fixed_scalars.iter().map(scalar_from_bytes).collect();

    assert_eq!(
        proof_points.len(),
        proof_scalars.len(),
        "proof points/scalars length mismatch"
    );
    assert_eq!(
        fixed_scalars.len(),
        2 + 2 * padded_n,
        "fixed scalars length mismatch"
    );

    // Reconstruct fixed generators
    let gens = bp_gens.share(0);
    if bp_gens.gens_capacity < padded_n {
        println!("ERROR: bp_gens capacity {} < padded_n {}", bp_gens.gens_capacity, padded_n);
        return false;
    }

    let fixed_points: Vec<G1A> = std::iter::once(pc_gens.B)
        .chain(std::iter::once(pc_gens.B_blinding))
        .chain(gens.G(padded_n).copied())
        .chain(gens.H(padded_n).copied())
        .collect();

    assert_eq!(
        fixed_points.len(),
        fixed_scalars.len(),
        "fixed points/scalars length mismatch"
    );

    // Combine all points and scalars for MSM
    let all_points: Vec<G1A> = proof_points
        .into_iter()
        .chain(fixed_points)
        .collect();

    let all_scalars: Vec<ark_bls12_381::Fr> = proof_scalars
        .into_iter()
        .chain(fixed_scalars)
        .collect();

    // Perform MSM
    let result = <G1A as AffineRepr>::Group::msm_unchecked(&all_points, &all_scalars);

    result.is_zero()
}

#[tokio::main]
async fn main() {
    sp1_sdk::utils::setup_logger();

    let num_proofs: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);

    println!("SP1 Schnorr Batch Verification Host");
    println!("Generating {} test proof(s)...", num_proofs);

    let (r1cs_proofs, instances, g3_tables, pc_gens, bp_gens) = generate_test_data(num_proofs);
    println!("Test data generated successfully.");

    // Verify natively first to confirm test data is valid
    println!("Verifying natively...");
    {
        use zkbrownian::proving::circuits::verify_schnorr_bridging;
        for (i, (r1cs_proof, instance)) in
            r1cs_proofs.iter().zip(instances.iter()).enumerate()
        {
            let schnorr_proof = {
                let mut buf = Vec::new();
                r1cs_proof.serialize_compressed(&mut buf).unwrap();
                zkbrownian::types::Schnorr::<G1A> {
                    data: buf,
                    _phantom: std::marker::PhantomData,
                }
            };
            let result = verify_schnorr_bridging(
                &schnorr_proof,
                instance,
                &pc_gens,
                &bp_gens,
                &g3_tables,
            );
            match result {
                Ok(true) => println!("  Proof {} verified natively OK", i),
                other => panic!("  Proof {} native verification FAILED: {:?}", i, other),
            }
        }
    }
    println!("Native verification passed.");

    // Serialize into GuestInput
    let proof_data: Vec<ProofData> = r1cs_proofs.iter().map(proof_to_data).collect();
    let instance_data: Vec<InstanceData> = instances.iter().map(instance_to_data).collect();
    let table_data = tables_to_data(&g3_tables);

    // Generate random scalars for batch combination and r_scalars
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
        batch_random_scalars,
        r_scalars,
    };

    println!("Serialized GuestInput: {} proofs", input.num_proofs);

    let client = ProverClient::from_env().await;
    let mut stdin = SP1Stdin::new();
    stdin.write(&input);

    println!("Executing SP1 guest...");
    let (public_values, report) = client.execute(ELF, stdin).await.expect("execution failed");
    println!(
        "Execution complete. Cycles: {}",
        report.total_instruction_count()
    );

    let output: GuestOutput = public_values.read();
    println!(
        "Guest output: padded_n={}, proof_points={}, proof_scalars={}, fixed_scalars={}",
        output.padded_n,
        output.proof_points_bytes.len(),
        output.proof_scalars.len(),
        output.fixed_scalars.len()
    );

    // Perform MSM check on host side
    println!("Verifying MSM on host...");
    let msm_ok = verify_msm(&output, &pc_gens, &bp_gens);
    if msm_ok {
        println!("MSM check PASSED! Verification successful.");
    } else {
        println!("MSM check FAILED! Verification error.");
        std::process::exit(1);
    }
}
