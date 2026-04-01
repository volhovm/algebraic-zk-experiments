//! Core verification scalar computation.
//!
//! Reimplements `verification_scalars_and_points` and `batch_verify` from
//! zkbrownian's bulletproofs verifier, using bls12_381::Scalar.

#![allow(non_snake_case)]

use bls12_381::Scalar;
use merlin::Transcript;
use sha2::{Digest, Sha256};

use sp1_schnorr_lib::{GuestInput, GuestOutput, LookupTableData, ProofData};

use crate::direct_constraints::Lookup3Bit;
use crate::transcript::{TranscriptProtocol, T_LABELS};
use crate::types::{exp_iter, inner_product, scalar_from_bytes, scalar_inverse, scalar_to_bytes};

/// Convert LookupTableData (from host, 32-byte encoded) to Lookup3Bit<2>.
fn convert_lookup_table(table_data: &LookupTableData) -> Lookup3Bit<2> {
    let mut elems = [[Scalar::zero(); 8]; 2];
    for (dst_row, src_row) in elems.iter_mut().zip(table_data.elems.iter()) {
        for (dst, src) in dst_row.iter_mut().zip(src_row.iter()) {
            *dst = scalar_from_bytes(src);
        }
    }
    Lookup3Bit { elems }
}

/// Verification tuple: the output of processing one proof.
struct VerificationTuple {
    /// Points from the proof (as raw compressed bytes, pass-through)
    proof_dependent_points: Vec<Vec<u8>>,
    /// Scalars multiplying the proof-dependent points
    proof_dependent_scalars: Vec<Scalar>,
    /// Scalars for fixed generators: [B, B_blinding, G_0..G_{n-1}, H_0..H_{n-1}]
    proof_independent_scalars: Vec<Scalar>,
}

/// Build the constraint system for one proof (matching verify_schnorr_bridging_batch).
///
/// This replicates the exact sequence of operations:
/// 1. Create verifier
/// 2. Allocate 4 variables (c_x, c_y, c_x_tilde, c_y_tilde) for pk_star
/// 3. Call re_randomize
/// 4. Allocate 4 variables for pk_r_star
/// 5. Call re_randomize again
/// 6. Compute verification_scalars_and_points
fn process_single_proof(
    proof: &ProofData,
    tables: &[Lookup3Bit<2>],
    r_scalar: Scalar,
) -> Result<VerificationTuple, &'static str> {
    // Create transcript matching the native verifier
    let mut transcript = Transcript::new(b"SchnorrBridging");
    transcript.r1cs_domain_sep();

    // --- Compute flattened constraints via direct path ---
    println!("cycle-tracker-report-start: constraint_building");

    // Compute challenges first (we need z for the direct path).
    // But we also need the transcript to be in the right state, which
    // requires knowing n1 and the constraint system shape.
    // The direct path gives us n directly.

    // Hardcoded circuit constants: num_committed=0, ncomm=0, op_degree=2, t_poly_deg=6
    let num_committed: usize = 0;
    let op_degree: usize = 2;
    let t_poly_deg: usize = 6;
    // op_splits(2) = [(1,1), (2,0), (0,2)]; only first two used (ncomm=0)
    let op_aLaR = (1usize, 1usize);
    let op_aO = (2usize, 0usize);

    // We still need the transcript challenges, which require appending
    // proof points. But the transcript state doesn't depend on the
    // constraint system — it depends on m (num_committed) and the proof data.

    // Append m (number of committed variables)
    transcript.append_u64(b"m", num_committed as u64);

    // Append proof points to transcript
    transcript.validate_and_append_point_bytes(b"A_I1", &proof.a_i1_bytes)?;
    transcript.validate_and_append_point_bytes(b"A_O1", &proof.a_o1_bytes)?;
    transcript.validate_and_append_point_bytes(b"S1", &proof.s1_bytes)?;

    // 1-phase domain separator
    transcript.r1cs_1phase_domain_sep();

    // Append phase-2 points (identity for 1-phase, but still appended)
    transcript.append_point_bytes(b"A_I2", &proof.a_i2_bytes);
    transcript.append_point_bytes(b"A_O2", &proof.a_o2_bytes);
    transcript.append_point_bytes(b"S2", &proof.s2_bytes);

    // Challenge: y, z
    let y = transcript.challenge_scalar(b"y");
    let z = transcript.challenge_scalar(b"z");

    // Append T commitment points (skip T[op_degree])
    for (d, (label, t_bytes)) in T_LABELS
        .iter()
        .zip(proof.t_points_bytes.iter())
        .enumerate()
        .take(t_poly_deg + 1)
    {
        if d == op_degree {
            continue;
        }
        transcript.validate_and_append_point_bytes(label, t_bytes)?;
    }

    // Challenge: u, x
    let u = transcript.challenge_scalar(b"u");
    let x = transcript.challenge_scalar(b"x");

    let r = r_scalar;

    // Precompute x powers
    let mut xs = vec![Scalar::zero(); t_poly_deg + 1];
    let mut rxs = vec![Scalar::zero(); t_poly_deg + 1];
    xs[0] = Scalar::one();
    rxs[0] = r;
    for i in 1..xs.len() {
        xs[i] = xs[i - 1] * x;
        rxs[i] = rxs[i - 1] * x;
    }

    // Append scalars to transcript
    let t_x = scalar_from_bytes(&proof.t_x);
    let t_x_blinding = scalar_from_bytes(&proof.t_x_blinding);
    let e_blinding = scalar_from_bytes(&proof.e_blinding);

    transcript.append_scalar(b"t_x", &t_x);
    transcript.append_scalar(b"t_x_blinding", &t_x_blinding);
    transcript.append_scalar(b"e_blinding", &e_blinding);

    // Challenge: w
    let w = transcript.challenge_scalar(b"w");

    // --- Direct constraints path ---
    println!("cycle-tracker-report-start: direct_constraints");
    let (wL, wR, wO, wc, n) = crate::direct_constraints::compute_flattened_direct(&z, tables);
    println!("cycle-tracker-report-end: direct_constraints");

    println!("cycle-tracker-report-end: constraint_building");

    // Deserialize l_vec and r_vec
    println!("cycle-tracker-report-start: deserialize_lr");
    let l_vec: Vec<Scalar> = proof.l_vec.iter().map(scalar_from_bytes).collect();
    let r_vec: Vec<Scalar> = proof.r_vec.iter().map(scalar_from_bytes).collect();
    println!("cycle-tracker-report-end: deserialize_lr");

    if l_vec.len() != n || r_vec.len() != n {
        return Err("l_vec/r_vec length mismatch");
    }

    // Inner product
    println!("cycle-tracker-report-start: inner_products");
    let ab = inner_product(&l_vec, &r_vec);

    // y-inverse powers
    let y_inv = scalar_inverse(&y);
    let y_inv_vec: Vec<Scalar> = exp_iter(y_inv).take(n).collect();

    // yneg_wR = wR[i] * y_inv_vec[i]
    let yneg_wR: Vec<Scalar> = wR
        .into_iter()
        .zip(y_inv_vec.iter())
        .map(|(wRi, yinv)| wRi * yinv)
        .collect();

    // delta = <yneg_wR[0..n], wL>
    // For direct path, num_vars == n (since we sized it directly)
    let delta = inner_product(&yneg_wR[0..n], &wL);
    println!("cycle-tracker-report-end: inner_products");

    println!("cycle-tracker-report-start: vector_scalars");
    // n2 = 0 for this 1-phase circuit, so u_for_g/h is always Scalar::one().
    // We skip the allocation and multiplication entirely.

    let xwR = xs[op_aLaR.0];

    // g_scalars[i] = xwR * yneg_wR[i] - l_vec[i]
    let g_scalars: Vec<Scalar> = yneg_wR
        .iter()
        .zip(l_vec.iter())
        .map(|(yneg_wRi, l_i)| xwR * yneg_wRi - l_i)
        .collect();

    // h_scalars[i] = y_inv[i] * (xs[op_aLaR.1]*wL[i] + xs[op_aO.1]*wO[i] - r[i]) - 1
    let h_scalars: Vec<Scalar> = wL
        .into_iter()
        .zip(wO.into_iter())
        .zip(y_inv_vec.into_iter())
        .zip(r_vec.iter())
        .map(|(((wLi, wOi), y_inv_i), r_i)| {
            let comb = xs[op_aLaR.1] * wLi + xs[op_aO.1] * wOi;
            y_inv_i * (comb - r_i) - Scalar::one()
        })
        .collect();
    println!("cycle-tracker-report-end: vector_scalars");

    println!("cycle-tracker-report-start: build_output");
    let xI = xs[op_aLaR.0];
    let xO = xs[op_aO.0];
    let xS = xs[op_degree + 1];

    // Build proof_dependent points (as raw bytes)
    // ncomm=0 for this circuit, so no vcomm points.
    let mut proof_points = vec![
        proof.a_i1_bytes.clone(), // A_I1
        proof.a_o1_bytes.clone(), // A_O1
        proof.s1_bytes.clone(),   // S1
        proof.a_i2_bytes.clone(), // A_I2
        proof.a_o2_bytes.clone(), // A_O2
        proof.s2_bytes.clone(),   // S2
    ];

    // Build proof_dependent scalars
    let mut proof_scalars = vec![
        xI,     // A_I1
        xO,     // A_O1
        xS,     // S1
        xI * u, // A_I2
        xO * u, // A_O2
        xS * u, // S2
    ];

    // Append T points and scalars directly (skip T[op_degree])
    for (d, (t_bytes, rx)) in proof
        .t_points_bytes
        .iter()
        .zip(rxs.iter())
        .enumerate()
        .take(t_poly_deg + 1)
    {
        if d == op_degree {
            continue;
        }
        proof_points.push(t_bytes.clone());
        proof_scalars.push(*rx);
    }

    // Build proof_independent (fixed) scalars
    let B_scalar = w * (t_x - ab) + r * (xs[op_degree] * (wc + delta) - t_x);
    let B_blinding_scalar = -e_blinding - r * t_x_blinding;

    let mut fixed_scalars = Vec::with_capacity(2 + n + n);
    fixed_scalars.push(B_scalar);
    fixed_scalars.push(B_blinding_scalar);
    fixed_scalars.extend(g_scalars);
    fixed_scalars.extend(h_scalars);

    println!("cycle-tracker-report-end: build_output");

    Ok(VerificationTuple {
        proof_dependent_points: proof_points,
        proof_dependent_scalars: proof_scalars,
        proof_independent_scalars: fixed_scalars,
    })
}

/// Compute the full batch verification output.
pub fn compute_batch_verification(input: &GuestInput) -> GuestOutput {
    assert_eq!(input.proofs.len(), input.num_proofs as usize);
    assert_eq!(input.instances.len(), input.num_proofs as usize);

    if input.num_proofs == 0 {
        return GuestOutput {
            output_hash: [0u8; 32],
            padded_n: 0,
        };
    }

    // Convert lookup tables
    println!("cycle-tracker-report-start: convert_tables");
    let tables: Vec<Lookup3Bit<2>> = input
        .lookup_tables
        .iter()
        .map(convert_lookup_table)
        .collect();
    println!("cycle-tracker-report-end: convert_tables");

    // Process all proofs
    println!("cycle-tracker-report-start: process_proofs");
    let mut verification_tuples = Vec::with_capacity(input.num_proofs as usize);
    for i in 0..input.num_proofs as usize {
        let r_scalar = scalar_from_bytes(&input.r_scalars[i]);
        let vt = process_single_proof(&input.proofs[i], &tables, r_scalar)
            .expect("Failed to process proof");
        verification_tuples.push(vt);
    }
    println!("cycle-tracker-report-end: process_proofs");

    println!("cycle-tracker-report-start: batch_combine");
    // Batch combine: first tuple is unscaled, remaining are scaled by random scalar
    let mut vt_iter = verification_tuples.into_iter();
    let first = vt_iter.next().unwrap();
    let mut all_proof_points = first.proof_dependent_points;
    let mut all_proof_scalars = first.proof_dependent_scalars;
    let mut fixed_scalars = first.proof_independent_scalars;
    let padded_n = ((fixed_scalars.len() - 2) / 2) as u32;

    for (idx, vt) in vt_iter.enumerate() {
        let random_scalar = scalar_from_bytes(&input.batch_random_scalars[idx]);

        // Append proof points (unscaled -- they're just points)
        all_proof_points.extend(vt.proof_dependent_points);

        // Scale and append proof scalars
        all_proof_scalars.extend(
            vt.proof_dependent_scalars
                .into_iter()
                .map(|s| s * random_scalar),
        );

        // Accumulate fixed scalars
        assert_eq!(fixed_scalars.len(), vt.proof_independent_scalars.len());
        for (acc, s) in fixed_scalars
            .iter_mut()
            .zip(vt.proof_independent_scalars.into_iter())
        {
            *acc += s * random_scalar;
        }
    }
    println!("cycle-tracker-report-end: batch_combine");

    // Hash the output instead of committing all scalars
    println!("cycle-tracker-report-start: hash_output");
    let mut hasher = Sha256::new();
    for point_bytes in &all_proof_points {
        hasher.update(point_bytes);
    }
    for scalar in &all_proof_scalars {
        hasher.update(scalar_to_bytes(scalar));
    }
    for scalar in &fixed_scalars {
        hasher.update(scalar_to_bytes(scalar));
    }
    hasher.update(padded_n.to_le_bytes());
    let output_hash: [u8; 32] = hasher.finalize().into();
    println!("cycle-tracker-report-end: hash_output");

    GuestOutput {
        output_hash,
        padded_n,
    }
}
