//! Core verification scalar computation.
//!
//! Reimplements `verification_scalars_and_points` and `batch_verify` from
//! zkbrownian's bulletproofs verifier, using bls12_381::Scalar.

#![allow(non_snake_case)]

use bls12_381::Scalar;
use merlin::Transcript;

use sp1_schnorr_lib::{GuestInput, GuestOutput, LookupTableData, ProofData};

use crate::constraint_system::VerifierCS;
use crate::relations::lookup::Lookup3Bit;
use crate::relations::rerandomize::re_randomize;
use crate::transcript::{TranscriptProtocol, T_LABELS};
use crate::types::{exp_iter, inner_product, scalar_from_bytes, scalar_inverse, scalar_to_bytes};

/// Compute op_splits, matching zkbrownian's r1cs::op_splits.
fn op_splits(op_deg: usize) -> Vec<(usize, usize)> {
    debug_assert_eq!(op_deg % 2, 0);
    let mid = op_deg / 2;
    let mut splits = Vec::with_capacity(op_deg);
    splits.push((mid, mid));
    splits.push((op_deg, 0));
    for r_deg in 1..op_deg + 1 {
        if r_deg == mid {
            continue;
        }
        let l_deg = op_deg - r_deg;
        splits.push((l_deg, r_deg));
    }
    splits
}

/// Convert LookupTableData (from host, 32-byte encoded) to Lookup3Bit<2>.
fn convert_lookup_table(table_data: &LookupTableData) -> Lookup3Bit<2> {
    let mut elems = [[Scalar::zero(); 8]; 2];
    for (row, (dst_row, src_row)) in elems.iter_mut().zip(table_data.elems.iter()).enumerate() {
        let _ = row;
        for (dst, src) in dst_row.iter_mut().zip(src_row.iter()) {
            let bytes: [u8; 32] = src
                .as_slice()
                .try_into()
                .expect("Table element must be 32 bytes");
            *dst = scalar_from_bytes(&bytes);
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

    println!("cycle-tracker-report-start: constraint_building");
    let mut cs = VerifierCS::new();

    // First re_randomize: pk_star
    // All variables use allocate() (not allocate_committed), matching the native verifier.
    // The instance values (pk_star_blinded.x/y) are NOT encoded as committed variables;
    // they flow through the Fiat-Shamir transcript instead.
    let c_x_var = cs.allocate();
    let c_y_var = cs.allocate();
    let c_x_tilde_var = cs.allocate();
    let c_y_tilde_var = cs.allocate();

    re_randomize(
        &mut cs,
        tables,
        c_x_var.into(),
        c_y_var.into(),
        c_x_tilde_var.into(),
        c_y_tilde_var.into(),
    );

    // Second re_randomize: pk_r_star
    let c_r_x_var = cs.allocate();
    let c_r_y_var = cs.allocate();
    let c_r_x_tilde_var = cs.allocate();
    let c_r_y_tilde_var = cs.allocate();

    re_randomize(
        &mut cs,
        tables,
        c_r_x_var.into(),
        c_r_y_var.into(),
        c_r_x_tilde_var.into(),
        c_r_y_tilde_var.into(),
    );

    // Now compute verification_scalars_and_points
    // This mirrors verifier.rs:467-714

    // Pad to match the native verifier
    while cs.size() > cs.num_vars {
        cs.allocate_multiplier();
    }
    println!("cycle-tracker-report-end: constraint_building");

    let n1 = cs.size();

    println!("cycle-tracker-report-start: transcript_challenges");
    // Append m (number of committed variables)
    transcript.append_u64(b"m", cs.num_committed as u64);

    let ncomm = cs.vec_comms.len(); // 0 for this circuit
    let op_degree = 2 + 2 * (ncomm / 2);
    let t_poly_deg = 2 * (op_degree + 1);
    let ops = op_splits(op_degree);
    let op_aLaR = ops[0];
    let op_aO = ops[1];
    let op_vec = &ops[2..];

    // Append proof points to transcript
    transcript.validate_and_append_point_bytes(b"A_I1", &proof.a_i1_bytes)?;
    transcript.validate_and_append_point_bytes(b"A_O1", &proof.a_o1_bytes)?;
    transcript.validate_and_append_point_bytes(b"S1", &proof.s1_bytes)?;

    // Process randomized constraints (verifier side: 2-phase or 1-phase)
    // re_randomize doesn't use specify_randomized_constraints, so always 1-phase
    cs.clear_pending();
    transcript.r1cs_1phase_domain_sep();

    let n = cs.size();
    let n2 = n - n1;

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
    println!("cycle-tracker-report-end: transcript_challenges");

    // Flatten constraints at z
    println!("cycle-tracker-report-start: flattened_constraints");
    let (wL, wR, wO, _wV, wVCs, wc) = cs.flattened_constraints(&z);
    println!("cycle-tracker-report-end: flattened_constraints");

    // Deserialize l_vec and r_vec
    let l_vec: Vec<Scalar> = proof.l_vec.iter().map(scalar_from_bytes).collect();
    let r_vec: Vec<Scalar> = proof.r_vec.iter().map(scalar_from_bytes).collect();

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

    // delta = <yneg_wR[0..num_vars], wL>
    let delta = inner_product(&yneg_wR[0..cs.num_vars], &wL);
    println!("cycle-tracker-report-end: inner_products");

    println!("cycle-tracker-report-start: vector_scalars");
    // u_for_g: [1, 1, ..., 1 (n1 times), u, u, ..., u (n2 times)]
    let u_for_g: Vec<Scalar> = std::iter::repeat_n(Scalar::one(), n1)
        .chain(std::iter::repeat_n(u, n2))
        .collect();

    let xwR = xs[op_aLaR.0];

    // g_scalars[i] = u_or_1 * (xwR * yneg_wR[i] - l_vec[i])
    let g_scalars: Vec<Scalar> = yneg_wR
        .iter()
        .zip(u_for_g.iter())
        .zip(l_vec.iter())
        .map(|((yneg_wRi, u_or_1), l_i)| *u_or_1 * (xwR * yneg_wRi - l_i))
        .collect();

    // h_scalars
    let mut h_scalars = Vec::with_capacity(n);
    {
        let mut wL_iter = wL.into_iter();
        let mut wO_iter = wO.into_iter();
        let mut y_inv_iter = y_inv_vec.into_iter();
        let mut u_for_h = u_for_g.into_iter();

        for (i, r_i) in r_vec.iter().enumerate().take(n) {
            let y_inv_i = y_inv_iter.next().unwrap();
            let u_or_1 = u_for_h.next().unwrap();

            let wLi = if i < cs.num_vars {
                wL_iter.next().unwrap_or(Scalar::zero())
            } else {
                Scalar::zero()
            };
            let wOi = if i < cs.num_vars {
                wO_iter.next().unwrap_or(Scalar::zero())
            } else {
                Scalar::zero()
            };

            // Compute right polynomial combination
            let mut comb = Scalar::zero();
            comb += xs[op_aLaR.1] * wLi;
            comb += xs[op_aO.1] * wOi;

            for j in 0..wVCs.len() {
                let wVCji = wVCs[j].get(i).copied().unwrap_or(Scalar::zero());
                comb += xs[op_vec[j].1] * wVCji;
            }

            let res = u_or_1 * (y_inv_i * (comb - r_i) - Scalar::one());
            h_scalars.push(res);
        }
    }
    println!("cycle-tracker-report-end: vector_scalars");

    println!("cycle-tracker-report-start: build_output");
    // T points and scalars (skip T[op_degree])
    let mut T_points_bytes: Vec<Vec<u8>> = Vec::new();
    let mut T_scalars: Vec<Scalar> = Vec::new();
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
        T_points_bytes.push(t_bytes.clone());
        T_scalars.push(*rx);
    }

    let xI = xs[op_aLaR.0];
    let xO = xs[op_aO.0];
    let xS = xs[op_degree + 1];

    // Build proof_dependent points (as raw bytes)
    // ncomm=0 for this circuit, so no vcomm points.
    // V is empty (allocate() returns MultiplierLeft/Right, not Committed).
    let mut proof_points = vec![
        proof.a_i1_bytes.clone(), // A_I1
        proof.a_o1_bytes.clone(), // A_O1
        proof.s1_bytes.clone(),   // S1
        proof.a_i2_bytes.clone(), // A_I2
        proof.a_o2_bytes.clone(), // A_O2
        proof.s2_bytes.clone(),   // S2
    ];
    proof_points.extend(T_points_bytes);

    // Build proof_dependent scalars
    let mut proof_scalars = vec![
        xI,     // A_I1
        xO,     // A_O1
        xS,     // S1
        xI * u, // A_I2
        xO * u, // A_O2
        xS * u, // S2
    ];
    proof_scalars.extend(T_scalars);

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
            proof_points_bytes: vec![],
            proof_scalars: vec![],
            fixed_scalars: vec![],
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

        // Append proof points (unscaled — they're just points)
        all_proof_points.extend(vt.proof_dependent_points);

        // Scale and append proof scalars
        let scaled_proof_scalars: Vec<Scalar> = vt
            .proof_dependent_scalars
            .into_iter()
            .map(|s| s * random_scalar)
            .collect();
        all_proof_scalars.extend(scaled_proof_scalars);

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

    println!("cycle-tracker-report-start: serialize_output");
    // Convert to output format
    let output = GuestOutput {
        proof_points_bytes: all_proof_points,
        proof_scalars: all_proof_scalars.iter().map(scalar_to_bytes).collect(),
        fixed_scalars: fixed_scalars.iter().map(scalar_to_bytes).collect(),
        padded_n,
    };
    println!("cycle-tracker-report-end: serialize_output");
    output
}
