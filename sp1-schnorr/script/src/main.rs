//! CLI host driver for SP1 Schnorr batch verification.

use sp1_sdk::prelude::*;
use sp1_sdk::ProverClient;

use sp1_schnorr_script::*;

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

    println!("Verifying natively...");
    verify_natively(&r1cs_proofs, &instances, &pc_gens, &bp_gens, &g3_tables);
    println!("Native verification passed.");

    let (input, r_scalars, batch_random_scalars) =
        prepare_guest_input(&r1cs_proofs, &instances, &g3_tables, num_proofs);
    println!("Serialized GuestInput: {} proofs", input.num_proofs);

    let client = ProverClient::from_env().await;
    let mut stdin = SP1Stdin::new();
    stdin.write(&input);

    println!("Executing SP1 guest...");
    let (mut public_values, report) = client.execute(ELF, stdin).await.expect("execution failed");
    println!(
        "Execution complete. Cycles: {}",
        report.total_instruction_count()
    );

    let output: GuestOutput = public_values.read();
    println!(
        "Guest output: padded_n={}, hash={:?}",
        output.padded_n,
        &output.output_hash[..8]
    );

    println!("Verifying hash+MSM on host...");
    let ok = verify_output_hash_and_msm(
        &output,
        &r1cs_proofs,
        &instances,
        &g3_tables,
        &r_scalars,
        &batch_random_scalars,
        &pc_gens,
        &bp_gens,
    );
    if ok {
        println!("Hash+MSM check PASSED! Verification successful.");
    } else {
        println!("Hash+MSM check FAILED! Verification error.");
        std::process::exit(1);
    }
}
