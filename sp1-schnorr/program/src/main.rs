//! SP1 guest program for Schnorr bridging batch verification.
//!
//! This program recomputes all the scalar arithmetic from
//! `verify_schnorr_bridging_batch` inside the zkVM. The host then
//! performs the final MSM check using the output scalars.

#![no_main]
sp1_zkvm::entrypoint!(main);

mod constraint_system;
mod relations;
mod transcript;
mod types;
mod verification;

use sp1_schnorr_lib::GuestInput;

pub fn main() {
    println!("cycle-tracker-report-start: total");

    println!("cycle-tracker-report-start: deserialize_input");
    let input: GuestInput = sp1_zkvm::io::read();
    println!("cycle-tracker-report-end: deserialize_input");

    println!("cycle-tracker-report-start: compute_batch_verification");
    let output = verification::compute_batch_verification(&input);
    println!("cycle-tracker-report-end: compute_batch_verification");

    println!("cycle-tracker-report-start: commit_output");
    sp1_zkvm::io::commit(&output);
    println!("cycle-tracker-report-end: commit_output");

    println!("cycle-tracker-report-end: total");
}
