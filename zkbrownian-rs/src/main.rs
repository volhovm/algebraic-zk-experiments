//! ZK Brownian Forward Protocol - Main binary
//!
//! Command-line interface for running the protocol

use zkbrownian::crypto::curve_ops::keygen;
use zkbrownian::protocol::{spawn, forward, WeightMatrix};
use zkbrownian::WEIGHT_SUM;
use rand::thread_rng;

fn main() {
    println!("ZK Brownian Forward Protocol");
    println!("=============================\n");

    let mut rng = thread_rng();

    // Simple demo
    println!("Generating keypair...");
    let (sk, pk) = keygen(&mut rng);
    println!("✓ Keypair generated\n");

    println!("Spawning message...");
    match spawn(&sk, &pk, 1, 100, &mut rng) {
        Ok(msg) => {
            println!("✓ Message spawned");
            println!("  Packet ID: {}", msg.pid);
            println!("  Session ID: {}", msg.sid);
            println!("  Hop count: {}", msg.hop_count());
        }
        Err(e) => {
            eprintln!("✗ Failed to spawn: {:?}", e);
        }
    }

    println!("\nFor full demo, run: cargo run --example basic_forward");
}
