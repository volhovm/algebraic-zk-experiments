//! Timing test for sequential vs batch forward operations
//!
//! This test helps debug performance differences between batch MSM
//! (which is 48% faster) and batch forward (which is only 22% faster).

use rand::thread_rng;
use zkbrownian::protocol::{forward, forward_batch, generate_random_state, spawn};
use zkbrownian::types::PublicParams;

#[test]
fn test_forward_sequential_then_batch_timing() {
    let mut rng = thread_rng();

    // Create public parameters
    println!("=== Generating public parameters ===");
    let pp = PublicParams::generate(8, 8, &mut rng).expect("Failed to generate params");

    // Setup: generate protocol state with 8 users
    println!("=== Generating random state for 8 users ===");
    let generated_state = generate_random_state(&pp, 8, &mut rng);

    let batch_size = 128;
    println!("\n=== Preparing {} messages ===", batch_size);
    let inputs: Vec<_> = (0..batch_size)
        .map(|i| {
            let user_view = &generated_state.users_view[0];
            let message = spawn(
                &user_view.secret_key,
                &user_view.public_key,
                1 + i as u32,
                100,
                &mut rng,
            )
            .unwrap();
            (user_view.clone(), message)
        })
        .collect();

    // Test 1: Sequential forward (64 times)
    println!("\n=== SEQUENTIAL FORWARD ({} messages) ===", batch_size);
    let sequential_start = std::time::Instant::now();

    for (i, (user_view, message)) in inputs.iter().enumerate() {
        print!(".");
        if i % 32 == 31 {
            println!("");
        }
        let _ = forward(&pp, user_view, message, &mut rng);
    }
    print!("\n");

    let sequential_time = sequential_start.elapsed();
    println!("\n=== SEQUENTIAL TOTAL: {:?} ===", sequential_time);
    println!(
        "=== SEQUENTIAL per message: {:?} ===\n",
        sequential_time / batch_size as u32
    );

    // Test 2: Batch forward (all 64 at once)
    println!("\n=== BATCH FORWARD ({} messages) ===", batch_size);
    let batch_start = std::time::Instant::now();

    let _ = forward_batch(&pp, &inputs, &mut rng);

    let batch_time = batch_start.elapsed();
    println!("\n=== BATCH TOTAL: {:?} ===", batch_time);
    println!(
        "=== BATCH per message: {:?} ===",
        batch_time / batch_size as u32
    );

    // Print comparison
    println!("\n========================================");
    println!("COMPARISON:");
    println!(
        "  Sequential: {:?} ({:?} per msg)",
        sequential_time,
        sequential_time / batch_size as u32
    );
    println!(
        "  Batch:      {:?} ({:?} per msg)",
        batch_time,
        batch_time / batch_size as u32
    );

    let speedup = sequential_time.as_secs_f64() / batch_time.as_secs_f64();
    println!("  Speedup: {:.2}x", speedup);
    println!("========================================");
}
