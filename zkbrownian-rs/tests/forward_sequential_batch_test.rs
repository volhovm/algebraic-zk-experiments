//! Timing test for sequential vs batch forward operations
//!
//! This test helps debug performance differences between batch MSM
//! (which is 48% faster) and batch forward (which is only 22% faster).

use rand::{thread_rng, SeedableRng};
use zkbrownian::protocol::{forward, forward_batch, generate_random_state, spawn, verify_batch};
use zkbrownian::types::{PublicKey, PublicParams, WeightCommitment};

#[test]
fn test_forward_sequential_then_batch_timing() {
    let mut rng = thread_rng();

    // Create public parameters
    println!("=== Generating public parameters ===");
    let pp = PublicParams::generate(8, 8, &mut rng).expect("Failed to generate params");

    // Setup: generate protocol state with 8 users
    println!("=== Generating random state for 8 users ===");
    let generated_state = generate_random_state(&pp, 8, &mut rng);

    for batch_size in [32, 64, 128] {
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
                println!();
            }
            let _ = forward(&pp, user_view, message, &mut rng);
        }
        println!();

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
}

#[test]
fn test_forward_sequential_vs_batch_correctness() {
    println!("=== Testing Sequential vs Batch Forward Correctness ===\n");

    let mut rng = thread_rng();

    // Create public parameters
    println!("=== Generating public parameters ===");
    let pp = PublicParams::generate(8, 8, &mut rng).expect("Failed to generate params");

    // Setup: generate protocol state with 8 users
    println!("=== Generating random state for 8 users ===");
    let generated_state = generate_random_state(&pp, 8, &mut rng);

    const BATCH_SIZE: usize = 64;
    println!("\n=== Testing with batch size: {} ===", BATCH_SIZE);

    // Create inputs - spawn messages from user 0
    let inputs: Vec<_> = (0..BATCH_SIZE)
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

    // Test 1: Sequential forward with deterministic RNG - 3 hops
    println!("\n=== Running SEQUENTIAL forward (3 hops) ===");
    let mut sequential_rng = rand::rngs::StdRng::seed_from_u64(42);
    let mut sequential_results: Vec<(_, usize, _)> = Vec::new();

    // Hop 1
    println!("  Hop 1...");
    for (user_view, message) in inputs.iter() {
        let (new_message, next_node_index, diversifier) =
            forward(&pp, user_view, message, &mut sequential_rng)
                .expect("Sequential forward hop 1 failed");
        sequential_results.push((new_message, next_node_index, diversifier));
    }

    // Hop 2
    println!("  Hop 2...");
    let mut hop2_results = Vec::new();
    for (message, current_holder, _diversifier) in sequential_results.iter() {
        let current_user_view = &generated_state.users_view[*current_holder];
        let (new_message, next_node_index, diversifier) =
            forward(&pp, current_user_view, message, &mut sequential_rng)
                .expect("Sequential forward hop 2 failed");
        hop2_results.push((new_message, next_node_index, diversifier));
    }
    sequential_results = hop2_results;

    // Hop 3
    println!("  Hop 3...");
    let mut hop3_results = Vec::new();
    for (message, current_holder, _diversifier) in sequential_results.iter() {
        let current_user_view = &generated_state.users_view[*current_holder];
        let (new_message, next_node_index, diversifier) =
            forward(&pp, current_user_view, message, &mut sequential_rng)
                .expect("Sequential forward hop 3 failed");
        hop3_results.push((new_message, next_node_index, diversifier));
    }
    sequential_results = hop3_results;

    println!(
        "  ✓ Sequential forward completed: {} messages after 3 hops",
        sequential_results.len()
    );

    // Test 2: Batch forward with same deterministic RNG seed - 3 hops
    println!("\n=== Running BATCH forward (3 hops) ===");
    let mut batch_rng = rand::rngs::StdRng::seed_from_u64(42);
    let mut batch_results: Vec<(_, usize, _)>;

    // Hop 1
    println!("  Hop 1...");
    batch_results =
        forward_batch(&pp, &inputs, &mut batch_rng).expect("Batch forward hop 1 failed");

    // Hop 2
    println!("  Hop 2...");
    let batch_inputs_hop2: Vec<_> = batch_results
        .iter()
        .map(|(msg, holder, _div)| (generated_state.users_view[*holder].clone(), msg.clone()))
        .collect();
    batch_results =
        forward_batch(&pp, &batch_inputs_hop2, &mut batch_rng).expect("Batch forward hop 2 failed");

    // Hop 3
    println!("  Hop 3...");
    let batch_inputs_hop3: Vec<_> = batch_results
        .iter()
        .map(|(msg, holder, _div)| (generated_state.users_view[*holder].clone(), msg.clone()))
        .collect();
    batch_results =
        forward_batch(&pp, &batch_inputs_hop3, &mut batch_rng).expect("Batch forward hop 3 failed");

    println!(
        "  ✓ Batch forward completed: {} messages after 3 hops",
        batch_results.len()
    );

    // Test 3: Compare results after 3 hops
    println!("\n=== Comparing results after 3 hops ===");
    assert_eq!(
        sequential_results.len(),
        batch_results.len(),
        "Result counts should match"
    );

    // Verify all messages have 3 hops
    for (i, ((seq_msg, _, _), (batch_msg, _, _))) in sequential_results
        .iter()
        .zip(batch_results.iter())
        .enumerate()
    {
        assert_eq!(
            seq_msg.hop_count(),
            3,
            "Sequential message {} should have 3 hops",
            i
        );
        assert_eq!(
            batch_msg.hop_count(),
            3,
            "Batch message {} should have 3 hops",
            i
        );
    }

    // Compare receiver indices distribution
    let mut sequential_receivers = vec![0; 8];
    let mut batch_receivers = vec![0; 8];

    for (i, ((seq_msg, seq_next, seq_div), (batch_msg, batch_next, batch_div))) in
        sequential_results
            .iter()
            .zip(batch_results.iter())
            .enumerate()
    {
        // Check that receiver indices match
        assert_eq!(
            seq_next, batch_next,
            "Message {}: receiver index mismatch (sequential={}, batch={})",
            i, seq_next, batch_next
        );

        // Check that diversifiers match
        assert_eq!(
            seq_div.d, batch_div.d,
            "Message {}: diversifier mismatch",
            i
        );

        // Check that the forwarded messages have the same structure
        assert_eq!(
            seq_msg.hop_count(),
            batch_msg.hop_count(),
            "Message {}: hop count mismatch",
            i
        );

        assert_eq!(
            seq_msg.pid, batch_msg.pid,
            "Message {}: packet ID mismatch",
            i
        );

        assert_eq!(
            seq_msg.sid, batch_msg.sid,
            "Message {}: session ID mismatch",
            i
        );

        // Check that the last hop's ppk matches
        let seq_ppk = seq_msg.latest_ppk().expect("No ppk in sequential message");
        let batch_ppk = batch_msg.latest_ppk().expect("No ppk in batch message");
        assert_eq!(
            seq_ppk.ppk_1, batch_ppk.ppk_1,
            "Message {}: ppk_1 mismatch",
            i
        );
        assert_eq!(
            seq_ppk.ppk_2, batch_ppk.ppk_2,
            "Message {}: ppk_2 mismatch",
            i
        );

        // Collect receiver distribution
        sequential_receivers[*seq_next] += 1;
        batch_receivers[*batch_next] += 1;
    }

    println!("  ✓ All {} messages match exactly!", BATCH_SIZE);

    // Print receiver distribution
    println!("\n=== Receiver Distribution ===");
    println!("Sequential: {:?}", sequential_receivers);
    println!("Batch:      {:?}", batch_receivers);
    assert_eq!(
        sequential_receivers, batch_receivers,
        "Receiver distributions should match"
    );

    // Test 4: Verify all messages
    println!("\n=== Verifying messages ===");

    let all_public_keys: Vec<PublicKey> = generated_state
        .users_view
        .iter()
        .map(|user_view| user_view.public_key.clone())
        .collect();

    let weight_commitment = WeightCommitment {
        commitment: vec![],
        metadata: vec![],
    };

    // Verify sequential messages
    println!("  Verifying {} sequential messages...", BATCH_SIZE);
    let sequential_msgs: Vec<_> = sequential_results
        .iter()
        .map(|(msg, _, _)| msg.clone())
        .collect();
    let seq_valid = verify_batch(
        &sequential_msgs,
        generated_state.protocol_state.merkle_tree.root,
        &weight_commitment,
        &all_public_keys,
        &pp,
    )
    .expect("Sequential verification error");
    assert!(seq_valid, "Sequential messages should verify");
    println!("  ✓ Sequential messages verified successfully!");

    // Verify batch messages - one by one to find the failure
    println!("  Verifying {} batch messages one by one...", BATCH_SIZE);
    for (i, (msg, _, _)) in batch_results.iter().enumerate() {
        let result = verify_batch(
            std::slice::from_ref(msg),
            generated_state.protocol_state.merkle_tree.root,
            &weight_commitment,
            &all_public_keys,
            &pp,
        );
        match result {
            Ok(valid) => {
                if !valid {
                    panic!(
                        "Batch message {} failed verification (returned false), hop_count={}",
                        i,
                        msg.hop_count()
                    );
                }
            }
            Err(e) => {
                panic!(
                    "Batch message {} failed verification with error: {:?}, hop_count={}",
                    i,
                    e,
                    msg.hop_count()
                );
            }
        }
    }
    println!("  ✓ All batch messages verified successfully!");

    println!("\n=== Test Passed: Sequential and Batch produce identical results after 3 hops ===");
}
