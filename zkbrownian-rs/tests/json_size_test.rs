//! Benchmark test for JSON serialization size and timing of Message types.
//!
//! Measures per-message JSON payload size and ser/deser time at different hop counts,
//! plus batch-level measurements to estimate simulator HTTP/JSON overhead.

use rand::thread_rng;
use std::time::Instant;
use zkbrownian::protocol::{forward, generate_random_state, spawn};
use zkbrownian::types::Message;

/// Generate messages with hop counts from 0 up to `max_hops` by forwarding through the network.
fn generate_messages_by_hop(max_hops: usize) -> Vec<Message> {
    let mut rng = thread_rng();
    let num_nodes = 5;
    let pp =
        zkbrownian::types::PublicParams::generate(num_nodes, 10, &mut rng).expect("Failed to gen");
    let state = generate_random_state(&pp, num_nodes, &mut rng);

    let spawner = &state.users_view[0];
    let initial = spawn(&spawner.secret_key, &spawner.public_key, 42, 1000, &mut rng)
        .expect("Failed to spawn");

    let mut messages = vec![initial.clone()];
    let mut current = initial;
    let mut current_node = 0usize;

    for _ in 0..max_hops {
        let user_view = &state.users_view[current_node];
        let (new_msg, next_node) =
            forward(&pp, user_view, &current, &mut rng).expect("Failed to forward");
        messages.push(new_msg.clone());
        current = new_msg;
        current_node = next_node;
    }

    messages
}

#[test]
fn test_json_size_and_timing() {
    println!("\n=== JSON Serialization Size & Timing Benchmark ===\n");

    let max_hops = 5;
    let messages = generate_messages_by_hop(max_hops);

    println!("--- Per-message (by hop count) ---");
    println!(
        "{:>5}  {:>12}  {:>10}  {:>10}",
        "hops", "JSON bytes", "ser (ms)", "deser (ms)"
    );

    for msg in &messages {
        let hops = msg.hop_count();

        // Serialize
        let ser_start = Instant::now();
        let json_bytes = serde_json::to_vec(msg).expect("ser failed");
        let ser_ms = ser_start.elapsed().as_secs_f64() * 1000.0;

        // Deserialize
        let deser_start = Instant::now();
        let _: Message = serde_json::from_slice(&json_bytes).expect("deser failed");
        let deser_ms = deser_start.elapsed().as_secs_f64() * 1000.0;

        println!(
            "{:>5}  {:>12}  {:>10.3}  {:>10.3}",
            hops,
            json_bytes.len(),
            ser_ms,
            deser_ms
        );
    }

    // Batch measurements: simulate typical simulator batch sizes
    println!("\n--- Batch serialization (Vec<Message>) ---");
    println!(
        "{:>5}  {:>5}  {:>12}  {:>10}  {:>10}",
        "hops", "N", "JSON bytes", "ser (ms)", "deser (ms)"
    );

    // Use messages at different hop counts for batch tests
    for &batch_size in &[10, 30, 50] {
        // Use the max-hop message repeated to simulate worst case
        let max_hop_msg = messages.last().unwrap();
        let batch: Vec<Message> = (0..batch_size).map(|_| max_hop_msg.clone()).collect();

        let ser_start = Instant::now();
        let json_bytes = serde_json::to_vec(&batch).expect("batch ser failed");
        let ser_ms = ser_start.elapsed().as_secs_f64() * 1000.0;

        let deser_start = Instant::now();
        let _: Vec<Message> = serde_json::from_slice(&json_bytes).expect("batch deser failed");
        let deser_ms = deser_start.elapsed().as_secs_f64() * 1000.0;

        println!(
            "{:>5}  {:>5}  {:>12}  {:>10.3}  {:>10.3}",
            max_hops,
            batch_size,
            json_bytes.len(),
            ser_ms,
            deser_ms
        );
    }

    // Also test with mixed hop counts (more realistic)
    println!("\n--- Batch with mixed hop counts ---");
    println!(
        "{:>12}  {:>5}  {:>12}  {:>10}  {:>10}",
        "hop range", "N", "JSON bytes", "ser (ms)", "deser (ms)"
    );

    for &batch_size in &[30, 50] {
        // Cycle through all available messages
        let batch: Vec<Message> = (0..batch_size)
            .map(|i| messages[i % messages.len()].clone())
            .collect();

        let ser_start = Instant::now();
        let json_bytes = serde_json::to_vec(&batch).expect("mixed batch ser failed");
        let ser_ms = ser_start.elapsed().as_secs_f64() * 1000.0;

        let deser_start = Instant::now();
        let _: Vec<Message> =
            serde_json::from_slice(&json_bytes).expect("mixed batch deser failed");
        let deser_ms = deser_start.elapsed().as_secs_f64() * 1000.0;

        println!(
            "{:>12}  {:>5}  {:>12}  {:>10.3}  {:>10.3}",
            format!("0-{}", max_hops),
            batch_size,
            json_bytes.len(),
            ser_ms,
            deser_ms
        );
    }

    println!("\n=== Benchmark Complete ===");
}
