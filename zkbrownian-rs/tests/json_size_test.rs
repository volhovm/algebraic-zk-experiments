//! Benchmark test for serialization size and timing of Message types.
//!
//! Compares JSON vs bincode: per-message payload size and ser/deser time at different hop counts,
//! plus batch-level measurements and roundtrip correctness checks.

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
    println!("\n=== Serialization Size & Timing Benchmark (JSON vs Bincode) ===\n");

    let max_hops = 5;
    let messages = generate_messages_by_hop(max_hops);

    // --- Per-message comparison ---
    println!("--- Per-message (by hop count) ---");
    println!(
        "{:>5}  {:>12}  {:>10}  {:>10}  {:>14}  {:>12}  {:>12}  {:>8}",
        "hops",
        "JSON bytes",
        "J ser(ms)",
        "J des(ms)",
        "bincode bytes",
        "B ser(ms)",
        "B des(ms)",
        "ratio"
    );

    for msg in &messages {
        let hops = msg.hop_count();

        // JSON
        let ser_start = Instant::now();
        let json_bytes = serde_json::to_vec(msg).expect("json ser failed");
        let json_ser_ms = ser_start.elapsed().as_secs_f64() * 1000.0;

        let deser_start = Instant::now();
        let _: Message = serde_json::from_slice(&json_bytes).expect("json deser failed");
        let json_deser_ms = deser_start.elapsed().as_secs_f64() * 1000.0;

        // Bincode
        let ser_start = Instant::now();
        let bin_bytes = bincode::serialize(msg).expect("bincode ser failed");
        let bin_ser_ms = ser_start.elapsed().as_secs_f64() * 1000.0;

        let deser_start = Instant::now();
        let _: Message = bincode::deserialize(&bin_bytes).expect("bincode deser failed");
        let bin_deser_ms = deser_start.elapsed().as_secs_f64() * 1000.0;

        let ratio = json_bytes.len() as f64 / bin_bytes.len() as f64;

        println!(
            "{:>5}  {:>12}  {:>10.3}  {:>10.3}  {:>14}  {:>12.3}  {:>12.3}  {:>7.2}x",
            hops,
            json_bytes.len(),
            json_ser_ms,
            json_deser_ms,
            bin_bytes.len(),
            bin_ser_ms,
            bin_deser_ms,
            ratio,
        );
    }

    // --- Batch comparison ---
    println!("\n--- Batch serialization (Vec<Message>, max-hop) ---");
    println!(
        "{:>5}  {:>5}  {:>12}  {:>10}  {:>10}  {:>14}  {:>12}  {:>12}  {:>8}",
        "hops",
        "N",
        "JSON bytes",
        "J ser(ms)",
        "J des(ms)",
        "bincode bytes",
        "B ser(ms)",
        "B des(ms)",
        "ratio"
    );

    let max_hop_msg = messages.last().unwrap();
    for &batch_size in &[10, 30, 50] {
        let batch: Vec<Message> = (0..batch_size).map(|_| max_hop_msg.clone()).collect();

        // JSON
        let ser_start = Instant::now();
        let json_bytes = serde_json::to_vec(&batch).expect("json batch ser failed");
        let json_ser_ms = ser_start.elapsed().as_secs_f64() * 1000.0;

        let deser_start = Instant::now();
        let _: Vec<Message> = serde_json::from_slice(&json_bytes).expect("json batch deser failed");
        let json_deser_ms = deser_start.elapsed().as_secs_f64() * 1000.0;

        // Bincode
        let ser_start = Instant::now();
        let bin_bytes = bincode::serialize(&batch).expect("bincode batch ser failed");
        let bin_ser_ms = ser_start.elapsed().as_secs_f64() * 1000.0;

        let deser_start = Instant::now();
        let _: Vec<Message> = bincode::deserialize(&bin_bytes).expect("bincode batch deser failed");
        let bin_deser_ms = deser_start.elapsed().as_secs_f64() * 1000.0;

        let ratio = json_bytes.len() as f64 / bin_bytes.len() as f64;

        println!(
            "{:>5}  {:>5}  {:>12}  {:>10.3}  {:>10.3}  {:>14}  {:>12.3}  {:>12.3}  {:>7.2}x",
            max_hops,
            batch_size,
            json_bytes.len(),
            json_ser_ms,
            json_deser_ms,
            bin_bytes.len(),
            bin_ser_ms,
            bin_deser_ms,
            ratio,
        );
    }

    // --- Batch with mixed hop counts ---
    println!("\n--- Batch with mixed hop counts ---");
    println!(
        "{:>12}  {:>5}  {:>12}  {:>10}  {:>10}  {:>14}  {:>12}  {:>12}  {:>8}",
        "hop range",
        "N",
        "JSON bytes",
        "J ser(ms)",
        "J des(ms)",
        "bincode bytes",
        "B ser(ms)",
        "B des(ms)",
        "ratio"
    );

    for &batch_size in &[30, 50] {
        let batch: Vec<Message> = (0..batch_size)
            .map(|i| messages[i % messages.len()].clone())
            .collect();

        // JSON
        let ser_start = Instant::now();
        let json_bytes = serde_json::to_vec(&batch).expect("json mixed ser failed");
        let json_ser_ms = ser_start.elapsed().as_secs_f64() * 1000.0;

        let deser_start = Instant::now();
        let _: Vec<Message> = serde_json::from_slice(&json_bytes).expect("json mixed deser failed");
        let json_deser_ms = deser_start.elapsed().as_secs_f64() * 1000.0;

        // Bincode
        let ser_start = Instant::now();
        let bin_bytes = bincode::serialize(&batch).expect("bincode mixed ser failed");
        let bin_ser_ms = ser_start.elapsed().as_secs_f64() * 1000.0;

        let deser_start = Instant::now();
        let _: Vec<Message> = bincode::deserialize(&bin_bytes).expect("bincode mixed deser failed");
        let bin_deser_ms = deser_start.elapsed().as_secs_f64() * 1000.0;

        let ratio = json_bytes.len() as f64 / bin_bytes.len() as f64;

        println!(
            "{:>12}  {:>5}  {:>12}  {:>10.3}  {:>10.3}  {:>14}  {:>12.3}  {:>12.3}  {:>7.2}x",
            format!("0-{}", max_hops),
            batch_size,
            json_bytes.len(),
            json_ser_ms,
            json_deser_ms,
            bin_bytes.len(),
            bin_ser_ms,
            bin_deser_ms,
            ratio,
        );
    }

    // --- Roundtrip correctness check ---
    println!("\n--- Bincode roundtrip correctness ---");
    for msg in &messages {
        let bin_bytes = bincode::serialize(msg).expect("bincode ser failed");
        let roundtripped: Message = bincode::deserialize(&bin_bytes).expect("bincode deser failed");

        assert_eq!(
            roundtripped.hop_count(),
            msg.hop_count(),
            "hop_count mismatch after bincode roundtrip"
        );
        assert_eq!(
            roundtripped.pid, msg.pid,
            "pid mismatch after bincode roundtrip"
        );
        assert_eq!(
            roundtripped.sid, msg.sid,
            "sid mismatch after bincode roundtrip"
        );

        println!(
            "  hops={}: roundtrip OK (pid={}, sid={})",
            msg.hop_count(),
            msg.pid,
            msg.sid
        );
    }

    println!("\n=== Benchmark Complete ===");
}
