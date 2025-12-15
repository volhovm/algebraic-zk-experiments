//! End-to-end test for the Forward protocol
//!
//! This test demonstrates:
//! 1. Generating protocol state with multiple users
//! 2. Spawning an initial message
//! 3. Forwarding the message through the network using UserView
//! 4. Verifying the message

use rand::thread_rng;
use std::time::Instant;
use zkbrownian::protocol::{
    forward, generate_random_state, spawn, verify, verify_batch, BulletinBoard, BulletinBoardEntry,
    InMemoryBulletinBoard,
};
use zkbrownian::types::{PublicKey, PublicParams, WeightCommitment};
use zkbrownian::MAX_HOPS;

#[test]
fn test_basic_forward_protocol() {
    println!("=== ZK Brownian Forward Protocol - E2E Test ===\n");

    let mut rng = thread_rng();

    // Step 1: Create public parameters
    let num_nodes = 5;
    let pp = PublicParams::generate(num_nodes, 10, &mut rng).expect("Failed to generate params");

    // Step 2: Generate protocol state with multiple users
    println!("Step 1: Generating protocol state for 5 users...");
    let generated_state = generate_random_state(&pp, num_nodes, &mut rng);

    for i in 0..num_nodes {
        println!(
            "  User {} created with {} neighbors",
            i,
            generated_state.users_view[i]
                .neighbours_view
                .neighbors
                .len()
        );
    }

    let all_public_keys: Vec<PublicKey> = generated_state
        .users_view
        .iter()
        .map(|user_view| user_view.public_key.clone())
        .collect();

    println!(
        "  Protocol state merkle root: {:?}",
        generated_state.protocol_state.merkle_tree.root
    );

    // Step 2: Create bulletin board
    println!("\nStep 2: Initializing bulletin board...");
    let mut bulletin_board = InMemoryBulletinBoard::new();

    // Step 3: User 0 spawns a message
    println!("\nStep 3: User 0 spawns a message...");
    let spawner_index = 0;
    let spawner_view = &generated_state.users_view[spawner_index];
    let packet_id = 42;
    let session_id = 1000;

    let message = spawn(
        &spawner_view.secret_key,
        &spawner_view.public_key,
        packet_id,
        session_id,
        &mut rng,
    )
    .expect("Failed to spawn message");

    println!("  ✓ Message spawned successfully");
    println!("    Packet ID: {}", message.pid);
    println!("    Session ID: {}", message.sid);
    println!("    Initial hop count: {}", message.hop_count());

    // Step 4: Forward the message through the network
    println!("\nStep 4: Forwarding message through network...");
    let mut current_message = message;
    let mut current_node_index = spawner_index;

    let num_hops = MAX_HOPS.min(3);
    let start_time = Instant::now();

    for hop in 0..num_hops {
        // Forward up to 3 hops for demo
        println!("\n  Hop {}:", hop + 1);
        println!("    Current node: {}", current_node_index);

        let current_user_view = &generated_state.users_view[current_node_index];

        let (new_message, next_node_index, _diversifier) =
            forward(&pp, current_user_view, &current_message, &mut rng)
                .expect("Failed to forward message");

        println!("    ✓ Message forwarded to node {}", next_node_index);
        println!("    New hop count: {}", new_message.hop_count());

        // Post to bulletin board
        let entry = BulletinBoardEntry {
            message: new_message.clone(),
            receiver_index: next_node_index,
            addressed_to: new_message.hops.last().unwrap().ppk.clone(),
        };

        bulletin_board.post(entry).unwrap();
        println!("    ✓ Posted to bulletin board");

        current_message = new_message;
        current_node_index = next_node_index;
    }

    let elapsed = start_time.elapsed();
    println!(
        "\n  Timing: {} hops completed in {:.2} ms ({:.2} ms per forward)",
        num_hops,
        elapsed.as_secs_f64() * 1000.0,
        elapsed.as_secs_f64() * 1000.0 / num_hops as f64
    );

    // Step 5: Verify the final message
    println!("\n\nStep 5: Verifying final message...");
    let weight_commitment = WeightCommitment {
        commitment: vec![],
        metadata: vec![],
    };

    let verification_result = verify(
        &current_message,
        current_message.hop_count(),
        generated_state.protocol_state.merkle_tree.root,
        &weight_commitment,
        &all_public_keys,
        &pp,
    )
    .expect("Verification error");

    assert!(verification_result, "Message verification failed");
    println!("  ✓ Message verified successfully!");

    // Step 6: Check bulletin board
    println!("\n\nStep 6: Bulletin board summary:");
    let all_messages = bulletin_board.get_all_messages();
    println!("  Total messages posted: {}", all_messages.len());

    for (i, entry) in all_messages.iter().enumerate() {
        println!(
            "    Message {}: {} hops, addressed to node {}",
            i + 1,
            entry.message.hop_count(),
            entry.receiver_index
        );
    }

    // Step 7: Batch verify all messages on the bulletin board
    println!("\n\nStep 7: Batch verifying all bulletin board messages...");
    let messages_to_verify: Vec<_> = all_messages
        .iter()
        .map(|entry| entry.message.clone())
        .collect();

    let verification_start = Instant::now();
    let all_valid = verify_batch(
        &messages_to_verify,
        generated_state.protocol_state.merkle_tree.root,
        &weight_commitment,
        &all_public_keys,
        &pp,
    )
    .expect("Batch verification error");
    let verification_elapsed = verification_start.elapsed();

    println!(
        "  ✓ Batch verified {} messages in {:.2} ms ({:.2} ms per message)",
        messages_to_verify.len(),
        verification_elapsed.as_secs_f64() * 1000.0,
        verification_elapsed.as_secs_f64() * 1000.0 / messages_to_verify.len() as f64
    );
    println!("  All messages valid: {}", all_valid);

    assert!(all_valid, "All messages should be valid");

    println!("\n=== Test Complete ===");
}

#[test]
fn test_full_protocol() {
    println!("=== ZK Brownian Full Protocol Test ===\n");
    println!("Testing concurrent packet forwarding with multiple users\n");

    let mut rng = thread_rng();

    // Step 1: Create public parameters
    let num_nodes = 5;
    let pp = PublicParams::generate(num_nodes, 10, &mut rng).expect("Failed to generate params");

    // Step 2: Generate protocol state with multiple users
    println!(
        "Step 1: Generating protocol state for {} users...",
        num_nodes
    );
    let generated_state = generate_random_state(&pp, num_nodes, &mut rng);

    for i in 0..num_nodes {
        println!(
            "  User {} created with {} neighbors",
            i,
            generated_state.users_view[i]
                .neighbours_view
                .neighbors
                .len()
        );
    }

    // Step 3: Create bulletin board
    println!("\nStep 2: Initializing bulletin board...");
    let mut bulletin_board = InMemoryBulletinBoard::new();

    // Step 4: Each user spawns 50 packets
    const NUM_PACKETS_PER_USER: usize = 50;
    const TTL: usize = 5;

    println!(
        "\nStep 3: Each user spawning {} packets...",
        NUM_PACKETS_PER_USER
    );

    // Store initial messages for each user
    // users_packets[user_idx] contains all packets spawned by that user
    let mut users_packets: Vec<Vec<_>> = vec![Vec::new(); num_nodes];

    for (user_idx, user_view) in generated_state.users_view.iter().enumerate() {
        let session_id = 1000 + user_idx;

        for packet_id in 0..NUM_PACKETS_PER_USER {
            let message = spawn(
                &user_view.secret_key,
                &user_view.public_key,
                packet_id as u32,
                session_id as u64,
                &mut rng,
            )
            .expect("Failed to spawn message");

            users_packets[user_idx].push((message, user_idx));
        }

        println!(
            "  User {} spawned {} packets (session {})",
            user_idx, NUM_PACKETS_PER_USER, session_id
        );
    }

    // Step 5: Forward messages through TTL rounds
    println!("\nStep 4: Forwarding packets through {} TTL rounds...", TTL);

    // Prepare data for verification
    let all_public_keys: Vec<PublicKey> = generated_state
        .users_view
        .iter()
        .map(|user_view| user_view.public_key.clone())
        .collect();

    let weight_commitment = WeightCommitment {
        commitment: vec![],
        metadata: vec![],
    };

    let mut total_verifications = 0;
    let mut total_verification_time = 0.0;

    for ttl_round in 0..TTL {
        println!("\n=== TTL Round {} ===", ttl_round);

        let round_start = Instant::now();
        let mut total_forwards = 0;

        // Collect all messages to forward this round (snapshot at start of round)
        // This prevents forwarding newly arrived messages in the same round
        let mut messages_to_forward: Vec<Vec<_>> = vec![Vec::new(); num_nodes];
        for user_idx in 0..num_nodes {
            messages_to_forward[user_idx] = users_packets[user_idx].drain(..).collect();
        }

        // Process each user's packets sequentially
        for (user_idx, user_messages) in messages_to_forward.iter_mut().enumerate() {
            let messages_for_user: Vec<_> =
                user_messages.iter().map(|(msg, _)| msg.clone()).collect();

            // Step 1: User receives messages - batch verify them
            if !messages_for_user.is_empty() {
                let verify_start = Instant::now();
                let all_valid = verify_batch(
                    &messages_for_user,
                    generated_state.protocol_state.merkle_tree.root,
                    &weight_commitment,
                    &all_public_keys,
                    &pp,
                )
                .expect("Batch verification error");
                let verify_elapsed = verify_start.elapsed();

                assert!(
                    all_valid,
                    "User {} received invalid messages in round {}",
                    user_idx, ttl_round
                );

                total_verifications += messages_for_user.len();
                total_verification_time += verify_elapsed.as_secs_f64() * 1000.0;
            }

            // Step 2 & 3: User forwards the verified messages
            for (message, _origin_user) in user_messages.drain(..) {
                let current_user_view = &generated_state.users_view[user_idx];

                // Forward the message
                let (new_message, next_node_index, _diversifier) =
                    forward(&pp, current_user_view, &message, &mut rng)
                        .expect("Failed to forward message");

                // Post to bulletin board
                let entry = BulletinBoardEntry {
                    message: new_message.clone(),
                    receiver_index: next_node_index,
                    addressed_to: new_message.hops.last().unwrap().ppk.clone(),
                };

                bulletin_board.post(entry).unwrap();
                total_forwards += 1;

                // Add message to the next user's queue for the NEXT round
                users_packets[next_node_index].push((new_message, _origin_user));
            }
        }

        let round_elapsed = round_start.elapsed();
        println!(
            "  Round {} complete: {} forwards in {:.2} ms ({:.2} ms per forward)",
            ttl_round,
            total_forwards,
            round_elapsed.as_secs_f64() * 1000.0,
            if total_forwards > 0 {
                round_elapsed.as_secs_f64() * 1000.0 / total_forwards as f64
            } else {
                0.0
            }
        );
    }

    // Print verification statistics
    println!("\n=== Verification Summary ===");
    println!("  Total messages verified: {}", total_verifications);
    println!(
        "  Total verification time: {:.2} ms ({:.2} ms per message)",
        total_verification_time,
        if total_verifications > 0 {
            total_verification_time / total_verifications as f64
        } else {
            0.0
        }
    );

    // Step 6: Summary
    println!("\n=== Protocol Summary ===");
    let all_messages = bulletin_board.get_all_messages();
    println!("  Total messages on bulletin board: {}", all_messages.len());
    println!(
        "  Expected messages: {}",
        num_nodes * NUM_PACKETS_PER_USER * TTL
    );

    // Verify we have the expected number of messages
    assert_eq!(
        all_messages.len(),
        num_nodes * NUM_PACKETS_PER_USER * TTL,
        "Should have exactly one forward per packet per TTL round"
    );

    // Count messages by hop count
    let mut hop_counts = std::collections::HashMap::new();
    for entry in &all_messages {
        *hop_counts.entry(entry.message.hop_count()).or_insert(0) += 1;
    }

    println!("\n  Messages by hop count:");
    for hop in 0..=TTL {
        if let Some(count) = hop_counts.get(&hop) {
            println!("    {} hops: {} messages", hop, count);
        }
    }

    println!("\n=== Test Complete ===");
}
