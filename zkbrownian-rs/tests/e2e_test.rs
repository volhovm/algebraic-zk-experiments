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
    forward, forward_batch, generate_random_state, spawn, verify, verify_batch, BulletinBoard,
    BulletinBoardEntry, InMemoryBulletinBoard,
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

    let num_hops = MAX_HOPS.min(30);
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

    // Calculate total number of Schnorr signatures (hops)
    let total_schnorr_sigs: usize = messages_to_verify.iter().map(|msg| msg.hop_count()).sum();

    println!(
        "  ✓ Batch verified {} messages ({} total Schnorr signatures) in {:.2} ms ({:.2} ms per Schnorr)",
        messages_to_verify.len(),
        total_schnorr_sigs,
        verification_elapsed.as_secs_f64() * 1000.0,
        verification_elapsed.as_secs_f64() * 1000.0 / total_schnorr_sigs as f64
    );
    println!("  All messages valid: {}", all_valid);

    assert!(all_valid, "All messages should be valid");

    println!("\n=== Test Complete ===");
}

#[test]
fn test_full_protocol_regular() {
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

    // Step 4: Each user spawns 10 packets
    const NUM_PACKETS_PER_USER: usize = 10;
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

            // Step 2 & 3: User forwards the verified messages using batches
            const BATCH_SIZE: usize = 64;
            let current_user_view = &generated_state.users_view[user_idx];

            // Process messages in batches of 64
            let mut messages_vec = std::mem::take(user_messages);
            for batch_chunk in messages_vec.chunks_mut(BATCH_SIZE) {
                // Prepare batch inputs: (user_view, message) tuples
                let batch_inputs: Vec<_> = batch_chunk
                    .iter()
                    .map(|(msg, _origin)| (current_user_view.clone(), msg.clone()))
                    .collect();

                // Forward all messages in this batch at once
                let batch_results = forward_batch(&pp, &batch_inputs, &mut rng)
                    .expect("Failed to batch forward messages");

                // Process results: post to bulletin board and queue for next round
                for (i, (new_message, next_node_index, _diversifier)) in
                    batch_results.into_iter().enumerate()
                {
                    let (_msg, origin_user) = &batch_chunk[i];

                    // Post to bulletin board
                    let entry = BulletinBoardEntry {
                        message: new_message.clone(),
                        receiver_index: next_node_index,
                        addressed_to: new_message.hops.last().unwrap().ppk.clone(),
                    };

                    bulletin_board.post(entry).unwrap();
                    total_forwards += 1;

                    // Add message to the next user's queue for the NEXT round
                    users_packets[next_node_index].push((new_message, *origin_user));
                }
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

    // Step 6: Summary
    println!("\n=== Protocol Summary ===");
    let all_messages = bulletin_board.get_all_messages();

    // Calculate total number of Schnorr signatures across all verified messages
    let total_schnorr_sigs: usize = all_messages
        .iter()
        .map(|entry| entry.message.hop_count())
        .sum();

    // Print verification statistics
    println!("\n=== Verification Summary ===");
    println!("  Total messages verified: {}", total_verifications);
    println!(
        "  Total verification time: {:.2} ms ({:.2} ms per message, {:.2} ms per Schnorr)",
        total_verification_time,
        if total_verifications > 0 {
            total_verification_time / total_verifications as f64
        } else {
            0.0
        },
        if total_schnorr_sigs > 0 {
            total_verification_time / total_schnorr_sigs as f64
        } else {
            0.0
        }
    );
    println!(
        "  Total Schnorr signatures verified: {}",
        total_schnorr_sigs
    );
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

#[test]
fn test_full_protocol_concurrent() {
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    println!("=== ZK Brownian Full Protocol Test CONCURRENT ===\n");
    println!("Testing concurrent packet forwarding with multiple users\n");

    let mut rng = thread_rng();

    // Step 1: Create public parameters
    let num_nodes = 5;
    let pp = PublicParams::generate(num_nodes, 10, &mut rng).expect("Failed to generate params");
    let pp = Arc::new(pp);

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

    // Print the weight matrix (trust graph)
    println!("\n  Trust Graph (Weight Matrix):");
    println!(
        "  Note: All weights for each node sum to 2^32 = {}",
        1u64 << 32
    );
    for (node_idx, neighbors) in generated_state.weight_matrix.adjacency.iter().enumerate() {
        println!("  Node {} -> neighbors:", node_idx);
        for (neighbor_idx, weight) in neighbors {
            let weight_pct = (*weight as f64 / (1u64 << 32) as f64) * 100.0;
            println!(
                "    -> Node {}: weight {} ({:.2}%)",
                neighbor_idx, weight, weight_pct
            );
        }
    }

    // Step 3: Create thread-safe vectors for each node
    println!("\nStep 2: Setting up thread-safe message queues...");

    type MessageQueue = Vec<(zkbrownian::types::Message, usize)>;
    let message_queues: Arc<Vec<Mutex<MessageQueue>>> =
        Arc::new((0..num_nodes).map(|_| Mutex::new(Vec::new())).collect());

    // Step 4: Each user spawns packets
    const NUM_PACKETS_PER_USER: usize = 250;
    const TTL: usize = 5;

    println!(
        "\nStep 3: Each user spawning {} packets...",
        NUM_PACKETS_PER_USER
    );

    // Spawn initial packets and put them into each node's queue
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

            message_queues[user_idx]
                .lock()
                .unwrap()
                .push((message, user_idx));
        }

        println!(
            "  User {} spawned {} packets (session {})",
            user_idx, NUM_PACKETS_PER_USER, session_id
        );
    }

    // Prepare data for verification (shared across threads)
    let all_public_keys: Vec<PublicKey> = generated_state
        .users_view
        .iter()
        .map(|user_view| user_view.public_key.clone())
        .collect();
    let all_public_keys = Arc::new(all_public_keys);

    let weight_commitment = Arc::new(WeightCommitment {
        commitment: vec![],
        metadata: vec![],
    });

    let merkle_root = generated_state.protocol_state.merkle_tree.root;

    // Create a shared bulletin board
    let bulletin_board: Arc<Mutex<Vec<BulletinBoardEntry>>> = Arc::new(Mutex::new(Vec::new()));

    println!(
        "\nStep 4: Starting concurrent forwarding with {} nodes...",
        num_nodes
    );
    let start_time = Instant::now();

    // Step 5: Spawn threads for each node
    let mut thread_handles = Vec::new();

    for node_idx in 0..num_nodes {
        let message_queues_clone = Arc::clone(&message_queues);
        let pp_clone = Arc::clone(&pp);
        let all_public_keys_clone = Arc::clone(&all_public_keys);
        let weight_commitment_clone = Arc::clone(&weight_commitment);
        let bb_clone = Arc::clone(&bulletin_board);
        let user_view = generated_state.users_view[node_idx].clone();

        let handle = thread::spawn(move || {
            let mut rng = rand::thread_rng();
            let mut forwarded_count = 0;
            let mut verification_count = 0;
            let mut final_messages_count = 0;

            // Timing measurements
            let thread_start = Instant::now();
            let mut total_verification_time = Duration::ZERO;
            let mut total_forward_time = Duration::ZERO;
            let mut total_idle_time = Duration::ZERO;
            let mut idle_iterations = 0;
            let mut processing_iterations = 0;

            // Exit condition: track when all queues first became empty
            // Only exit after ALL queues have been empty for this duration
            let mut all_empty_since: Option<Instant> = None;
            const EMPTY_DURATION_THRESHOLD: Duration = Duration::from_secs(5);

            println!(
                "  [Node {}] Thread started, processing messages...",
                node_idx
            );

            // Track when we last processed messages (for batching)
            let mut last_process_time = Instant::now();
            const BATCH_ACCUMULATION_DURATION: Duration = Duration::from_secs(5);

            // Each node continuously reads from its queue and processes messages
            loop {
                let loop_start = Instant::now();

                // Check if enough time has passed since last processing
                let time_since_last_process = last_process_time.elapsed();
                let should_process = time_since_last_process >= BATCH_ACCUMULATION_DURATION;

                if !should_process {
                    // Not enough time has passed, sleep briefly and continue
                    idle_iterations += 1;
                    thread::sleep(Duration::from_millis(100));
                    total_idle_time += loop_start.elapsed();

                    // Check if ALL queues are empty (exit condition)
                    let queue_sizes: Vec<usize> = message_queues_clone
                        .iter()
                        .map(|q| q.lock().unwrap().len())
                        .collect();
                    let all_queues_empty = queue_sizes.iter().all(|&size| size == 0);

                    if all_queues_empty && verification_count > 0 {
                        // Track how long all queues have been empty
                        if all_empty_since.is_none() {
                            all_empty_since = Some(Instant::now());
                            println!(
                                "  [Node {}] All queues empty, starting {:.0}s countdown to exit...",
                                node_idx, EMPTY_DURATION_THRESHOLD.as_secs_f64()
                            );
                        }

                        let empty_duration = all_empty_since.unwrap().elapsed();
                        if empty_duration >= EMPTY_DURATION_THRESHOLD {
                            // All queues have been empty for the threshold duration
                            println!(
                                "  [Node {}] EXITING: all queues empty for {:.1}s, verified {} messages",
                                node_idx, empty_duration.as_secs_f64(), verification_count
                            );
                            break;
                        }
                    } else if all_empty_since.is_some() {
                        // Queues were empty but now have messages again, reset the timer
                        println!(
                            "  [Node {}] Queues were empty but now have messages, resetting exit timer",
                            node_idx
                        );
                        all_empty_since = None;
                    }

                    continue;
                }

                // Time to process accumulated messages
                last_process_time = Instant::now();

                // Read and clear the queue
                let messages = {
                    let mut queue = message_queues_clone[node_idx].lock().unwrap();
                    std::mem::take(&mut *queue) // Take all messages and replace with empty vec
                };

                if messages.is_empty() {
                    // No messages accumulated, continue
                    idle_iterations += 1;
                    continue;
                }

                processing_iterations += 1;

                // Reset the empty timer since we're processing messages
                if all_empty_since.is_some() {
                    all_empty_since = None;
                }

                // Log batch processing
                println!(
                    "  [Node {}] BATCH PROCESSING: processing {} messages accumulated over {:.1}s (verified so far: {}, forwarded: {}, final: {})",
                    node_idx, messages.len(), time_since_last_process.as_secs_f64(), verification_count, forwarded_count, final_messages_count
                );

                // Verify the message
                let verify_start = Instant::now();
                let all_valid = verify_batch(
                    &messages
                        .clone()
                        .into_iter()
                        .map(|(m, _)| m)
                        .collect::<Vec<_>>(),
                    merkle_root,
                    &weight_commitment_clone,
                    &all_public_keys_clone,
                    &pp_clone,
                )
                .expect("Batch verification error");
                total_verification_time += verify_start.elapsed();

                verification_count += messages.len();

                if !all_valid {
                    panic!("Node {} received invalid message", node_idx);
                }

                // Process all messages we just read
                for (message, _origin_user) in messages {
                    let current_hops = message.hop_count();

                    // Check if message has reached TTL
                    if current_hops >= TTL {
                        // Message has reached TTL, save as final
                        final_messages_count += 1;
                        if final_messages_count == 1 {
                            println!(
                                "  [Node {}] First message reached TTL ({} hops)",
                                node_idx, current_hops
                            );
                        }
                        // Debug: log messages with hops > TTL
                        if current_hops > TTL {
                            println!(
                                "  [Node {}] WARNING: Message exceeded TTL! hops={} (TTL={}) [sid={}, pid={}]",
                                node_idx, current_hops, TTL, message.sid, message.pid
                            );
                        }
                        // Don't forward, just continue to next message
                        continue;
                    }

                    // Forward the message (only if under TTL)
                    let forward_start = Instant::now();
                    let (new_message, next_node_index, _diversifier) =
                        forward(&pp_clone, &user_view, &message, &mut rng)
                            .expect("Failed to forward message");
                    total_forward_time += forward_start.elapsed();

                    // Post to bulletin board
                    let entry = BulletinBoardEntry {
                        message: new_message.clone(),
                        receiver_index: next_node_index,
                        addressed_to: new_message.hops.last().unwrap().ppk.clone(),
                    };

                    bb_clone.lock().unwrap().push(entry);
                    forwarded_count += 1;

                    // Send to next node's queue
                    message_queues_clone[next_node_index]
                        .lock()
                        .unwrap()
                        .push((new_message.clone(), _origin_user));
                }
            }

            let total_thread_time = thread_start.elapsed();
            let active_time = total_thread_time - total_idle_time;

            println!(
                "  [Node {}] Thread finishing. Total: {} verified, {} forwarded, {} final",
                node_idx, verification_count, forwarded_count, final_messages_count
            );
            println!(
                "  [Node {}] Timing: total={:.2}ms, active={:.2}ms ({:.1}%), idle={:.2}ms ({:.1}%)",
                node_idx,
                total_thread_time.as_secs_f64() * 1000.0,
                active_time.as_secs_f64() * 1000.0,
                (active_time.as_secs_f64() / total_thread_time.as_secs_f64()) * 100.0,
                total_idle_time.as_secs_f64() * 1000.0,
                (total_idle_time.as_secs_f64() / total_thread_time.as_secs_f64()) * 100.0
            );
            println!(
                "  [Node {}] CPU breakdown: verify={:.2}ms ({:.1}%), forward={:.2}ms ({:.1}%)",
                node_idx,
                total_verification_time.as_secs_f64() * 1000.0,
                (total_verification_time.as_secs_f64() / active_time.as_secs_f64()) * 100.0,
                total_forward_time.as_secs_f64() * 1000.0,
                (total_forward_time.as_secs_f64() / active_time.as_secs_f64()) * 100.0
            );
            println!(
                "  [Node {}] Iterations: processing={}, idle={}",
                node_idx, processing_iterations, idle_iterations
            );

            (
                forwarded_count,
                verification_count,
                final_messages_count,
                total_thread_time,
                active_time,
                total_idle_time,
                total_verification_time,
                total_forward_time,
            )
        });

        thread_handles.push(handle);
    }

    println!("  All threads spawned. Waiting for completion...");

    // Wait for all threads to complete
    let mut total_forwarded = 0;
    let mut total_verifications = 0;
    let mut total_final_messages = 0;
    let mut aggregate_total_time = Duration::ZERO;
    let mut aggregate_active_time = Duration::ZERO;
    let mut aggregate_idle_time = Duration::ZERO;
    let mut aggregate_verify_time = Duration::ZERO;
    let mut aggregate_forward_time = Duration::ZERO;

    println!("\n  Waiting for threads to join...");
    for (idx, handle) in thread_handles.into_iter().enumerate() {
        println!("  Waiting for Node {} to finish...", idx);
        let (
            forwarded,
            verified,
            final_msgs,
            total_time,
            active_time,
            idle_time,
            verify_time,
            forward_time,
        ) = handle.join().expect("Thread panicked");
        println!("  Node {} joined successfully", idx);
        total_forwarded += forwarded;
        total_verifications += verified;
        total_final_messages += final_msgs;
        aggregate_total_time += total_time;
        aggregate_active_time += active_time;
        aggregate_idle_time += idle_time;
        aggregate_verify_time += verify_time;
        aggregate_forward_time += forward_time;
    }

    println!("\n  All threads joined. Checking remaining messages in queues...");
    for (idx, queue) in message_queues.iter().enumerate() {
        let remaining = queue.lock().unwrap().len();
        if remaining > 0 {
            println!(
                "  WARNING: Node {} has {} messages still in queue!",
                idx, remaining
            );
        }
    }

    let elapsed = start_time.elapsed();

    // Collect all bulletin board messages
    let bulletin_board_messages = bulletin_board.lock().unwrap().clone();

    println!(
        "\n  Concurrent forwarding complete in {:.2} ms (wall-clock time)",
        elapsed.as_secs_f64() * 1000.0
    );
    println!("  Total messages forwarded: {}", total_forwarded);
    println!(
        "  Total messages that reached TTL: {}",
        total_final_messages
    );
    println!("  Total verifications: {}", total_verifications);
    println!(
        "  EXPECTED: {} total messages spawned, each should reach TTL exactly once",
        num_nodes * NUM_PACKETS_PER_USER
    );
    println!(
        "  ISSUE: {} final messages received, but {} expected!",
        total_final_messages,
        num_nodes * NUM_PACKETS_PER_USER
    );

    // Aggregate timing statistics
    println!("\n=== Aggregate CPU Time Across All Threads ===");
    println!(
        "  Total CPU time (sum of all threads): {:.2} ms",
        aggregate_total_time.as_secs_f64() * 1000.0
    );
    println!(
        "  Active CPU time: {:.2} ms ({:.1}%)",
        aggregate_active_time.as_secs_f64() * 1000.0,
        (aggregate_active_time.as_secs_f64() / aggregate_total_time.as_secs_f64()) * 100.0
    );
    println!(
        "  Idle CPU time: {:.2} ms ({:.1}%)",
        aggregate_idle_time.as_secs_f64() * 1000.0,
        (aggregate_idle_time.as_secs_f64() / aggregate_total_time.as_secs_f64()) * 100.0
    );
    println!(
        "  Time in verification: {:.2} ms ({:.1}% of active)",
        aggregate_verify_time.as_secs_f64() * 1000.0,
        (aggregate_verify_time.as_secs_f64() / aggregate_active_time.as_secs_f64()) * 100.0
    );
    println!(
        "  Time in forwarding: {:.2} ms ({:.1}% of active)",
        aggregate_forward_time.as_secs_f64() * 1000.0,
        (aggregate_forward_time.as_secs_f64() / aggregate_active_time.as_secs_f64()) * 100.0
    );

    // Parallelism metrics
    let parallelism = aggregate_total_time.as_secs_f64() / elapsed.as_secs_f64();
    println!(
        "  Average parallelism: {:.2}x ({} threads)",
        parallelism, num_nodes
    );

    // Per-operation averages
    // Calculate total number of Schnorr signatures across all verified messages
    let total_schnorr_sigs: usize = bulletin_board_messages
        .iter()
        .map(|entry| entry.message.hop_count())
        .sum();

    if total_verifications > 0 {
        println!(
            "  Average verification time: {:.2} ms/msg ({:.2} ms/Schnorr, {} total Schnorr sigs)",
            (aggregate_verify_time.as_secs_f64() * 1000.0) / total_verifications as f64,
            if total_schnorr_sigs > 0 {
                (aggregate_verify_time.as_secs_f64() * 1000.0) / total_schnorr_sigs as f64
            } else {
                0.0
            },
            total_schnorr_sigs
        );
    }
    if total_forwarded > 0 {
        println!(
            "  Average forward time: {:.2} ms/msg",
            (aggregate_forward_time.as_secs_f64() * 1000.0) / total_forwarded as f64
        );
    }

    // Step 6: Summary
    println!("\n=== Protocol Summary ===");
    println!(
        "  Total messages on bulletin board: {}",
        bulletin_board_messages.len()
    );
    println!(
        "  Note: With true concurrency, nodes perform more than {} rounds",
        TTL
    );
    println!("  Each node processes messages as they arrive, leading to more total hops");

    // Count messages by hop count
    let mut hop_counts = std::collections::HashMap::new();
    for entry in &bulletin_board_messages {
        *hop_counts.entry(entry.message.hop_count()).or_insert(0) += 1;
    }

    println!("\n  Messages by hop count:");
    let mut sorted_hops: Vec<_> = hop_counts.keys().collect();
    sorted_hops.sort();
    for hop in sorted_hops {
        println!("    {} hops: {} messages", hop, hop_counts[hop]);
    }

    println!("\n=== Test Complete ===");
}
