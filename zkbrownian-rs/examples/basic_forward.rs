//! Basic example demonstrating the Forward protocol
//!
//! This example shows:
//! 1. Setting up multiple nodes with key pairs
//! 2. Creating a weight matrix
//! 3. Spawning an initial message
//! 4. Forwarding the message through the network
//! 5. Verifying the message

use zkbrownian::crypto::curve_ops::keygen;
use zkbrownian::protocol::{forward, spawn, verify, BulletinBoard, InMemoryBulletinBoard, WeightMatrix, BulletinBoardEntry};
use zkbrownian::types::{PublicKey, SecretKey, WeightCommitment};
use zkbrownian::{MAX_HOPS, WEIGHT_SUM};
use rand::thread_rng;

fn main() {
    println!("=== ZK Brownian Forward Protocol - Basic Example ===\n");

    let mut rng = thread_rng();

    // Step 1: Setup network with multiple nodes
    println!("Step 1: Setting up network with 5 nodes...");
    let num_nodes = 5;
    let mut nodes: Vec<(SecretKey, PublicKey)> = Vec::new();

    for i in 0..num_nodes {
        let (sk, pk) = keygen(&mut rng);
        nodes.push((sk, pk));
        println!("  Node {} created", i);
    }

    let all_public_keys: Vec<PublicKey> = nodes.iter().map(|(_, pk)| pk.clone()).collect();

    // Step 2: Create weight matrix (uniform distribution for simplicity)
    println!("\nStep 2: Creating uniform weight matrix...");
    let weight_matrix = WeightMatrix::uniform(num_nodes, WEIGHT_SUM);
    println!("  Each node has equal weight to all other nodes");

    // Step 3: Create bulletin board
    println!("\nStep 3: Initializing bulletin board...");
    let mut bulletin_board = InMemoryBulletinBoard::new();

    // Step 4: Node 0 spawns a message
    println!("\nStep 4: Node 0 spawns a message...");
    let spawner_index = 0;
    let (spawner_sk, spawner_pk) = &nodes[spawner_index];
    let packet_id = 42;
    let session_id = 1000;

    let message = match spawn(spawner_sk, spawner_pk, packet_id, session_id, &mut rng) {
        Ok(msg) => {
            println!("  ✓ Message spawned successfully");
            println!("    Packet ID: {}", msg.pid);
            println!("    Session ID: {}", msg.sid);
            println!("    Initial hop count: {}", msg.hop_count());
            msg
        }
        Err(e) => {
            println!("  ✗ Failed to spawn message: {:?}", e);
            return;
        }
    };

    // Step 5: Forward the message through the network
    println!("\nStep 5: Forwarding message through network...");
    let mut current_message = message;
    let mut current_node_index = spawner_index;

    for hop in 0..MAX_HOPS.min(3) {
        // Forward up to 3 hops for demo
        println!("\n  Hop {}:", hop + 1);
        println!("    Current node: {}", current_node_index);

        let (current_sk, current_pk) = &nodes[current_node_index];

        match forward(
            current_pk,
            current_sk,
            &current_message,
            &weight_matrix,
            &all_public_keys,
            &mut rng,
        ) {
            Ok((new_message, next_node_index, diversifier)) => {
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
            Err(e) => {
                println!("    ✗ Forward failed: {:?}", e);
                break;
            }
        }
    }

    // Step 6: Verify the final message
    println!("\n\nStep 6: Verifying final message...");
    let weight_commitment = WeightCommitment {
        commitment: vec![],
        metadata: vec![],
    };

    match verify(
        &current_message,
        current_message.hop_count(),
        &weight_commitment,
        &all_public_keys,
    ) {
        Ok(true) => {
            println!("  ✓ Message verified successfully!");
        }
        Ok(false) => {
            println!("  ✗ Message verification failed");
        }
        Err(e) => {
            println!("  ✗ Verification error: {:?}", e);
        }
    }

    // Step 7: Check bulletin board
    println!("\n\nStep 7: Bulletin board summary:");
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

    println!("\n=== Example Complete ===");
}
