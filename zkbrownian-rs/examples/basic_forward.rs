//! Basic example demonstrating the Forward protocol
//!
//! This example shows:
//! 1. Generating protocol state with multiple users
//! 2. Spawning an initial message
//! 3. Forwarding the message through the network using UserView
//! 4. Verifying the message

use rand::thread_rng;
use zkbrownian::protocol::{
    forward, generate_state, spawn, verify, BulletinBoard, BulletinBoardEntry,
    InMemoryBulletinBoard,
};
use zkbrownian::types::{PublicKey, WeightCommitment};
use zkbrownian::MAX_HOPS;

fn main() {
    println!("=== ZK Brownian Forward Protocol - Basic Example ===\n");

    let mut rng = thread_rng();

    // Step 1: Generate protocol state with multiple users
    println!("Step 1: Generating protocol state for 5 users...");
    let num_nodes = 5;
    let generated_state = generate_state(num_nodes, &mut rng);

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

    let message = match spawn(
        &spawner_view.secret_key,
        &spawner_view.public_key,
        packet_id,
        session_id,
        &mut rng,
    ) {
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

    // Step 4: Forward the message through the network
    println!("\nStep 4: Forwarding message through network...");
    let mut current_message = message;
    let mut current_node_index = spawner_index;

    for hop in 0..MAX_HOPS.min(3) {
        // Forward up to 3 hops for demo
        println!("\n  Hop {}:", hop + 1);
        println!("    Current node: {}", current_node_index);

        let current_user_view = &generated_state.users_view[current_node_index];

        match forward(current_user_view, &current_message, &mut rng) {
            Ok((new_message, next_node_index, _diversifier)) => {
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

    // Step 5: Verify the final message
    println!("\n\nStep 5: Verifying final message...");
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

    println!("\n=== Example Complete ===");
}
