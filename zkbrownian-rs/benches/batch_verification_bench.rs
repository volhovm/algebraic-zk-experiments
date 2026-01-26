//! Benchmarks for batch verification operations

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::thread_rng;
use zkbrownian::protocol::{forward, generate_random_state, spawn, verify_batch};
use zkbrownian::types::{PublicKey, PublicParams, WeightCommitment};

fn batch_verification_benchmark(c: &mut Criterion) {
    let mut rng = thread_rng();

    // Step 1: Create public parameters
    let num_nodes = 10;
    let pp = PublicParams::generate(num_nodes, 10, &mut rng).expect("Failed to generate params");

    // Step 2: Generate protocol state
    let generated_state = generate_random_state(&pp, num_nodes, &mut rng);

    // Step 3: Generate messages by spawning and forwarding to reach TTL
    const NUM_MESSAGES: usize = 200;
    const TTL: usize = 5;

    let mut all_messages = Vec::new();

    for i in 0..NUM_MESSAGES {
        let spawner_index = i % num_nodes;
        let spawner_view = &generated_state.users_view[spawner_index];

        // Spawn initial message
        let mut message = spawn(
            &spawner_view.secret_key,
            &spawner_view.public_key,
            i as u32,
            1000 + (i / num_nodes) as u64,
            &mut rng,
        )
        .expect("Failed to spawn message");

        // Forward the message TTL times
        let mut current_node_index = spawner_index;
        for _ in 0..TTL {
            let current_user_view = &generated_state.users_view[current_node_index];
            let (new_message, next_node_index, _diversifier) =
                forward(&pp, current_user_view, &message, &mut rng)
                    .expect("Failed to forward message");

            message = new_message;
            current_node_index = next_node_index;
        }

        all_messages.push(message);
    }

    // Prepare verification parameters
    let all_public_keys: Vec<PublicKey> = generated_state
        .users_view
        .iter()
        .map(|user_view| user_view.public_key.clone())
        .collect();

    let weight_commitment = WeightCommitment {
        commitment: vec![],
        metadata: vec![],
    };

    // Step 4: Benchmark different batch sizes
    let mut group = c.benchmark_group("batch_verification");
    let batch_sizes = vec![1, 10, 25, 50, 100, 200];

    for &batch_size in &batch_sizes {
        if batch_size > NUM_MESSAGES {
            continue;
        }

        group.bench_with_input(
            BenchmarkId::from_parameter(batch_size),
            &batch_size,
            |b, &size| {
                let batch = &all_messages[0..size];
                b.iter(|| {
                    verify_batch(
                        black_box(batch),
                        black_box(generated_state.protocol_state.merkle_tree.root),
                        black_box(&weight_commitment),
                        black_box(&all_public_keys),
                        black_box(&pp),
                    )
                    .expect("Batch verification error")
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, batch_verification_benchmark);
criterion_main!(benches);
