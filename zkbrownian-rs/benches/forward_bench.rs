//! Benchmarks for Forward protocol operations

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::thread_rng;
use zkbrownian::crypto::curve_ops::keygen;
use zkbrownian::protocol::{forward, forward_batch, generate_random_state, spawn};
use zkbrownian::types::PublicParams;

fn bench_keygen(c: &mut Criterion) {
    let mut rng = thread_rng();

    c.bench_function("keygen", |b| {
        b.iter(|| {
            let (_sk, _pk) = keygen(black_box(&mut rng));
        })
    });
}

fn bench_spawn(c: &mut Criterion) {
    let mut rng = thread_rng();
    let (sk, pk) = keygen(&mut rng);

    c.bench_function("spawn", |b| {
        b.iter(|| {
            let _ = spawn(
                black_box(&sk),
                black_box(&pk),
                black_box(1),
                black_box(100),
                black_box(&mut rng),
            );
        })
    });
}

fn bench_forward(c: &mut Criterion) {
    let mut rng = thread_rng();

    // Create public parameters
    let pp = PublicParams::generate(2, 10, &mut rng).expect("Failed to generate params");

    // Setup: generate protocol state
    let generated_state = generate_random_state(&pp, 2, &mut rng);
    let user_0_view = &generated_state.users_view[0];

    let message = spawn(
        &user_0_view.secret_key,
        &user_0_view.public_key,
        1,
        100,
        &mut rng,
    )
    .unwrap();

    c.bench_function("forward", |b| {
        b.iter(|| {
            let _ = forward(
                black_box(&pp),
                black_box(user_0_view),
                black_box(&message),
                black_box(&mut rng),
            );
        })
    });
}

fn bench_forward_batch(c: &mut Criterion) {
    let mut rng = thread_rng();

    // Create a group for batch size comparison
    let mut group = c.benchmark_group("forward_batch");
    group.sample_size(10);

    // Create public parameters with more nodes for batching
    let pp = PublicParams::generate(8, 8, &mut rng).expect("Failed to generate params");

    // Setup: generate protocol state with multiple users
    let num_users = 8;
    let generated_state = generate_random_state(&pp, num_users, &mut rng);

    for batch_size in [50, 100, 250, 500] {
        // Prepare batch_size messages
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

        group.bench_with_input(
            BenchmarkId::from_parameter(batch_size),
            &batch_size,
            |b, _| {
                b.iter(|| {
                    let _ = forward_batch(black_box(&pp), black_box(&inputs), black_box(&mut rng));
                });
            },
        );
    }

    group.finish();
}

fn bench_forward_sequential_vs_batch(c: &mut Criterion) {
    let mut rng = thread_rng();

    // Create public parameters
    let pp = PublicParams::generate(8, 8, &mut rng).expect("Failed to generate params");

    // Setup: generate protocol state
    let num_users = 8;
    let generated_state = generate_random_state(&pp, num_users, &mut rng);

    // Prepare 100 messages for comparison
    let batch_size = 100;
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

    // Benchmark batch forward
    c.bench_function("forward_batch_100", |b| {
        b.iter(|| {
            let _ = forward_batch(black_box(&pp), black_box(&inputs), black_box(&mut rng));
        });
    });

    // Benchmark sequential forward
    c.bench_function("forward_sequential_100", |b| {
        b.iter(|| {
            for (user_view, message) in &inputs {
                let _ = forward(
                    black_box(&pp),
                    black_box(user_view),
                    black_box(message),
                    black_box(&mut rng),
                );
            }
        });
    });
}

criterion_group!(
    benches,
    bench_keygen,
    bench_spawn,
    bench_forward,
    bench_forward_batch,
    bench_forward_sequential_vs_batch
);
criterion_main!(benches);
