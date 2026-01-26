//! Simple benchmark for Forward protocol - measures total duration

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::thread_rng;
use zkbrownian::protocol::{forward, generate_random_state, spawn};
use zkbrownian::types::PublicParams;

fn bench_forward_simple(c: &mut Criterion) {
    let mut rng = thread_rng();

    // Create public parameters with more users for better routing
    let pp = PublicParams::generate(2, 10, &mut rng).expect("Failed to generate params");

    // Setup: generate protocol state with 5 users
    let generated_state = generate_random_state(&pp, 5, &mut rng);
    let user_0_view = &generated_state.users_view[0];

    // Create initial message
    let message = spawn(
        &user_0_view.secret_key,
        &user_0_view.public_key,
        1,
        100,
        &mut rng,
    )
    .unwrap();

    c.bench_function("forward_simple", |b| {
        b.iter(|| {
            let result = forward(
                black_box(&pp),
                black_box(user_0_view),
                black_box(&message),
                black_box(&mut rng),
            );
            // Ensure the result is used
            black_box(result)
        })
    });
}

criterion_group!(benches, bench_forward_simple);
criterion_main!(benches);
