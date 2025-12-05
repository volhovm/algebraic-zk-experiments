//! Benchmarks for Forward protocol operations

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::thread_rng;
use zkbrownian::crypto::curve_ops::keygen;
use zkbrownian::crypto::generators::Generators;
use zkbrownian::protocol::{forward, generate_state, spawn};
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

    // Setup: generate protocol state
    let generated_state = generate_state(2, &mut rng);
    let user_0_view = &generated_state.users_view[0];

    // Create public parameters
    let pp = PublicParams {
        num_nodes: 2,
        max_out_degree: 10,
        g1_generators: vec![],
        g2_generators: vec![],
        groth16_params: vec![],
        generators: Generators::generate(&mut rng, 10, 10),
    };

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

criterion_group!(benches, bench_keygen, bench_spawn, bench_forward);
criterion_main!(benches);
