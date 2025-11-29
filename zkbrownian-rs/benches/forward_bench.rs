//! Benchmarks for Forward protocol operations

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::thread_rng;
use zkbrownian::crypto::curve_ops::keygen;
use zkbrownian::protocol::{forward, spawn, WeightMatrix};
use zkbrownian::WEIGHT_SUM;

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

    // Setup
    let (sk1, pk1) = keygen(&mut rng);
    let (_sk2, pk2) = keygen(&mut rng);
    let all_pks = vec![pk1.clone(), pk2.clone()];
    let weight_matrix = WeightMatrix::uniform(2, WEIGHT_SUM);
    let message = spawn(&sk1, &pk1, 1, 100, &mut rng).unwrap();

    c.bench_function("forward", |b| {
        b.iter(|| {
            let _ = forward(
                black_box(&pk1),
                black_box(&sk1),
                black_box(&message),
                black_box(&weight_matrix),
                black_box(&all_pks),
                black_box(&mut rng),
            );
        })
    });
}

criterion_group!(benches, bench_keygen, bench_spawn, bench_forward);
criterion_main!(benches);
