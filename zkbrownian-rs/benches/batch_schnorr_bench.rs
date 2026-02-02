//! Benchmark for batch Schnorr proof generation
//!
//! This benchmark measures the performance of table construction and memory usage.

use ark_bls12_381::G1Affine as G1A;
use criterion::{criterion_group, criterion_main, Criterion};
use zkbrownian::proving::bulletproofs::{BatchProvingTables, BulletproofGens, PedersenGens};
use zkbrownian::proving::relations::rerandomize::build_tables;

/// Benchmark table construction (one-time setup cost)
fn bench_table_construction(c: &mut Criterion) {
    let pc_gens: PedersenGens<G1A> = PedersenGens::default();
    let bp_gens: BulletproofGens<G1A> = BulletproofGens::new(4096, 1);

    c.bench_function("batch_table_construction", |b| {
        b.iter(|| {
            let _tables = BatchProvingTables::new(&pc_gens, &bp_gens, 4096, 0, 8);
        });
    });
}

/// Benchmark table memory usage estimation
fn bench_table_memory(c: &mut Criterion) {
    let pc_gens: PedersenGens<G1A> = PedersenGens::default();
    let bp_gens: BulletproofGens<G1A> = BulletproofGens::new(4096, 1);
    let tables = BatchProvingTables::new(&pc_gens, &bp_gens, 4096, 0, 8);

    c.bench_function("batch_table_memory_estimate", |b| {
        b.iter(|| {
            let _mem = tables.memory_usage_estimate();
        });
    });

    // Print actual memory usage
    println!(
        "\nBatch tables memory usage: {} MB",
        tables.memory_usage_estimate() / 1_000_000
    );
}

/// Benchmark G3 table construction
fn bench_g3_table_construction(c: &mut Criterion) {
    // Generate a proper G3 generator (same as in PublicParams)
    use rand::SeedableRng;
    let mut rng = rand::rngs::StdRng::seed_from_u64(0); // Deterministic for benchmarking
    let generators = zkbrownian::crypto::generators::Generators::generate(&mut rng, 10, 10, 10);
    let h_g3 = *generators.g3(1).expect("G3 generator should exist");

    c.bench_function("g3_table_construction", |b| {
        b.iter(|| {
            let _tables = build_tables(h_g3);
        });
    });
}

criterion_group!(
    benches,
    bench_table_construction,
    bench_table_memory,
    bench_g3_table_construction,
);
criterion_main!(benches);
