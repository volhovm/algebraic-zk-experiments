//! Benchmarks for MSM (Multi-Scalar Multiplication) operations

use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::{scalar_mul::BatchMulPreprocessing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_std::UniformRand;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::thread_rng;

use zkbrownian::crypto::msm::FixedBaseMsmTable;

fn bench_msm(c: &mut Criterion) {
    let mut rng = thread_rng();

    // Test sizes: 512, 1024, 2048, 4096
    let sizes = [512, 1024, 2048, 2500, 4096];

    let mut group = c.benchmark_group("msm_unchecked");

    for &size in &sizes {
        // Generate fixed base elements (same for all runs)
        let bases: Vec<G1Affine> = (0..size)
            .map(|_| G1Projective::rand(&mut rng).into_affine())
            .collect();

        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &_size| {
            // Generate fresh scalars for each iteration
            let scalars: Vec<_> = (0..size)
                .map(|_| <G1Affine as AffineRepr>::ScalarField::rand(&mut rng))
                .collect();

            b.iter(|| {
                let _ = black_box(<G1Projective as VariableBaseMSM>::msm_unchecked(
                    black_box(&bases),
                    black_box(&scalars),
                ));
            });
        });
    }

    group.finish();
}

fn bench_fixed_base_msm_table(c: &mut Criterion) {
    let mut rng = thread_rng();

    // Test sizes: 512, 1024, 2048, 2500, 4096
    let sizes = [1024, 2048, 2500, 4096];
    // Test different window sizes
    let window_sizes = [8, 12];

    for &window_bits in &window_sizes {
        let mut group = c.benchmark_group(format!("fixed_base_msm_w{}", window_bits));

        for &size in &sizes {
            // Generate fixed base elements (same for all runs)
            let bases: Vec<G1Projective> =
                (0..size).map(|_| G1Projective::rand(&mut rng)).collect();

            // Precompute table once (this is the one-time cost)
            let table = FixedBaseMsmTable::new(&bases, window_bits);

            group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &_size| {
                // Generate fresh scalars for each iteration
                let scalars: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut rng)).collect();

                b.iter(|| {
                    let result = black_box(table.msm(black_box(&scalars)));
                    black_box(result)
                });
            });
        }

        group.finish();
    }
}

fn bench_fixed_base_msm_with_precomputation(c: &mut Criterion) {
    let mut rng = thread_rng();

    // Test sizes
    let sizes = [512, 1024, 2048, 2500, 4096];
    let window_bits = 8; // Use window_bits=8 as the default

    let mut group = c.benchmark_group("fixed_base_msm_w8_with_precomp");

    for &size in &sizes {
        // Generate fixed base elements
        let bases: Vec<G1Projective> = (0..size).map(|_| G1Projective::rand(&mut rng)).collect();

        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &_size| {
            // Generate fresh scalars for each iteration
            let scalars: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut rng)).collect();

            b.iter(|| {
                // Include precomputation time in the benchmark
                let table = FixedBaseMsmTable::new(&bases, window_bits);
                let result = black_box(table.msm(black_box(&scalars)));
                black_box(result)
            });
        });
    }

    group.finish();
}

fn bench_fixed_base_msm_batch(c: &mut Criterion) {
    let mut rng = thread_rng();

    // Test different batch sizes
    let base_sizes = [2048, 4096];
    let batch_sizes = [256, 512, 1024];
    let window_bits = 8;

    for &base_size in &base_sizes {
        for &batch_size in &batch_sizes {
            let mut group = c.benchmark_group(format!(
                "fixed_base_msm_batch_n{}_b{}",
                base_size, batch_size
            ));
            group.sample_size(10);

            // Generate fixed bases once
            let bases: Vec<G1Projective> = (0..base_size)
                .map(|_| G1Projective::rand(&mut rng))
                .collect();

            let bases_affine: Vec<G1Affine> =
                bases.iter().map(|x| x.clone().into_affine()).collect();

            // Precompute table once
            let table = FixedBaseMsmTable::new(&bases, window_bits);

            group.bench_function("batch", |b| {
                // Generate fresh scalar batches for each iteration
                let scalar_batch: Vec<Vec<Fr>> = (0..batch_size)
                    .map(|_| (0..base_size).map(|_| Fr::rand(&mut rng)).collect())
                    .collect();

                b.iter(|| {
                    let results = black_box(table.msm_batch(black_box(&scalar_batch)));
                    black_box(results)
                });
            });

            // Also benchmark the sequential approach for comparison
            group.bench_function("sequential", |b| {
                let scalar_batch: Vec<Vec<Fr>> = (0..batch_size)
                    .map(|_| (0..base_size).map(|_| Fr::rand(&mut rng)).collect())
                    .collect();

                b.iter(|| {
                    let results: Vec<G1Projective> = scalar_batch
                        .iter()
                        .map(|scalars| table.msm(scalars))
                        .collect();
                    black_box(results)
                });
            });

            // Also benchmark the sequential approach for comparison
            group.bench_function("no precomp sequential", |b| {
                let scalar_batch: Vec<Vec<Fr>> = (0..batch_size)
                    .map(|_| (0..base_size).map(|_| Fr::rand(&mut rng)).collect())
                    .collect();

                b.iter(|| {
                    let results: Vec<G1Projective> = scalar_batch
                        .iter()
                        .map(|scalars| {
                            black_box(<G1Projective as VariableBaseMSM>::msm_unchecked(
                                black_box(&bases_affine),
                                black_box(&scalars),
                            ))
                        })
                        .collect();
                    black_box(results)
                });
            });

            group.finish();
        }
    }
}

criterion_group!(
    benches,
    bench_msm,
    bench_fixed_base_msm_table,
    bench_fixed_base_msm_with_precomputation,
    bench_fixed_base_msm_batch
);
criterion_main!(benches);
