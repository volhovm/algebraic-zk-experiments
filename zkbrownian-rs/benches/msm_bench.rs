//! Benchmarks for MSM (Multi-Scalar Multiplication) operations

use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::{scalar_mul::BatchMulPreprocessing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_std::UniformRand;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::thread_rng;

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

fn bench_msm_with_fixed_base_preprocessing(c: &mut Criterion) {
    let mut rng = thread_rng();

    // Test sizes: 512, 1024, 2048, 2500, 4096
    let sizes = [512, 1024, 2048, 2500, 4096];

    let mut group = c.benchmark_group("msm_fixed_base_preprocessed");

    for &size in &sizes {
        // Generate fixed base elements (same for all runs)
        let bases: Vec<G1Projective> = (0..size).map(|_| G1Projective::rand(&mut rng)).collect();

        // Precompute preprocessing tables for each fixed base
        // This simulates the case where we have fixed generators (like in BulletproofGens)
        let preprocessing_tables: Vec<BatchMulPreprocessing<G1Projective>> = bases
            .iter()
            .map(|base| BatchMulPreprocessing::new(*base, 1)) // num_scalars=1 per base
            .collect();

        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &_size| {
            // Generate fresh scalars for each iteration
            let scalars: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut rng)).collect();

            b.iter(|| {
                // Manually compute MSM using preprocessed fixed bases
                let points: Vec<G1Affine> = preprocessing_tables
                    .iter()
                    .zip(scalars.iter())
                    .flat_map(|(table, scalar)| {
                        // Use preprocessed multiplication for each base
                        // batch_mul expects a slice, so we pass a single-element slice
                        table.batch_mul(&[*scalar])
                    })
                    .collect();

                // Sum all the points
                let result: G1Projective = points.into_iter().map(|p| p.into_group()).sum();
                black_box(result)
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_msm, bench_msm_with_fixed_base_preprocessing);
criterion_main!(benches);
