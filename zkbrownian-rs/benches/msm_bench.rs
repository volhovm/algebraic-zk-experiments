//! Benchmarks for MSM (Multi-Scalar Multiplication) operations

use ark_bls12_381::{G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_std::UniformRand;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::thread_rng;

fn bench_msm(c: &mut Criterion) {
    let mut rng = thread_rng();

    // Test sizes: 512, 1024, 2048, 4096
    let sizes = [512, 1024, 2048, 4096];

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

criterion_group!(benches, bench_msm);
criterion_main!(benches);
