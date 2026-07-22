#![allow(clippy::redundant_closure)]
#![allow(clippy::unit_arg)]

use std::ops::Mul;

use ark_bls12_381::{
    Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective,
};
use ark_ec::{
    pairing::{prepare_g1, prepare_g2, Pairing},
    AffineRepr, CurveGroup,
};
use ark_ff::{BigInteger256, Field, UniformRand};
use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use itertools::izip;
use rand::prelude::StdRng;
use rand_core::SeedableRng;

type E = Bls12_381;
type G1Prepared = <E as Pairing>::G1Prepared;
type G2Prepared = <E as Pairing>::G2Prepared;
type TargetField = <E as Pairing>::TargetField;

const BENCH_CASES: [usize; 7] = [1, 2, 4, 8, 16, 32, 64];

pub fn bench_mul(c: &mut Criterion) {
    let mut rng = &mut StdRng::seed_from_u64(0);

    let mut group = c.benchmark_group("mul");

    let g1 = G1Projective::rand(&mut rng);
    let g2 = G2Projective::rand(&mut rng);
    let g1_affine = g1.into_affine();
    let g2_affine = g2.into_affine();
    let r = Fr::rand(&mut rng);

    group.bench_function("G1", |b| b.iter(|| g1.mul(r)));
    group.bench_function("G2Projective", |b| b.iter(|| g2.mul(r)));
    group.bench_function("G1Affine", |b| b.iter(|| g1_affine.mul(r)));
    group.bench_function("G2Affine", |b| b.iter(|| g2_affine.mul(r)));
}

pub fn bench_into_affine(c: &mut Criterion) {
    let mut rng = &mut StdRng::seed_from_u64(0);

    let mut group = c.benchmark_group("into_affine");

    let g1 = G1Projective::rand(&mut rng);
    let g2 = G2Projective::rand(&mut rng);

    group.bench_function("G1", |b| b.iter(|| g1.into_affine()));
    group.bench_function("G2Projective", |b| b.iter(|| g2.into_affine()));
}

pub fn bench_into_projective(c: &mut Criterion) {
    let mut rng = &mut StdRng::seed_from_u64(0);

    let mut group = c.benchmark_group("into_group");

    let g1_affine = G1Projective::rand(&mut rng).into_affine();
    let g2_affine = G2Projective::rand(&mut rng).into_affine();

    group.bench_function("G1Affine", |b| b.iter(|| g1_affine.into_group()));
    group.bench_function("G2Affine", |b| b.iter(|| g2_affine.into_group()));
}

pub fn bench_prepare_gx(c: &mut Criterion) {
    let mut rng = &mut StdRng::seed_from_u64(0);

    let mut group = c.benchmark_group("prepare_gx");

    let g1_affine = G1Projective::rand(&mut rng).into_affine();
    let g2_affine = G2Projective::rand(&mut rng).into_affine();

    group.bench_function("G1Affine", |b| b.iter(|| prepare_g1::<E>(g1_affine)));
    group.bench_function("G2Affine", |b| b.iter(|| prepare_g2::<E>(g2_affine)));
}

pub fn bench_pow(c: &mut Criterion) {
    let mut rng = &mut StdRng::seed_from_u64(0);

    let mut group = c.benchmark_group("pow");

    let fqk = TargetField::rand(&mut rng);
    let int = BigInteger256::rand(&mut rng);

    group.bench_function("TargetField", |b| b.iter(|| fqk.pow(int)));
}

fn make_prepared_pairing_inputs(
    size: usize,
    rng: &mut StdRng,
) -> (Vec<G1Prepared>, Vec<G2Prepared>) {
    let (p, q) = make_pairing_inputs(size, rng);
    let p = p
        .into_iter()
        .map(|i| G1Prepared::from(i))
        .collect::<Vec<G1Prepared>>();
    let q = q
        .into_iter()
        .map(|i| G2Prepared::from(i))
        .collect::<Vec<G2Prepared>>();
    (p, q)
}

fn make_pairing_inputs(
    size: usize,
    rng: &mut StdRng,
) -> (Vec<G1Affine>, Vec<G2Affine>) {
    let p = (0..size)
        .map(|_| G1Affine::generator().mul(Fr::rand(rng)).into_affine())
        .collect::<Vec<G1Affine>>();
    let q = (0..size)
        .map(|_| G2Affine::generator().mul(Fr::rand(rng)).into_affine())
        .collect::<Vec<G2Affine>>();
    (p, q)
}

pub fn bench_miller_loop(c: &mut Criterion) {
    let rng = &mut StdRng::seed_from_u64(0);

    let mut group = c.benchmark_group("miller_loop");

    let (p, q) =
        make_prepared_pairing_inputs(BENCH_CASES[BENCH_CASES.len() - 1], rng);

    for nr_of_inputs in BENCH_CASES {
        let p = p.iter().take(nr_of_inputs).cloned().collect::<Vec<_>>();
        let q = q.iter().take(nr_of_inputs).cloned().collect::<Vec<_>>();
        group.bench_function(
            BenchmarkId::new("BLS12-381 miller_loop", nr_of_inputs),
            |b| b.iter(|| E::multi_miller_loop(p.clone(), q.clone())),
        );
    }
}

pub fn bench_final_exponentiation(c: &mut Criterion) {
    let rng = &mut StdRng::seed_from_u64(0);

    let mut group = c.benchmark_group("final_exponentiation");

    let (p, q) =
        make_prepared_pairing_inputs(BENCH_CASES[BENCH_CASES.len() - 1], rng);

    let ml = BENCH_CASES
        .iter()
        .map(|nr_of_inputs| {
            let p = p.iter().take(*nr_of_inputs).cloned().collect::<Vec<_>>();
            let q = q.iter().take(*nr_of_inputs).cloned().collect::<Vec<_>>();
            E::multi_miller_loop(p, q)
        })
        .collect::<Vec<_>>();

    for (ml, nr_of_inputs) in izip!(ml, BENCH_CASES) {
        group.bench_function(
            BenchmarkId::new("BLS12-381 final_exponentiation", nr_of_inputs),
            |b| b.iter(|| E::final_exponentiation(ml)),
        );
    }
}

pub fn bench_pairing(c: &mut Criterion) {
    let rng = &mut StdRng::seed_from_u64(0);

    let mut group = c.benchmark_group("pairing");

    let (p, q) = make_pairing_inputs(1, rng);

    group.bench_function("BLS12-381 pairing", |b| {
        b.iter(|| black_box(Bls12_381::pairing(p[0], q[0])))
    });
}

pub fn bench_product_of_pairings(c: &mut Criterion) {
    let rng = &mut StdRng::seed_from_u64(0);

    let mut group = c.benchmark_group("multi_pairing");
    group.sample_size(10);

    let (p, q) =
        make_prepared_pairing_inputs(BENCH_CASES[BENCH_CASES.len() - 1], rng);

    for nr_of_inputs in BENCH_CASES {
        group.bench_function(
            BenchmarkId::new("BLS12-381 multi_pairing", nr_of_inputs),
            |b| {
                b.iter(|| {
                    let p = p
                        .iter()
                        .take(nr_of_inputs)
                        .cloned()
                        .collect::<Vec<_>>();
                    let q = q
                        .iter()
                        .take(nr_of_inputs)
                        .cloned()
                        .collect::<Vec<_>>();
                    black_box(Bls12_381::multi_miller_loop(p, q))
                })
            },
        );
    }
}

pub fn bench_dummy(_c: &mut Criterion) {
    // Does nothing on purpose, but is required to make criterion happy.
}

criterion_group!(
    benches,
    // Using this dummy benchmark to make criterion happy.
    bench_dummy,
    // Disabling these benchmarks for now, as they are stable and we only ever run them locally.
    // bench_mul,
    // bench_into_affine,
    // bench_into_projective,
    // bench_prepare_gx,
    // bench_pow,
    // bench_miller_loop,
    // bench_final_exponentiation,
    // bench_pairing,
    // bench_product_of_pairings,
);

criterion_main!(benches);
