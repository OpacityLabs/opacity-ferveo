#![allow(clippy::redundant_closure)]

use ark_bls12_381::{Bls12_381, Fr};
use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use ferveo_tdec::{test_common::setup_simple, *};
use rand::prelude::StdRng;
use rand_core::{RngCore, SeedableRng};

const NUM_SHARES_CASES: [usize; 5] = [4, 8, 16, 32, 64];
const MSG_SIZE_CASES: [usize; 7] = [256, 512, 1024, 2048, 4096, 8192, 16384];

type E = Bls12_381;

#[allow(dead_code)]
#[derive(Clone)]
struct SetupShared {
    threshold: usize,
    shares_num: usize,
    msg: Vec<u8>,
    aad: Vec<u8>,
    pubkey: DkgPublicKey<E>,
    privkey: PrivateKeyShare<E>,
    ciphertext: Ciphertext<E>,
    shared_secret: SharedSecret<E>,
}

#[derive(Clone)]
struct SetupSimple {
    shared: SetupShared,
    contexts: Vec<PrivateDecryptionContextSimple<E>>,
    pub_contexts: Vec<PublicDecryptionContextSimple<E>>,
    decryption_shares: Vec<DecryptionShareSimple<E>>,
    lagrange_coeffs: Vec<Fr>,
}

impl SetupSimple {
    pub fn new(shares_num: usize, msg_size: usize, rng: &mut StdRng) -> Self {
        let threshold = shares_num * 2 / 3;
        let mut msg: Vec<u8> = vec![0u8; msg_size];
        rng.fill_bytes(&mut msg[..]);
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, privkey, contexts) =
            setup_simple::<E>(shares_num, threshold, rng);

        // Ciphertext.commitment is already computed to match U
        let ciphertext =
            encrypt::<E>(SecretBox::new(msg.clone()), aad, &pubkey, rng)
                .unwrap();

        // Creating decryption shares
        let decryption_shares: Vec<_> = contexts
            .iter()
            .map(|context| {
                context
                    .create_share(&ciphertext.header().unwrap(), aad)
                    .unwrap()
            })
            .collect();

        let pub_contexts = contexts[0].clone().public_decryption_contexts;
        let domain: Vec<Fr> = pub_contexts.iter().map(|c| c.domain).collect();
        let lagrange_coeffs = prepare_combine_simple::<E>(&domain);

        let shared_secret =
            share_combine_simple::<E>(&decryption_shares, &lagrange_coeffs);

        let shared = SetupShared {
            threshold,
            shares_num,
            msg: msg.to_vec(),
            aad: aad.to_vec(),
            pubkey,
            privkey,
            ciphertext,
            shared_secret,
        };
        Self {
            shared,
            contexts,
            pub_contexts,
            decryption_shares,
            lagrange_coeffs,
        }
    }
}

pub fn bench_create_decryption_share(c: &mut Criterion) {
    let rng = &mut StdRng::seed_from_u64(0);

    let mut group = c.benchmark_group("SHARE CREATE");
    group.sample_size(10);

    let msg_size = MSG_SIZE_CASES[0];

    for shares_num in NUM_SHARES_CASES {
        let simple = {
            let setup = SetupSimple::new(shares_num, msg_size, rng);
            move || {
                black_box({
                    // This way we could test the performance of this method for a single participant.
                    setup
                        .contexts
                        .iter()
                        .map(|ctx| {
                            // Using create_unchecked here to avoid the cost of verifying the ciphertext
                            DecryptionShareSimple::create_unchecked(
                                &ctx.setup_params.b,
                                &ctx.private_key_share,
                                &setup.shared.ciphertext.header().unwrap(),
                            )
                        })
                        .collect::<Vec<_>>()
                })
            }
        };
        let simple_precomputed = {
            let setup = SetupSimple::new(shares_num, MSG_SIZE_CASES[0], rng);
            let selected_participants = (0..shares_num).collect::<Vec<_>>();
            move || {
                black_box(
                    setup
                        .contexts
                        .iter()
                        .map(|context| {
                            context.create_share_precomputed(
                                &setup.shared.ciphertext.header().unwrap(),
                                &setup.shared.aad,
                                &selected_participants,
                            )
                        })
                        .collect::<Vec<_>>(),
                );
            }
        };
        group.bench_function(
            BenchmarkId::new("share_create_simple", shares_num),
            |b| b.iter(|| simple()),
        );
        group.bench_function(
            BenchmarkId::new("share_create_simple_precomputed", shares_num),
            |b| b.iter(|| simple_precomputed()),
        );
    }
}

pub fn bench_share_prepare(c: &mut Criterion) {
    let rng = &mut StdRng::seed_from_u64(0);

    let mut group = c.benchmark_group("SHARE PREPARE");
    group.sample_size(10);
    let msg_size = MSG_SIZE_CASES[0];

    for shares_num in NUM_SHARES_CASES {
        let simple = {
            let setup = SetupSimple::new(shares_num, msg_size, rng);
            let domain: Vec<Fr> =
                setup.pub_contexts.iter().map(|c| c.domain).collect();
            move || black_box(prepare_combine_simple::<E>(&domain))
        };
        group.bench_function(
            BenchmarkId::new("share_prepare_simple", shares_num),
            |b| b.iter(|| simple()),
        );
    }
}

pub fn bench_share_combine(c: &mut Criterion) {
    let rng = &mut StdRng::seed_from_u64(0);

    let mut group = c.benchmark_group("SHARE COMBINE");
    group.sample_size(10);

    let msg_size = MSG_SIZE_CASES[0];

    for shares_num in NUM_SHARES_CASES {
        let simple = {
            let setup = SetupSimple::new(shares_num, msg_size, rng);
            move || {
                black_box(share_combine_simple::<E>(
                    &setup.decryption_shares,
                    &setup.lagrange_coeffs,
                ));
            }
        };
        let simple_precomputed = {
            let setup = SetupSimple::new(shares_num, MSG_SIZE_CASES[0], rng);
            // TODO: Use threshold instead of shares_num
            let selected_participants = (0..shares_num).collect::<Vec<_>>();

            let decryption_shares: Vec<_> = setup
                .contexts
                .iter()
                .map(|context| {
                    context
                        .create_share_precomputed(
                            &setup.shared.ciphertext.header().unwrap(),
                            &setup.shared.aad,
                            &selected_participants,
                        )
                        .unwrap()
                })
                .collect();

            move || {
                black_box(share_combine_precomputed::<E>(&decryption_shares));
            }
        };

        group.bench_function(
            BenchmarkId::new("share_combine_simple", shares_num),
            |b| b.iter(|| simple()),
        );
        group.bench_function(
            BenchmarkId::new("share_combine_simple_precomputed", shares_num),
            |b| b.iter(|| simple_precomputed()),
        );
    }
}

pub fn bench_share_encrypt_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("ENCRYPT DECRYPT");
    group.sample_size(10);

    let rng = &mut StdRng::seed_from_u64(0);
    let shares_num = NUM_SHARES_CASES[0];

    for msg_size in MSG_SIZE_CASES {
        let mut encrypt = {
            let mut rng = rng.clone();
            let setup = SetupSimple::new(shares_num, msg_size, &mut rng);
            move || {
                let setup = setup.clone();
                black_box(
                    encrypt::<E>(
                        SecretBox::new(setup.shared.msg),
                        &setup.shared.aad,
                        &setup.shared.pubkey,
                        &mut rng,
                    )
                    .unwrap(),
                );
            }
        };
        let decrypt = {
            let setup = SetupSimple::new(shares_num, msg_size, rng);
            move || {
                black_box(
                    decrypt_with_shared_secret::<E>(
                        &setup.shared.ciphertext,
                        &setup.shared.aad,
                        &setup.shared.shared_secret,
                    )
                    .unwrap(),
                );
            }
        };

        group.bench_function(BenchmarkId::new("encrypt", msg_size), |b| {
            b.iter(|| encrypt())
        });
        group.bench_function(BenchmarkId::new("decrypt", msg_size), |b| {
            b.iter(|| decrypt())
        });
    }
}

pub fn bench_ciphertext_validity_checks(c: &mut Criterion) {
    let mut group = c.benchmark_group("CIPHERTEXT VERIFICATION");
    group.sample_size(10);

    let rng = &mut StdRng::seed_from_u64(0);
    let shares_num = NUM_SHARES_CASES[0];

    for msg_size in MSG_SIZE_CASES {
        let ciphertext_verification = {
            let mut rng = rng.clone();
            let setup = SetupSimple::new(shares_num, msg_size, &mut rng);
            move || {
                black_box(setup.shared.ciphertext.check(&setup.shared.aad))
                    .unwrap();
            }
        };
        group.bench_function(
            BenchmarkId::new("ciphertext_verification", msg_size),
            |b| b.iter(|| ciphertext_verification()),
        );
    }
}

pub fn bench_decryption_share_validity_checks(c: &mut Criterion) {
    let mut group = c.benchmark_group("DECRYPTION SHARE VERIFICATION");
    group.sample_size(10);

    let rng = &mut StdRng::seed_from_u64(0);
    let msg_size = MSG_SIZE_CASES[0];

    for shares_num in NUM_SHARES_CASES {
        let share_simple_verification = {
            let mut rng = rng.clone();
            let setup = SetupSimple::new(shares_num, msg_size, &mut rng);
            move || {
                black_box(verify_decryption_shares_simple(
                    &setup.pub_contexts,
                    &setup.shared.ciphertext,
                    &setup.decryption_shares,
                ))
            }
        };
        group.bench_function(
            BenchmarkId::new("share_simple_verification", shares_num),
            |b| b.iter(|| share_simple_verification()),
        );
    }
}

criterion_group!(
    benches,
    bench_create_decryption_share,
    bench_share_prepare,
    bench_share_combine,
    bench_share_encrypt_decrypt,
    bench_ciphertext_validity_checks,
    bench_decryption_share_validity_checks,
);

criterion_main!(benches);
