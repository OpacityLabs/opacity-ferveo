//! Regression tests for degenerate (all-identity) input rejection.
//!
//! Identity points pass pairing-based validity checks vacuously — e(𝒪, ·) = 1
//! on both sides — so every such check must reject them explicitly. Honest
//! parties produce identity points only with negligible probability, so none
//! of these rejections can refuse legitimate input. See
//! `docs/security-notes.md` §2.

use ark_bls12_381::{G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ferveo::{
    api::{
        encrypt, AggregatedTranscript, Ciphertext, Dkg, SecretBox, Validator,
        ValidatorKeypair, ValidatorMessage,
    },
    Error, EthereumAddress,
};
use ferveo_common::serialization::{FromBytes, ToBytes};
use rand::SeedableRng;
use rand_core::RngCore;
use std::str::FromStr;

const TAU: u32 = 0;
const SHARES_NUM: u32 = 4;
const THRESHOLD: u32 = 3;
const AAD: &[u8] = b"degenerate-inputs-aad";

fn setup(
    rng: &mut impl RngCore,
) -> (Vec<ValidatorKeypair>, Vec<Validator>, Vec<ValidatorMessage>) {
    let keypairs: Vec<ValidatorKeypair> = (0..SHARES_NUM)
        .map(|_| ValidatorKeypair::new(rng))
        .collect();
    let validators: Vec<Validator> = keypairs
        .iter()
        .enumerate()
        .map(|(i, kp)| Validator {
            address: EthereumAddress::from_str(&format!("0x{i:040}")).unwrap(),
            public_key: kp.public_key(),
            share_index: i as u32,
        })
        .collect();
    let messages: Vec<ValidatorMessage> = validators
        .iter()
        .map(|me| {
            let mut dkg =
                Dkg::new(TAU, SHARES_NUM, THRESHOLD, &validators, me).unwrap();
            (me.clone(), dkg.generate_transcript(rng).unwrap())
        })
        .collect();
    (keypairs, validators, messages)
}

/// An aggregate whose commitments, shares and σ are all the identity used to
/// verify against an empty message set (every check vacuously true) and
/// yielded the identity as the DKG public key. It must now fail: the empty
/// message set is rejected outright, and against real messages the identity
/// constant term fails the proof-of-knowledge check.
#[test]
fn all_identity_aggregate_is_rejected() {
    let rng = &mut rand::rngs::StdRng::seed_from_u64(0);
    let (_, validators, messages) = setup(rng);
    let dkg = Dkg::new(TAU, SHARES_NUM, THRESHOLD, &validators, &validators[0])
        .unwrap();
    let aggregate = dkg.aggregate_transcripts(&messages).unwrap();

    // Positive control: the honest aggregate verifies.
    assert!(aggregate.verify(SHARES_NUM, THRESHOLD, &messages).is_ok());

    let mut inner: ferveo::AggregatedTranscript<ferveo::api::E> =
        bincode::deserialize(&aggregate.to_bytes().unwrap()).unwrap();
    inner.aggregate.coeffs = vec![G1Affine::zero(); THRESHOLD as usize];
    inner.aggregate.shares.clear();
    inner.aggregate.sigma = G2Affine::zero();
    inner.public_key = ferveo_tdec::DkgPublicKey(G1Affine::zero());
    let degenerate =
        AggregatedTranscript::from_bytes(&bincode::serialize(&inner).unwrap())
            .expect("degenerate aggregate should still deserialize");

    assert!(
        matches!(
            degenerate.verify(SHARES_NUM, THRESHOLD, &[]),
            Err(Error::NoTranscriptsToVerify)
        ),
        "an empty message set must be rejected, not verified vacuously"
    );
    assert!(
        matches!(
            degenerate.verify(SHARES_NUM, THRESHOLD, &messages),
            Err(Error::InvalidTranscriptAggregate)
        ),
        "an identity constant term must fail the proof-of-knowledge check"
    );
}

/// A dealer transcript whose constant term is the identity satisfies the σ
/// pairing check vacuously; per-dealer verification must reject it.
#[test]
fn identity_constant_term_transcript_is_rejected() {
    let rng = &mut rand::rngs::StdRng::seed_from_u64(1);
    let (_, validators, mut messages) = setup(rng);
    let dkg = Dkg::new(TAU, SHARES_NUM, THRESHOLD, &validators, &validators[0])
        .unwrap();

    messages[1].1.coeffs[0] = G1Affine::zero();
    messages[1].1.sigma = G2Affine::zero();
    assert!(
        matches!(
            dkg.aggregate_transcripts(&messages),
            Err(Error::InvalidPvssTranscript(_))
        ),
        "an identity-F₀ dealer transcript must be rejected"
    );
}

/// A ciphertext whose commitment U and auth tag W are both the identity used
/// to pass the §4.4.2 validity gate for any AAD and any ciphertext hash. The
/// gate must now reject it, and no decryption share may be produced.
#[test]
fn all_identity_ciphertext_header_is_rejected() {
    let rng = &mut rand::rngs::StdRng::seed_from_u64(2);
    let (keypairs, validators, messages) = setup(rng);
    let dkg = Dkg::new(TAU, SHARES_NUM, THRESHOLD, &validators, &validators[0])
        .unwrap();
    let aggregate = dkg.aggregate_transcripts(&messages).unwrap();
    let ciphertext = encrypt(
        SecretBox::new(b"the actual message".to_vec()),
        AAD,
        &aggregate.public_key(),
    )
    .unwrap();

    // Positive control: the honest header passes its validity check.
    let honest: ferveo_tdec::Ciphertext<ferveo::api::E> =
        bincode::deserialize(&ciphertext.to_bytes().unwrap()).unwrap();
    assert!(honest.header().unwrap().check(AAD).unwrap());

    let mut zeroed = honest;
    zeroed.commitment = G1Affine::zero();
    zeroed.auth_tag = G2Affine::zero();
    // The gate must fail under the original AAD and any other alike.
    assert!(zeroed.header().unwrap().check(AAD).is_err());
    assert!(zeroed.header().unwrap().check(b"unrelated-aad").is_err());

    let zeroed_api =
        Ciphertext::from_bytes(&bincode::serialize(&zeroed).unwrap())
            .expect("zeroed ciphertext should still deserialize");
    assert!(
        aggregate
            .create_decryption_share_simple(
                &dkg,
                &zeroed_api.header().unwrap(),
                AAD,
                &keypairs[0],
            )
            .is_err(),
        "no decryption share may be produced for an all-identity header"
    );
}
