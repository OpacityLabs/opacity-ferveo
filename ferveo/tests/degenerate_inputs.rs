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
        encrypt, to_bytes, AggregatedTranscript, Ciphertext, Dkg, DkgPublicKey,
        SecretBox, Validator, ValidatorKeypair, ValidatorMessage,
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

    // Positive control: the unmutated message set aggregates.
    assert!(dkg.aggregate_transcripts(&messages).is_ok());

    messages[1].1.coeffs[0] = G1Affine::zero();
    messages[1].1.sigma = G2Affine::zero();
    assert!(
        matches!(
            dkg.aggregate_transcripts(&messages),
            Err(Error::InvalidPvssTranscript(addr))
                if addr == validators[1].address
        ),
        "the identity-F₀ dealer transcript must be rejected, blaming dealer 1"
    );
}

/// The aggregate's public key travels as its own serialized field, bound to
/// the committed polynomial only at construction. `verify` must reject an
/// aggregate whose `public_key` field disagrees with the constant term F₀ —
/// whether swapped to the identity or to any other point.
#[test]
fn tampered_aggregate_public_key_is_rejected() {
    let rng = &mut rand::rngs::StdRng::seed_from_u64(3);
    let (_, validators, messages) = setup(rng);
    let dkg = Dkg::new(TAU, SHARES_NUM, THRESHOLD, &validators, &validators[0])
        .unwrap();
    let aggregate = dkg.aggregate_transcripts(&messages).unwrap();

    // Positive control: the honest aggregate verifies.
    assert!(aggregate.verify(SHARES_NUM, THRESHOLD, &messages).is_ok());

    let mut inner: ferveo::AggregatedTranscript<ferveo::api::E> =
        bincode::deserialize(&aggregate.to_bytes().unwrap()).unwrap();
    for wrong_point in [G1Affine::zero(), G1Affine::generator()] {
        inner.public_key = ferveo_tdec::DkgPublicKey(wrong_point);
        let tampered = AggregatedTranscript::from_bytes(
            &bincode::serialize(&inner).unwrap(),
        )
        .expect("tampered aggregate should still deserialize");
        assert!(
            matches!(
                tampered.verify(SHARES_NUM, THRESHOLD, &messages),
                Err(Error::InvalidAggregatePublicKey)
            ),
            "a public_key field disagreeing with F₀ must be rejected"
        );
    }
}

/// Identity dealer transcripts contribute nothing to the aggregation sum, so
/// they could pad a dealer set: an aggregate produced by a single dealer would
/// verify as one produced by many, though that dealer alone knows the secret.
/// Every dealer transcript must therefore be verified in its own right.
#[test]
fn identity_transcripts_cannot_pad_the_dealer_set() {
    let rng = &mut rand::rngs::StdRng::seed_from_u64(4);
    let (_, validators, messages) = setup(rng);
    let dkg = Dkg::new(TAU, SHARES_NUM, THRESHOLD, &validators, &validators[0])
        .unwrap();

    // An aggregate over a single dealer, verified against its own message set.
    let aggregate = dkg.aggregate_transcripts(&messages[..1]).unwrap();
    assert!(aggregate
        .verify(SHARES_NUM, THRESHOLD, &messages[..1])
        .is_ok());

    // The same aggregate, presented as if all four validators had dealt.
    let mut padded = messages;
    for message in padded.iter_mut().skip(1) {
        message.1.coeffs = vec![G1Affine::zero(); THRESHOLD as usize];
        message.1.shares = vec![G2Affine::zero(); SHARES_NUM as usize];
        message.1.sigma = G2Affine::zero();
    }
    assert!(
        matches!(
            aggregate.verify(SHARES_NUM, THRESHOLD, &padded),
            Err(Error::InvalidTranscriptAggregate)
        ),
        "identity transcripts must not pad a single-dealer aggregate into a \
         four-dealer one"
    );
}

/// Trailing identity coefficients pad a lower-degree polynomial out to the
/// expected coefficient count, lowering the effective threshold: a constant
/// polynomial gives every validator the same share, so any single share
/// reconstructs the secret while verification still reports the threshold.
#[test]
fn trailing_identity_coefficients_are_rejected() {
    let rng = &mut rand::rngs::StdRng::seed_from_u64(5);
    let (_, validators, messages) = setup(rng);
    let dkg = Dkg::new(TAU, SHARES_NUM, THRESHOLD, &validators, &validators[0])
        .unwrap();
    let aggregate = dkg.aggregate_transcripts(&messages).unwrap();

    // Positive control: the honest aggregate has a full-degree commitment.
    assert!(aggregate.verify(SHARES_NUM, THRESHOLD, &messages).is_ok());

    let mut inner: ferveo::AggregatedTranscript<ferveo::api::E> =
        bincode::deserialize(&aggregate.to_bytes().unwrap()).unwrap();
    // Zero the leading coefficient: still THRESHOLD entries, but the committed
    // polynomial now has degree THRESHOLD - 2.
    *inner.aggregate.coeffs.last_mut().unwrap() = G1Affine::zero();
    let padded =
        AggregatedTranscript::from_bytes(&bincode::serialize(&inner).unwrap())
            .expect("padded aggregate should still deserialize");
    assert!(
        matches!(
            padded.verify(SHARES_NUM, THRESHOLD, &messages),
            Err(Error::InvalidTranscriptDegree(THRESHOLD, got))
                if got == THRESHOLD - 1
        ),
        "a commitment padded with trailing identity coefficients must be \
         rejected as the lower degree it actually pins"
    );
}

/// The 48-byte compressed encoding of the identity G1 point deserializes as a
/// legitimate subgroup member, but as a DKG public key it makes every
/// encryption's shared secret a public constant — silent, total
/// confidentiality loss. `from_bytes` must reject it; in-protocol an identity
/// F₀ is already rejected during verification, so this closes the
/// out-of-band-bytes path.
#[test]
fn identity_dkg_public_key_bytes_are_rejected() {
    let rng = &mut rand::rngs::StdRng::seed_from_u64(6);
    let (_, validators, messages) = setup(rng);
    let dkg = Dkg::new(TAU, SHARES_NUM, THRESHOLD, &validators, &validators[0])
        .unwrap();
    let aggregate = dkg.aggregate_transcripts(&messages).unwrap();

    // Positive control: an honest public key round-trips through bytes.
    let honest = aggregate.public_key();
    let honest_bytes = honest.to_bytes().unwrap();
    assert_eq!(DkgPublicKey::from_bytes(&honest_bytes).unwrap(), honest);

    let identity_bytes = to_bytes(&G1Affine::zero()).unwrap();
    assert_eq!(identity_bytes.len(), DkgPublicKey::serialized_size());
    assert!(
        matches!(
            DkgPublicKey::from_bytes(&identity_bytes),
            Err(Error::IdentityDkgPublicKey)
        ),
        "the identity G1 encoding must be rejected as a DKG public key"
    );
}

/// `api::DkgPublicKey` derives serde `Deserialize`, so an identity public key
/// can enter via bincode without ever passing `from_bytes`. `encrypt` is the
/// last line of defense: encrypting to the identity makes the shared secret
/// the identity of the target group, so the derived AEAD key is a public
/// constant.
#[test]
fn encrypt_to_identity_dkg_public_key_is_rejected() {
    let rng = &mut rand::rngs::StdRng::seed_from_u64(7);
    let (_, validators, messages) = setup(rng);
    let dkg = Dkg::new(TAU, SHARES_NUM, THRESHOLD, &validators, &validators[0])
        .unwrap();
    let aggregate = dkg.aggregate_transcripts(&messages).unwrap();

    // Positive control: encryption to the honest public key succeeds.
    assert!(encrypt(
        SecretBox::new(b"the actual message".to_vec()),
        AAD,
        &aggregate.public_key(),
    )
    .is_ok());

    let identity_inner: ferveo_tdec::DkgPublicKey<ferveo::api::E> =
        ferveo_tdec::DkgPublicKey(G1Affine::zero());
    let smuggled: DkgPublicKey =
        bincode::deserialize(&bincode::serialize(&identity_inner).unwrap())
            .expect("the identity public key should still deserialize");
    assert!(
        matches!(
            encrypt(
                SecretBox::new(b"the actual message".to_vec()),
                AAD,
                &smuggled,
            ),
            Err(Error::ThresholdEncryptionError(
                ferveo_tdec::Error::IdentityDkgPublicKey
            ))
        ),
        "encrypt must reject the identity DKG public key"
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
    assert!(matches!(
        zeroed.header().unwrap().check(AAD),
        Err(ferveo_tdec::Error::CiphertextVerificationFailed)
    ));
    assert!(matches!(
        zeroed.header().unwrap().check(b"unrelated-aad"),
        Err(ferveo_tdec::Error::CiphertextVerificationFailed)
    ));

    // Positive control: the honest header yields a decryption share.
    assert!(aggregate
        .create_decryption_share_simple(
            &dkg,
            &ciphertext.header().unwrap(),
            AAD,
            &keypairs[0],
        )
        .is_ok());

    let zeroed_api =
        Ciphertext::from_bytes(&bincode::serialize(&zeroed).unwrap())
            .expect("zeroed ciphertext should still deserialize");
    assert!(
        matches!(
            aggregate.create_decryption_share_simple(
                &dkg,
                &zeroed_api.header().unwrap(),
                AAD,
                &keypairs[0],
            ),
            Err(Error::ThresholdEncryptionError(
                ferveo_tdec::Error::CiphertextVerificationFailed
            ))
        ),
        "no decryption share may be produced for an all-identity header"
    );
}
