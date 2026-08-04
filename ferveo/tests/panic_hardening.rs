//! Regression tests for denial-of-service hardening on the active path.
//!
//! Every case here feeds peer-supplied data (deserialized transcripts,
//! aggregates and ciphertext headers) into the public `ferveo::api` surface that
//! opacity-stack calls. Before hardening, each one panicked — an unauthenticated
//! peer could crash a node by sending a malformed message. They must return
//! `Err` instead.

use ferveo::{
    api::{
        AggregatedTranscript, Dkg, DkgPublicKey, Validator, ValidatorKeypair,
        ValidatorMessage,
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
const AAD: &[u8] = b"panic-hardening-aad";

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

/// A peer transcript whose commitment vector is empty must be rejected by
/// aggregation, not panic while summing coefficients.
#[test]
fn empty_coeffs_transcript_is_rejected_by_aggregation() {
    let rng = &mut rand::rngs::StdRng::seed_from_u64(0);
    let (_, validators, mut messages) = setup(rng);
    let dkg = Dkg::new(TAU, SHARES_NUM, THRESHOLD, &validators, &validators[0])
        .unwrap();

    messages[1].1.coeffs.clear();
    // Rejected per-dealer by verify_transcripts (verify_optimistic returns
    // false for an empty commitment vector) before aggregation is reached.
    assert!(
        matches!(
            dkg.aggregate_transcripts(&messages),
            Err(Error::InvalidPvssTranscript(_))
        ),
        "empty-coeffs transcript must be rejected with a specific error"
    );
}

/// A peer transcript with a *shortened* commitment vector must be rejected too:
/// aggregation zips coefficient vectors and previously panicked on mismatch.
#[test]
fn mismatched_coeffs_length_is_rejected_by_aggregation() {
    let rng = &mut rand::rngs::StdRng::seed_from_u64(1);
    let (_, validators, mut messages) = setup(rng);
    let dkg = Dkg::new(TAU, SHARES_NUM, THRESHOLD, &validators, &validators[0])
        .unwrap();

    messages[1].1.coeffs.pop();
    assert!(
        matches!(
            dkg.aggregate_transcripts(&messages),
            Err(Error::MismatchedTranscriptLengths("coefficients", _, _))
        ),
        "coeff-length mismatch must name the mismatched field"
    );
}

/// Likewise for the share vector.
#[test]
fn mismatched_shares_length_is_rejected_by_aggregation() {
    let rng = &mut rand::rngs::StdRng::seed_from_u64(2);
    let (_, validators, mut messages) = setup(rng);
    let dkg = Dkg::new(TAU, SHARES_NUM, THRESHOLD, &validators, &validators[0])
        .unwrap();

    messages[1].1.shares.pop();
    assert!(
        matches!(
            dkg.aggregate_transcripts(&messages),
            Err(Error::MismatchedTranscriptLengths("shares", _, _))
        ),
        "share-length mismatch must name the mismatched field"
    );
}

/// `AggregatedTranscript::new` aggregates caller-supplied transcripts without a
/// prior DKG check; it must also reject malformed input rather than panic.
#[test]
fn aggregated_transcript_new_rejects_malformed_transcripts() {
    let rng = &mut rand::rngs::StdRng::seed_from_u64(3);
    let (_, _, mut messages) = setup(rng);

    messages[1].1.coeffs.pop();
    assert!(
        matches!(
            AggregatedTranscript::new(&messages),
            Err(Error::MismatchedTranscriptLengths("coefficients", _, _))
        ),
        "malformed transcript must be an error, not a panic"
    );
}

/// An aggregate deserialized with an empty commitment vector must be rejected
/// by verification, not panic indexing `coeffs[0]`.
#[test]
fn empty_coeffs_aggregate_is_rejected_by_verify() {
    let rng = &mut rand::rngs::StdRng::seed_from_u64(4);
    let (_, validators, messages) = setup(rng);
    let dkg = Dkg::new(TAU, SHARES_NUM, THRESHOLD, &validators, &validators[0])
        .unwrap();
    let aggregate = dkg.aggregate_transcripts(&messages).unwrap();

    // Round-trip through the wire format, emptying the coefficients the way a
    // hostile peer would.
    let mut inner: ferveo::AggregatedTranscript<ferveo::api::E> =
        bincode::deserialize(&aggregate.to_bytes().unwrap()).unwrap();
    inner.aggregate.coeffs.clear();
    let tampered_bytes = bincode::serialize(&inner).unwrap();

    // Deserialization must succeed for this test to mean anything: the point is
    // that *verification* rejects the tampered aggregate. If a future change
    // makes from_bytes reject it, this assertion fails loudly rather than
    // letting the test pass vacuously.
    let tampered = AggregatedTranscript::from_bytes(&tampered_bytes)
        .expect("tampered aggregate should still deserialize");
    assert!(
        tampered.verify(SHARES_NUM, THRESHOLD, &messages).is_err(),
        "empty-coeffs aggregate must be an error, not a panic"
    );
}

/// The `EmptyTranscript` guard inside `do_verify_aggregation` is only reached
/// when a *peer message* carries no commitments — `verify_optimistic` rejects a
/// malformed aggregate earlier, so this needs its own input.
#[test]
fn empty_coeffs_peer_message_is_rejected_by_verify() {
    let rng = &mut rand::rngs::StdRng::seed_from_u64(10);
    let (_, validators, messages) = setup(rng);
    let dkg = Dkg::new(TAU, SHARES_NUM, THRESHOLD, &validators, &validators[0])
        .unwrap();
    let aggregate = dkg.aggregate_transcripts(&messages).unwrap();

    let mut tampered = messages.clone();
    tampered[1].1.coeffs.clear();
    assert!(
        matches!(
            aggregate.verify(SHARES_NUM, THRESHOLD, &tampered),
            Err(Error::EmptyTranscript)
        ),
        "a peer message with no commitments must hit the EmptyTranscript guard"
    );
}

/// `from_aggregate` derives the DKG public key from the aggregate's constant
/// term. If every transcript is empty the lengths still agree, so aggregation
/// proceeds and the guard in `from_aggregate` is what must catch it.
#[test]
fn all_empty_transcripts_are_rejected_by_from_aggregate() {
    let rng = &mut rand::rngs::StdRng::seed_from_u64(11);
    let (_, _, mut messages) = setup(rng);

    for m in messages.iter_mut() {
        m.1.coeffs.clear();
    }
    assert!(
        matches!(
            AggregatedTranscript::new(&messages),
            Err(Error::EmptyTranscript)
        ),
        "uniformly empty transcripts must hit the from_aggregate guard"
    );
}

/// A decryption share must not be produced for a ciphertext header that fails
/// verification: the node returns an error instead of crashing.
#[test]
fn tampered_ciphertext_header_is_rejected_by_decryption_share() {
    let rng = &mut rand::rngs::StdRng::seed_from_u64(5);
    let (keypairs, validators, messages) = setup(rng);
    let dkg = Dkg::new(TAU, SHARES_NUM, THRESHOLD, &validators, &validators[0])
        .unwrap();
    let aggregate = dkg.aggregate_transcripts(&messages).unwrap();

    let pk: DkgPublicKey = aggregate.public_key();
    let ciphertext = ferveo::api::encrypt(
        ferveo::api::SecretBox::new(b"msg".to_vec()),
        AAD,
        &pk,
    )
    .unwrap();

    // Associated data that does not match the ciphertext makes the header fail
    // its validity check — the same outcome as a forged or corrupted header.
    assert!(
        aggregate
            .create_decryption_share_simple(
                &dkg,
                &ciphertext.header().unwrap(),
                b"wrong-aad",
                &keypairs[0],
            )
            .is_err(),
        "unverifiable ciphertext header must be an error, not a panic"
    );
}

/// Share indices address the evaluation domain positionally, so an
/// out-of-range index must be rejected at construction rather than panicking
/// later while indexing polynomial evaluations.
#[test]
fn out_of_range_share_index_is_rejected_at_dkg_construction() {
    let rng = &mut rand::rngs::StdRng::seed_from_u64(8);
    let (_, validators, _) = setup(rng);

    let mut bad = validators.clone();
    bad[1].share_index = 99;
    assert!(
        matches!(
            Dkg::new(TAU, SHARES_NUM, THRESHOLD, &bad, &bad[0]),
            Err(Error::InvalidShareIndex(99))
        ),
        "out-of-range share index must be an error, not a later panic"
    );
}

/// Reordering share indices is legitimate (they are a permutation of the
/// domain positions) and must keep working — the range check above must not
/// reject valid configurations.
#[test]
fn permuted_share_indices_are_still_accepted() {
    let rng = &mut rand::rngs::StdRng::seed_from_u64(9);
    let (_, validators, _) = setup(rng);

    let mut swapped = validators.clone();
    swapped[0].share_index = 1;
    swapped[1].share_index = 0;
    assert!(
        Dkg::new(TAU, SHARES_NUM, THRESHOLD, &swapped, &swapped[0]).is_ok(),
        "a permutation of share indices must remain valid"
    );
}

/// A truncated aggregate (fewer shares than validators) must not panic when a
/// validator looks up its own share.
#[test]
fn truncated_aggregate_share_lookup_is_rejected() {
    let rng = &mut rand::rngs::StdRng::seed_from_u64(7);
    let (keypairs, validators, messages) = setup(rng);
    let dkg = Dkg::new(TAU, SHARES_NUM, THRESHOLD, &validators, &validators[3])
        .unwrap();
    let aggregate = dkg.aggregate_transcripts(&messages).unwrap();
    let ciphertext = ferveo::api::encrypt(
        ferveo::api::SecretBox::new(b"msg".to_vec()),
        AAD,
        &aggregate.public_key(),
    )
    .unwrap();

    // Drop shares so validator 3's index is out of range.
    let mut inner: ferveo::AggregatedTranscript<ferveo::api::E> =
        bincode::deserialize(&aggregate.to_bytes().unwrap()).unwrap();
    inner.aggregate.shares.truncate(1);
    let tampered_bytes = bincode::serialize(&inner).unwrap();

    let tampered = AggregatedTranscript::from_bytes(&tampered_bytes)
        .expect("truncated aggregate should still deserialize");
    assert!(
        matches!(
            tampered.create_decryption_share_simple(
                &dkg,
                &ciphertext.header().unwrap(),
                AAD,
                &keypairs[3],
            ),
            Err(Error::InvalidShareIndex(3))
        ),
        "out-of-range share index must be an error, not a panic"
    );

    // The precomputed variant removed three panics of its own and needs the
    // same coverage.
    assert!(
        tampered
            .create_decryption_share_precomputed(
                &dkg,
                &ciphertext.header().unwrap(),
                AAD,
                &keypairs[3],
                &validators,
            )
            .is_err(),
        "precomputed variant must reject an out-of-range share index"
    );
}

/// `DkgParams` derives `Deserialize`, which rebuilds it field by field and so
/// bypasses the validity check in `DkgParams::new`. A zero security threshold
/// then underflows `security_threshold - 1`, which in release builds wraps to
/// `u32::MAX` and aborts the process in the allocator — an abort, not a
/// catchable panic. `PubliclyVerifiableDkg::new` must re-validate.
#[test]
fn deserialized_dkg_params_are_revalidated() {
    let rng = &mut rand::rngs::StdRng::seed_from_u64(13);
    let (_, validators, _) = setup(rng);

    // tau = 0, security_threshold = 0, shares_num = 4 (bincode: three fixint LE u32).
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0u32.to_le_bytes()); // tau
    bytes.extend_from_slice(&0u32.to_le_bytes()); // security_threshold
    bytes.extend_from_slice(&SHARES_NUM.to_le_bytes()); // shares_num
    let params: ferveo::DkgParams = bincode::deserialize(&bytes)
        .expect("DkgParams deserializes without validation");

    // The constructor would have rejected these parameters outright.
    assert!(ferveo::DkgParams::new(0, 0, SHARES_NUM).is_err());

    assert!(
        matches!(
            ferveo::PubliclyVerifiableDkg::<ferveo::api::E>::new(
                &validators,
                &params,
                &validators[0],
            ),
            Err(Error::InvalidDkgParameters(_, 0))
        ),
        "a deserialized DkgParams with threshold 0 must be rejected, not abort \
         the process later"
    );
}

/// A zero decryption key has no inverse; unblinding must return an error rather
/// than panicking inside ferveo-tdec.
#[test]
fn non_invertible_decryption_key_is_rejected() {
    let rng = &mut rand::rngs::StdRng::seed_from_u64(12);
    let (_, validators, messages) = setup(rng);
    let dkg = Dkg::new(TAU, SHARES_NUM, THRESHOLD, &validators, &validators[0])
        .unwrap();
    let aggregate = dkg.aggregate_transcripts(&messages).unwrap();
    let ciphertext = ferveo::api::encrypt(
        ferveo::api::SecretBox::new(b"msg".to_vec()),
        AAD,
        &aggregate.public_key(),
    )
    .unwrap();

    let zero_keypair = ValidatorKeypair {
        decryption_key: ferveo::api::Fr::from(0u64),
    };
    assert!(
        aggregate
            .create_decryption_share_simple(
                &dkg,
                &ciphertext.header().unwrap(),
                AAD,
                &zero_keypair,
            )
            .is_err(),
        "a non-invertible decryption key must be an error, not a panic"
    );
}
