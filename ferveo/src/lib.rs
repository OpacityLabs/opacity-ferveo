#![warn(rust_2018_idioms)]

pub mod api;
pub mod dkg;
pub mod primitives;
pub mod pvss;
#[cfg(feature = "experimental-refresh")]
pub mod refresh;
pub mod validator;

#[cfg(test)]
mod test_common;

pub use dkg::*;
pub use primitives::*;
pub use pvss::*;
#[cfg(feature = "experimental-refresh")]
pub use refresh::*;
pub use validator::*;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    ThresholdEncryptionError(#[from] ferveo_tdec::Error),

    /// DKG validator set must contain the validator with the given address
    #[error("Expected validator to be a part of the DKG validator set: {0}")]
    DealerNotInValidatorSet(EthereumAddress),

    /// DKG received an unknown dealer. Dealer must be the part of the DKG validator set.
    #[error("DKG received an unknown dealer: {0}")]
    UnknownDealer(EthereumAddress),

    /// DKG received a PVSS transcript from a dealer that has already been dealt.
    #[error("DKG received a PVSS transcript from a dealer that has already been dealt: {0}")]
    DuplicateDealer(EthereumAddress),

    /// DKG received an invalid transcript for which optimistic verification failed
    #[error("DKG received an invalid transcript from validator: {0}")]
    InvalidPvssTranscript(EthereumAddress),

    /// Not enough validators to perform the DKG for a given number of shares
    #[error("Not enough validators (expected {0}, got {1})")]
    InsufficientValidators(u32, u32),

    /// Transcript aggregate doesn't match the received PVSS instances
    #[error("Transcript aggregate doesn't match the received PVSS instances")]
    InvalidTranscriptAggregate,

    /// A transcript or aggregate commits to a polynomial of the wrong degree
    /// for the security threshold (expected `threshold` coefficients)
    #[error("Invalid transcript degree: expected {0} coefficients (security threshold), got {1}")]
    InvalidTranscriptDegree(u32, u32),

    /// The validator public key doesn't match the one in the DKG
    #[error("Validator public key mismatch")]
    ValidatorPublicKeyMismatch,

    #[error(transparent)]
    BincodeError(#[from] bincode::Error),

    #[error(transparent)]
    ArkSerializeError(#[from] ark_serialize::SerializationError),

    /// Invalid byte length
    #[error("Invalid byte length. Expected {0}, got {1}")]
    InvalidByteLength(usize, usize),

    /// Invalid variant
    #[error("Invalid variant: {0}")]
    InvalidVariant(String),

    /// DKG parameters validation failed
    #[error("Invalid DKG parameters: number of shares {0}, threshold {1}")]
    InvalidDkgParameters(u32, u32),

    /// Failed to access a share for a given share index
    #[error("Invalid share index: {0}")]
    InvalidShareIndex(u32),

    /// Failed to verify a share update
    #[error("Invalid share update")]
    InvalidShareUpdate,

    /// Failed to produce a precomputed variant decryption share
    #[error("Invalid DKG parameters for precomputed variant: number of shares {0}, threshold {1}")]
    InvalidDkgParametersForPrecomputedVariant(u32, u32),

    /// DKG may not contain duplicated share indices
    #[error("Duplicated share index: {0}")]
    DuplicatedShareIndex(u32),

    /// Creating a transcript aggregate requires at least one transcript
    #[error("No transcripts to aggregate")]
    NoTranscriptsToAggregate,

    /// The number of messages may not be greater than the number of validators
    #[error("Invalid aggregate verification parameters: number of validators {0}, number of messages: {1}")]
    InvalidAggregateVerificationParameters(u32, u32),

    /// Too many transcripts received by the DKG
    #[error("Too many transcripts. Expected: {0}, got: {1}")]
    TooManyTranscripts(u32, u32),

    /// Received a duplicated transcript from a validator
    #[error("Received a duplicated transcript from validator: {0}")]
    DuplicateTranscript(EthereumAddress),
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod test_dkg_full {
    use std::collections::HashMap;

    use ark_bls12_381::{Bls12_381 as E, G1Affine};
    use ark_ec::AffineRepr;
    #[cfg(feature = "experimental-refresh")]
    use ark_ec::CurveGroup;
    use ark_ff::Zero;
    use ark_std::test_rng;
    use ferveo_common::Keypair;
    #[cfg(feature = "experimental-refresh")]
    use ferveo_tdec::ShareCommitment;
    use ferveo_tdec::{
        self, DecryptionSharePrecomputed, DecryptionShareSimple, SecretBox,
        SharedSecret,
    };
    use itertools::izip;
    use rand::seq::SliceRandom;
    #[cfg(feature = "experimental-refresh")]
    use rand::Rng;
    use test_case::test_case;

    use super::*;
    use crate::test_common::*;

    pub fn create_shared_secret_simple_tdec(
        dkg: &PubliclyVerifiableDkg<E>,
        aad: &[u8],
        ciphertext_header: &ferveo_tdec::CiphertextHeader<E>,
        validator_keypairs: &[Keypair<E>],
        transcripts: &[PubliclyVerifiableSS<E>],
    ) -> (
        AggregatedTranscript<E>,
        Vec<DecryptionShareSimple<E>>,
        SharedSecret<E>,
    ) {
        let server_aggregate =
            AggregatedTranscript::from_transcripts(transcripts).unwrap();
        assert!(server_aggregate
            .aggregate
            .verify_aggregation(dkg, transcripts)
            .unwrap());

        let decryption_shares: Vec<DecryptionShareSimple<E>> =
            validator_keypairs
                .iter()
                .map(|validator_keypair| {
                    let validator = dkg
                        .get_validator(&validator_keypair.public_key())
                        .unwrap();
                    server_aggregate
                        .aggregate
                        .create_decryption_share_simple(
                            ciphertext_header,
                            aad,
                            validator_keypair,
                            validator.share_index,
                        )
                        .unwrap()
                })
                // We take only the first `security_threshold` decryption shares
                .take(dkg.dkg_params.security_threshold() as usize)
                .collect();

        let domain_points = &dkg.domain_points()[..decryption_shares.len()];
        assert_eq!(domain_points.len(), decryption_shares.len());

        let lagrange_coeffs =
            ferveo_tdec::prepare_combine_simple::<E>(domain_points);
        let shared_secret = ferveo_tdec::share_combine_simple::<E>(
            &decryption_shares,
            &lagrange_coeffs,
        );
        (server_aggregate, decryption_shares, shared_secret)
    }

    #[test_case(4, 3; "N is a power of 2, t is 1 + 50%")]
    #[test_case(4, 4; "N is a power of 2, t=N")]
    #[test_case(30, 16; "N is not a power of 2, t is 1 + 50%")]
    #[test_case(30, 30; "N is not a power of 2, t=N")]
    fn test_dkg_simple_tdec(shares_num: u32, security_threshold: u32) {
        let rng = &mut test_rng();
        let validators_num = shares_num;
        let (dkg, validator_keypairs, messages) =
            setup_dealt_dkg_with_n_validators(
                security_threshold,
                shares_num,
                validators_num,
            );
        let transcripts = messages
            .iter()
            .take(shares_num as usize)
            .map(|m| m.1.clone())
            .collect::<Vec<_>>();
        let local_aggregate =
            AggregatedTranscript::from_transcripts(&transcripts).unwrap();
        assert!(local_aggregate
            .aggregate
            .verify_aggregation(&dkg, &transcripts)
            .unwrap());
        let ciphertext = ferveo_tdec::encrypt::<E>(
            SecretBox::new(MSG.to_vec()),
            AAD,
            &local_aggregate.public_key,
            rng,
        )
        .unwrap();
        let (_, _, shared_secret) = create_shared_secret_simple_tdec(
            &dkg,
            AAD,
            &ciphertext.header().unwrap(),
            validator_keypairs.as_slice(),
            &transcripts,
        );

        let plaintext = ferveo_tdec::decrypt_with_shared_secret(
            &ciphertext,
            AAD,
            &shared_secret,
        )
        .unwrap();
        assert_eq!(plaintext, MSG);
    }

    #[test_case(4, 3; "N is a power of 2, t is 1 + 50%")]
    #[test_case(4, 4; "N is a power of 2, t=N")]
    #[test_case(30, 16; "N is not a power of 2, t is 1 + 50%")]
    #[test_case(30, 30; "N is not a power of 2, t=N")]
    fn test_dkg_simple_tdec_precomputed(
        shares_num: u32,
        security_threshold: u32,
    ) {
        let rng = &mut test_rng();
        let validators_num = shares_num;
        let (dkg, validator_keypairs, messages) =
            setup_dealt_dkg_with_n_transcript_dealt(
                security_threshold,
                shares_num,
                validators_num,
                shares_num,
            );
        let transcripts = messages
            .iter()
            .take(shares_num as usize)
            .map(|m| m.1.clone())
            .collect::<Vec<_>>();
        let local_aggregate =
            AggregatedTranscript::from_transcripts(&transcripts).unwrap();
        assert!(local_aggregate
            .aggregate
            .verify_aggregation(&dkg, &transcripts)
            .unwrap());
        let ciphertext = ferveo_tdec::encrypt::<E>(
            SecretBox::new(MSG.to_vec()),
            AAD,
            &local_aggregate.public_key,
            rng,
        )
        .unwrap();

        // In precomputed variant, client selects a specific subset of validators to create
        // decryption shares
        let selected_keypairs = validator_keypairs
            .choose_multiple(rng, security_threshold as usize)
            .collect::<Vec<_>>();
        let selected_validators = selected_keypairs
            .iter()
            .map(|keypair| {
                dkg.get_validator(&keypair.public_key())
                    .expect("Validator not found")
            })
            .collect::<Vec<_>>();
        let selected_domain_points = selected_validators
            .iter()
            .filter_map(|v| {
                dkg.get_domain_point(v.share_index)
                    .ok()
                    .map(|domain_point| (v.share_index, domain_point))
            })
            .collect::<HashMap<u32, ferveo_tdec::DomainPoint<E>>>();

        let mut decryption_shares: Vec<DecryptionSharePrecomputed<E>> =
            selected_keypairs
                .iter()
                .map(|validator_keypair| {
                    let validator = dkg
                        .get_validator(&validator_keypair.public_key())
                        .unwrap();
                    local_aggregate
                        .aggregate
                        .create_decryption_share_precomputed(
                            &ciphertext.header().unwrap(),
                            AAD,
                            validator_keypair,
                            validator.share_index,
                            &selected_domain_points,
                        )
                        .unwrap()
                })
                .collect();
        // Order of decryption shares is not important
        decryption_shares.shuffle(rng);

        // Decrypt with precomputed variant
        let shared_secret =
            ferveo_tdec::share_combine_precomputed::<E>(&decryption_shares);
        let plaintext = ferveo_tdec::decrypt_with_shared_secret(
            &ciphertext,
            AAD,
            &shared_secret,
        )
        .unwrap();
        assert_eq!(plaintext, MSG);
    }

    #[test_case(4, 3; "N is a power of 2, t is 1 + 50%")]
    #[test_case(4, 4; "N is a power of 2, t=N")]
    #[test_case(30, 16; "N is not a power of 2, t is 1 + 50%")]
    #[test_case(30, 30; "N is not a power of 2, t=N")]
    fn test_dkg_simple_tdec_share_verification(
        shares_num: u32,
        security_threshold: u32,
    ) {
        let rng = &mut test_rng();
        let (dkg, validator_keypairs, messages) =
            setup_dealt_dkg_with(security_threshold, shares_num);
        let transcripts = messages
            .iter()
            .take(shares_num as usize)
            .map(|m| m.1.clone())
            .collect::<Vec<_>>();
        let local_aggregate =
            AggregatedTranscript::from_transcripts(&transcripts).unwrap();
        assert!(local_aggregate
            .aggregate
            .verify_aggregation(&dkg, &transcripts)
            .unwrap());
        let ciphertext = ferveo_tdec::encrypt::<E>(
            SecretBox::new(MSG.to_vec()),
            AAD,
            &local_aggregate.public_key,
            rng,
        )
        .unwrap();

        let (local_aggregate, decryption_shares, _) =
            create_shared_secret_simple_tdec(
                &dkg,
                AAD,
                &ciphertext.header().unwrap(),
                validator_keypairs.as_slice(),
                &transcripts,
            );

        izip!(
            &local_aggregate.aggregate.shares,
            &validator_keypairs,
            &decryption_shares,
        )
        .for_each(
            |(aggregated_share, validator_keypair, decryption_share)| {
                assert!(decryption_share.verify(
                    aggregated_share,
                    &validator_keypair.public_key().encryption_key,
                    &ciphertext,
                ));
            },
        );

        // Testing red-path decryption share verification
        let decryption_share = decryption_shares[0].clone();

        // Should fail because of the bad decryption share
        let mut with_bad_decryption_share = decryption_share.clone();
        with_bad_decryption_share.decryption_share = TargetField::zero();
        assert!(!with_bad_decryption_share.verify(
            &local_aggregate.aggregate.shares[0],
            &validator_keypairs[0].public_key().encryption_key,
            &ciphertext,
        ));

        // Should fail because of the bad checksum
        let mut with_bad_checksum = decryption_share;
        with_bad_checksum.validator_checksum.checksum = G1Affine::zero();
        assert!(!with_bad_checksum.verify(
            &local_aggregate.aggregate.shares[0],
            &validator_keypairs[0].public_key().encryption_key,
            &ciphertext,
        ));
    }

    #[test_case(4, 3; "N is a power of 2, t is 1 + 50%")]
    #[test_case(4, 4; "N is a power of 2, t=N")]
    #[test_case(30, 16; "N is not a power of 2, t is 1 + 50%")]
    #[test_case(30, 30; "N is not a power of 2, t=N")]
    #[cfg(feature = "experimental-refresh")]
    fn test_dkg_simple_tdec_share_refreshing(
        shares_num: u32,
        security_threshold: u32,
    ) {
        let rng = &mut test_rng();
        let (dkg, validator_keypairs, messages) =
            setup_dealt_dkg_with(security_threshold, shares_num);
        let transcripts = messages
            .iter()
            .take(shares_num as usize)
            .map(|m| m.1.clone())
            .collect::<Vec<_>>();

        // Initially, each participant creates a transcript, which is
        // combined into a joint AggregateTranscript.
        let local_aggregate =
            AggregatedTranscript::from_transcripts(&transcripts).unwrap();
        assert!(local_aggregate
            .aggregate
            .verify_aggregation(&dkg, &transcripts)
            .unwrap());

        // Ciphertext created from the aggregate public key
        let ciphertext = ferveo_tdec::encrypt::<E>(
            SecretBox::new(MSG.to_vec()),
            AAD,
            &local_aggregate.public_key,
            rng,
        )
        .unwrap();

        // The set of transcripts (or equivalently, the AggregateTranscript),
        // represents a (blinded) shared secret.
        let (_, _, old_shared_secret) = create_shared_secret_simple_tdec(
            &dkg,
            AAD,
            &ciphertext.header().unwrap(),
            validator_keypairs.as_slice(),
            &transcripts,
        );

        // When the share refresh protocol is necessary, each participant
        // prepares an UpdateTranscript, containing updates for each other.
        let mut update_transcripts: HashMap<u32, UpdateTranscript<E>> =
            HashMap::new();
        let mut validator_map: HashMap<u32, _> = HashMap::new();

        for validator in dkg.validators.values() {
            update_transcripts.insert(
                validator.share_index,
                dkg.generate_refresh_transcript(rng).unwrap(),
            );
            validator_map.insert(
                validator.share_index,
                validator_keypairs
                    .get(validator.share_index as usize)
                    .unwrap()
                    .public_key(),
            );
        }

        // Participants distribute UpdateTranscripts and update their shares
        // accordingly. The result is a new, joint AggregatedTranscript.
        let new_aggregate = local_aggregate
            .aggregate
            .refresh(&update_transcripts, &validator_map)
            .unwrap();

        // TODO: Assert new aggregate is different than original, including coefficients
        assert_ne!(local_aggregate.aggregate, new_aggregate);

        // TODO: Show that all participants obtain the same new aggregate transcript.

        // Get decryption shares, now with the refreshed aggregate transcript:
        let decryption_shares: Vec<DecryptionShareSimple<E>> =
            validator_keypairs
                .iter()
                .map(|validator_keypair| {
                    let validator = dkg
                        .get_validator(&validator_keypair.public_key())
                        .unwrap();
                    new_aggregate
                        .create_decryption_share_simple(
                            &ciphertext.header().unwrap(),
                            AAD,
                            validator_keypair,
                            validator.share_index,
                        )
                        .unwrap()
                })
                // We take only the first `security_threshold` decryption shares
                .take(dkg.dkg_params.security_threshold() as usize)
                .collect();

        // Order of decryption shares is not important, but since we are using low-level
        // API here to performa a refresh for testing purpose, we will not shuffle
        // the shares this time

        let lagrange = ferveo_tdec::prepare_combine_simple::<E>(
            &dkg.domain_points()[..security_threshold as usize],
        );
        let new_shared_secret = ferveo_tdec::share_combine_simple::<E>(
            &decryption_shares[..security_threshold as usize],
            &lagrange,
        );
        assert_eq!(old_shared_secret, new_shared_secret);
    }

    #[test_case(4, 3; "N is a power of 2, t is 1 + 50%")]
    #[test_case(4, 4; "N is a power of 2, t=N")]
    #[test_case(30, 16; "N is not a power of 2, t is 1 + 50%")]
    #[test_case(30, 30; "N is not a power of 2, t=N")]
    #[cfg(feature = "experimental-refresh")]
    fn test_dkg_simple_tdec_handover(shares_num: u32, security_threshold: u32) {
        let rng = &mut test_rng();
        let (dkg, validator_keypairs, messages) =
            setup_dealt_dkg_with(security_threshold, shares_num);

        let transcripts = messages
            .iter()
            .take(shares_num as usize)
            .map(|m| m.1.clone())
            .collect::<Vec<_>>();

        // Initially, each participant creates a transcript, which is
        // combined into a joint AggregateTranscript.
        let local_aggregate =
            AggregatedTranscript::from_transcripts(&transcripts).unwrap();
        assert!(local_aggregate
            .aggregate
            .verify_aggregation(&dkg, &transcripts)
            .unwrap());

        // Ciphertext created from the aggregate public key
        let ciphertext = ferveo_tdec::encrypt::<E>(
            SecretBox::new(MSG.to_vec()),
            AAD,
            &local_aggregate.public_key,
            rng,
        )
        .unwrap();

        // The set of transcripts (or equivalently, the AggregateTranscript),
        // represents a (blinded) shared secret.
        let (_, _, old_shared_secret) = create_shared_secret_simple_tdec(
            &dkg,
            AAD,
            &ciphertext.header().unwrap(),
            validator_keypairs.as_slice(),
            &transcripts,
        );

        // Let's choose a random validator to handover
        let handover_slot_index = rng.gen_range(0..shares_num);
        // Do not reorder: drawing the handover index before the keypair keeps
        // the deterministic test RNG stream from re-deriving one of the
        // validator keypairs above (observed at N=4).

        // New participant that will receive the handover
        let incoming_validator_keypair = Keypair::<E>::new(rng);

        // TODO: Rewrite this test so that the offboarding of validator
        // is done by recreating a DKG instance with a new set of
        // validators from the Coordinator, rather than modifying the
        // existing DKG instance.

        // Get departing validator's public key and blinded share
        let departing_validator =
            dkg.validators.get(&handover_slot_index).unwrap();
        let departing_public_key = departing_validator.public_key;
        assert_eq!(departing_validator.share_index, handover_slot_index);
        assert_ne!(
            departing_public_key,
            incoming_validator_keypair.public_key()
        );

        // Incoming node creates a handover transcript
        let handover_transcript = dkg
            .generate_handover_transcript(
                &local_aggregate,
                handover_slot_index,
                &incoming_validator_keypair,
                rng,
            )
            .unwrap();

        // Make sure handover transcript is valid. This is publicly verifiable.
        // We're doing this for testing purposes, but in practice, this is done
        // by the departing participant when using the high-level API.
        let share_commitments = get_share_commitments_from_poly_commitments::<E>(
            &local_aggregate.aggregate.coeffs,
            &dkg.domain,
        );
        let share_commitment = ShareCommitment::<E>(
            share_commitments
                .get(handover_slot_index as usize)
                .ok_or(Error::InvalidShareIndex(handover_slot_index))
                .unwrap()
                .into_affine(),
        );
        assert!(handover_transcript.validate(share_commitment).unwrap());

        // The departing validator uses the handover transcript produced by the
        // incoming validator to create a new aggregate transcript.
        // This part is showing the high-level API for handover finalization.
        let departing_keypair = validator_keypairs
            .get(handover_slot_index as usize)
            .unwrap();
        assert_eq!(
            departing_validator.public_key,
            departing_keypair.public_key()
        );

        let aggregate_after_handover = local_aggregate
            .aggregate
            .finalize_handover(&handover_transcript, departing_keypair)
            .unwrap();

        // If we use a different keypair, we should get an error
        let error = local_aggregate
            .aggregate
            .finalize_handover(
                &handover_transcript,
                &incoming_validator_keypair,
            )
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            Error::ValidatorPublicKeyMismatch.to_string()
        );

        // New aggregate is different than original...
        assert_ne!(local_aggregate.aggregate, aggregate_after_handover);

        // ...but let's look a bit deeper:
        // - Polynomial coefficients are the same, which makes sense since the private shares are not changing
        assert_eq!(
            local_aggregate.aggregate.coeffs,
            aggregate_after_handover.coeffs
        );
        // - The shares vector is different ...
        assert_ne!(
            local_aggregate.aggregate.shares,
            aggregate_after_handover.shares
        );
        // ... but actually they only differ at the handover index
        for i in 0..shares_num {
            let share_before = local_aggregate.aggregate.shares.get(i as usize);
            let share_after = aggregate_after_handover.shares.get(i as usize);
            if i == handover_slot_index {
                assert_ne!(share_before, share_after);
            } else {
                assert_eq!(share_before, share_after);
            }
        }

        // Get decryption shares, now with the aggregate transcript after handover:
        let decryption_shares: Vec<DecryptionShareSimple<E>> =
            validator_keypairs
                .iter()
                .enumerate()
                .map(|(index, validator_keypair)| {
                    let keypair = if index == handover_slot_index as usize {
                        &incoming_validator_keypair
                    } else {
                        validator_keypair
                    };
                    aggregate_after_handover
                        .create_decryption_share_simple(
                            &ciphertext.header().unwrap(),
                            AAD,
                            keypair,
                            index as u32,
                        )
                        .unwrap()
                })
                // We take only the first `security_threshold` decryption shares
                .take(dkg.dkg_params.security_threshold() as usize)
                .collect();

        let lagrange = ferveo_tdec::prepare_combine_simple::<E>(
            &dkg.domain_points()[..security_threshold as usize],
        );
        let new_shared_secret = ferveo_tdec::share_combine_simple::<E>(
            &decryption_shares[..security_threshold as usize],
            &lagrange,
        );
        assert_eq!(old_shared_secret, new_shared_secret);
    }
}
