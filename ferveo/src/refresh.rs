//! Experimental share-mobility protocols: **share refresh** and **handover**.
//!
//! Gated behind the `experimental-refresh` cargo feature (off by default).
//! opacity-stack does **not** use these; it rotates keys at the application
//! layer. This code is ported from upstream ferveo, is **unaudited**, and has
//! known gaps (below). Do not enable it for production key management without a
//! security review.
//!
//! Known limitations (were upstream #200):
//! - `UpdatableBlindedKeyShare::apply_share_updates` applies share updates
//!   without validating their Feldman commitments. Callers must first verify
//!   the update transcripts via `UpdateTranscript::verify_refresh`.
//! - `PubliclyVerifiableSS::refresh` does not update the polynomial commitments
//!   (`coeffs`) to match the refreshed shares, so a refreshed aggregate will
//!   not pass `verify_full`.
//! - Validation failures panic (`assert!`/`unwrap()`) instead of returning
//!   errors; an invalid update from a peer is currently a crash.
//! - `PubliclyVerifiableSS::finalize_handover` discards the boolean returned
//!   by `verify_validator_share`: only the `Err` arm propagates, so an
//!   `Ok(false)` ("share invalid") result silently installs an invalid
//!   re-blinded share into the post-handover aggregate.
//!
//! Share *recovery* (recovering a lost share at an arbitrary domain point) was
//! removed as dead scaffolding; the update-polynomial machinery it shared with
//! refresh remains available here.

use std::{collections::HashMap, ops::Mul};

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{Field, Zero};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain,
    Polynomial,
};
use ark_std::{One, UniformRand};
use ferveo_common::{serialization, Keypair, PublicKey};
use ferveo_tdec::{
    prepare_combine_simple, BlindedKeyShare, CiphertextHeader,
    DecryptionSharePrecomputed, DecryptionShareSimple, DomainPoint,
    ShareCommitment,
};
use rand_core::RngCore;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::serde_as;
use subproductdomain::fast_multiexp;
use zeroize::ZeroizeOnDrop;

use crate::{batch_to_projective_g1, Error, Result};

type InnerBlindedKeyShare<E> = ferveo_tdec::BlindedKeyShare<E>;

/// Blinded key share held by a participant in the DKG protocol
#[derive(Debug, Clone)]
pub struct UpdatableBlindedKeyShare<E: Pairing>(pub InnerBlindedKeyShare<E>);

impl<E: Pairing> UpdatableBlindedKeyShare<E> {
    pub fn new(blinded_key_share: InnerBlindedKeyShare<E>) -> Self {
        Self(blinded_key_share)
    }

    /// From PSS paper, section 4.2.3, (https://link.springer.com/content/pdf/10.1007/3-540-44750-4_27.pdf)
    pub fn apply_share_updates(
        &self,
        update_transcripts: &HashMap<u32, UpdateTranscript<E>>,
        index: u32,
    ) -> Self {
        // Current participant receives update transcripts from other participants
        let share_updates_for_index: Vec<_> = update_transcripts
            .values()
            .map(|update_transcript_from_producer| {
                let update_for_participant: ShareUpdate<E> =
                    update_transcript_from_producer
                        .updates
                        .get(&index)
                        .cloned()
                        .unwrap();
                // Validate share update against the target validator public key
                update_for_participant
                    .verify(&PublicKey {
                        encryption_key: self.0.validator_public_key,
                    })
                    .unwrap();
                update_for_participant
            })
            .collect();

        // KNOWN GAP (experimental, was #200): the Feldman commitments carried
        // by each share update are not validated here. Callers must verify the
        // update transcripts (`UpdateTranscript::verify_refresh`) before
        // applying them. See the module-level docs.
        let updated_key_share = share_updates_for_index
            .iter()
            .fold(self.0.blinded_key_share, |acc, delta| {
                (acc + delta.update).into()
            });
        Self(BlindedKeyShare {
            validator_public_key: self.0.validator_public_key,
            blinded_key_share: updated_key_share,
        })
    }

    pub fn create_decryption_share_simple(
        &self,
        ciphertext_header: &CiphertextHeader<E>,
        aad: &[u8],
        validator_keypair: &Keypair<E>,
    ) -> Result<DecryptionShareSimple<E>> {
        let decryption_share = self
            .0
            .create_decryption_share_simple(
                ciphertext_header,
                aad,
                validator_keypair,
            )
            .unwrap();
        Ok(decryption_share)
    }

    // TODO: Move to BlindedKeyShare
    /// In precomputed variant, we offload some of the decryption related computation to the server-side:
    /// We use the `prepare_combine_simple` function to precompute the lagrange coefficients
    pub fn create_decryption_share_precomputed(
        &self,
        ciphertext_header: &CiphertextHeader<E>,
        aad: &[u8],
        validator_keypair: &Keypair<E>,
        share_index: u32,
        domain_points_map: &HashMap<u32, DomainPoint<E>>,
    ) -> Result<DecryptionSharePrecomputed<E>> {
        // We need to turn the domain points into a vector, and sort it by share index
        let mut domain_points = domain_points_map
            .iter()
            .map(|(share_index, domain_point)| (*share_index, *domain_point))
            .collect::<Vec<_>>();
        domain_points.sort_by_key(|(share_index, _)| *share_index);

        // Now, we have to pass the domain points to the `prepare_combine_simple` function
        // and use the resulting lagrange coefficients to create the decryption share

        let only_domain_points = domain_points
            .iter()
            .map(|(_, domain_point)| *domain_point)
            .collect::<Vec<_>>();
        let lagrange_coeffs = prepare_combine_simple::<E>(&only_domain_points);

        // Before we pick the lagrange coefficient for the current share index, we need
        // to map the share index to the index in the domain points vector
        // Given that we sorted the domain points by share index, the first element in the vector
        // will correspond to the smallest share index, second to the second smallest, and so on

        let sorted_share_indices = domain_points
            .iter()
            .enumerate()
            .map(|(adjusted_share_index, (share_index, _))| {
                (*share_index, adjusted_share_index)
            })
            .collect::<HashMap<u32, usize>>();
        let adjusted_share_index = *sorted_share_indices
            .get(&share_index)
            .ok_or(Error::InvalidShareIndex(share_index))?;

        // Finally, pick the lagrange coefficient for the current share index
        let lagrange_coeff = &lagrange_coeffs[adjusted_share_index];
        let private_key_share = self.0.unblind(validator_keypair);
        DecryptionSharePrecomputed::create(
            share_index as usize,
            &validator_keypair.decryption_key,
            &private_key_share.unwrap(),
            ciphertext_header,
            aad,
            lagrange_coeff,
        )
        .map_err(|e| e.into())
    }
}

/// An update to a private key share generated by a participant in a share refresh operation.
#[serde_as]
#[derive(
    Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ZeroizeOnDrop,
)]
pub struct ShareUpdate<E: Pairing> {
    #[serde_as(as = "serialization::SerdeAs")]
    pub update: E::G2Affine,

    #[serde_as(as = "serialization::SerdeAs")]
    pub commitment: E::G1Affine,
}

impl<E: Pairing> ShareUpdate<E> {
    // TODO: Use multipairings?
    // TODO: Unit tests
    pub fn verify(
        &self,
        target_validator_public_key: &PublicKey<E>,
    ) -> Result<bool> {
        let public_key_point: E::G2Affine =
            target_validator_public_key.encryption_key;
        let is_valid = E::pairing(E::G1::generator(), self.update)
            == E::pairing(self.commitment, public_key_point);
        if is_valid {
            Ok(true)
        } else {
            Err(Error::InvalidShareUpdate)
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateTranscript<E: Pairing> {
    /// Used in Feldman commitment to the update polynomial
    pub coeffs: Vec<E::G1Affine>,

    /// The share updates to be dealt to each validator
    pub updates: HashMap<u32, ShareUpdate<E>>,
}

impl<E: Pairing> UpdateTranscript<E> {
    /// From PSS paper, section 4.2.1, (https://link.springer.com/content/pdf/10.1007/3-540-44750-4_27.pdf)
    pub fn create_refresh_updates(
        domain_points_and_keys: &HashMap<u32, (DomainPoint<E>, PublicKey<E>)>,
        threshold: u32,
        rng: &mut impl RngCore,
    ) -> UpdateTranscript<E> {
        // Update polynomial has root at 0
        prepare_share_updates_with_root::<E>(
            domain_points_and_keys,
            &DomainPoint::<E>::zero(),
            threshold,
            rng,
        )
    }

    // Shared verifier for update transcripts, parametrized by the polynomial
    // root (0 for refresh). `verify_refresh` is the only caller; the public
    // recovery entry points were removed with the rest of the recovery
    // scaffolding, but the general root-based logic is kept here.
    fn verify_recovery(
        &self,
        validator_public_keys: &HashMap<u32, PublicKey<E>>,
        domain: &ark_poly::GeneralEvaluationDomain<E::ScalarField>,
        root: E::ScalarField,
    ) -> Result<bool> {
        // TODO: Make sure input validators and transcript validators match

        // TODO: Validate that update polynomial commitments have proper length

        // Validate consistency between share updates, validator keys and polynomial commitments.
        // Let's first reconstruct the expected update commitments from the polynomial commitments:
        let mut reconstructed_commitments =
            batch_to_projective_g1::<E>(&self.coeffs);
        domain.fft_in_place(&mut reconstructed_commitments);

        for (index, update) in self.updates.iter() {
            // Next, validate share updates against their corresponding target validators
            update
                .verify(validator_public_keys.get(index).unwrap())
                .unwrap();

            // Finally, validate update commitments against update polynomial commitments
            let expected_commitment = reconstructed_commitments
                .get(*index as usize)
                .ok_or(Error::InvalidShareIndex(*index))?;
            assert_eq!(expected_commitment.into_affine(), update.commitment);
            // TODO: Error handling of everything in this block
        }

        // Validate update polynomial commitments C_i are consistent with the type of update
        // * For refresh  (root 0): f(0) = 0  ==>  a_0 = 0  ==>  C_0 = [0]G = 1
        // * For recovery (root z): f(z) = 0  ==>  sum{a_i * z^i} = 0  ==>  [sum{...}]G = 1  ==> sum{[z^i]C_i} = 1

        if root.is_zero() {
            // Refresh
            assert!(self.coeffs[0].is_zero());
            // TODO: Check remaining are not zero? Only if we disallow producing zero coeffs
        } else {
            // Recovery
            let mut reverse_coeffs = self.coeffs.iter().rev();
            let mut acc: E::G1Affine = *reverse_coeffs.next().unwrap();
            for &coeff in reverse_coeffs {
                let b = acc.mul(root).into_affine();
                acc = (coeff + b).into();
            }
            assert!(acc.is_zero());
        }

        Ok(true)
    }

    // TODO: Unit tests
    pub fn verify_refresh(
        &self,
        validator_public_keys: &HashMap<u32, PublicKey<E>>,
        domain: &ark_poly::GeneralEvaluationDomain<E::ScalarField>,
    ) -> Result<bool> {
        self.verify_recovery(
            validator_public_keys,
            domain,
            E::ScalarField::zero(),
        )
    }
}

// HandoverTranscript, a.k.a. "The Baton", represents the message an incoming
// node produces to initiate a handover with an outgoing node.
// After the handover, the incoming node replaces the outgoing node in an
// existing cohort, securely obtaining a new blinded key share, but under the
// incoming node's private key.
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoverTranscript<E: Pairing> {
    pub share_index: u32,
    #[serde_as(as = "serialization::SerdeAs")]
    pub double_blind_share: E::G2,

    #[serde_as(as = "serialization::SerdeAs")]
    pub commitment_to_share: E::G2,

    #[serde_as(as = "serialization::SerdeAs")]
    pub commitment_to_g1: E::G1,

    #[serde_as(as = "serialization::SerdeAs")]
    pub commitment_to_g2: E::G2,

    #[serde(bound(
        serialize = "ferveo_common::PublicKey<E>: Serialize",
        deserialize = "ferveo_common::PublicKey<E>: DeserializeOwned"
    ))]
    pub incoming_pubkey: PublicKey<E>,

    #[serde(bound(
        serialize = "ferveo_common::PublicKey<E>: Serialize",
        deserialize = "ferveo_common::PublicKey<E>: DeserializeOwned"
    ))]
    pub outgoing_pubkey: PublicKey<E>,
}

impl<E: Pairing> HandoverTranscript<E> {
    pub fn new(
        share_index: u32,
        outgoing_blinded_share: &BlindedKeyShare<E>,
        outgoing_pubkey: PublicKey<E>,
        incoming_validator_keypair: &Keypair<E>,
        rng: &mut impl RngCore,
    ) -> Self {
        // t
        let random_scalar = E::ScalarField::rand(rng);
        // d_j
        let incoming_decryption_key = incoming_validator_keypair.decryption_key;
        // d_j * Y_i
        let double_blind_share = outgoing_blinded_share
            .blinded_key_share
            .mul(incoming_decryption_key);
        // t * d_j * ek_i
        let commitment_to_share = outgoing_pubkey
            .encryption_key
            .mul(incoming_decryption_key.mul(random_scalar));

        Self {
            share_index,
            double_blind_share,
            commitment_to_share,
            commitment_to_g1: E::G1::generator().mul(random_scalar),
            commitment_to_g2: E::G2::generator().mul(random_scalar),
            incoming_pubkey: incoming_validator_keypair.public_key(),
            outgoing_pubkey,
        }
    }

    // See similarity with transcript check #4 (do_verify_full in pvss)
    pub fn validate(
        &self,
        share_commitment: ShareCommitment<E>,
    ) -> Result<bool> {
        // e(comm_G1, double_blind_share) == e(A_i, comm_share)
        //   or equivalently:
        // e(-comm_G1, double_blind_share) · e(A_i, comm_share) == 1
        let commitment_to_g1_inv = -self.commitment_to_g1;
        let mut is_valid = E::multi_pairing(
            [commitment_to_g1_inv, share_commitment.0.into()],
            [self.double_blind_share, self.commitment_to_share],
        )
        .0 == E::TargetField::one();

        // e(comm_G1, gen_G2) == e(gen_G1, comm_G2)
        //   or equivalently:
        // e(-comm_G1, gen_G2) · e(gen_G1, comm_G2) == 1
        is_valid = is_valid
            && E::multi_pairing(
                [commitment_to_g1_inv, E::G1::generator()],
                [E::G2::generator(), self.commitment_to_g2],
            )
            .0 == E::TargetField::one();

        if is_valid {
            Ok(true)
        } else {
            Err(Error::InvalidShareUpdate) // TODO: review error
        }
    }

    pub fn finalize(
        &self,
        departing_validator_keypair: &Keypair<E>,
        share_commitment: ShareCommitment<E>,
    ) -> Result<BlindedKeyShare<E>> {
        let is_valid = &self.validate(share_commitment).unwrap();
        if !is_valid {
            return Err(Error::InvalidShareUpdate); // TODO: Make this more specific
        }
        let new_blinded_share_element = &self.double_blind_share.mul(
            departing_validator_keypair
                .decryption_key
                .inverse()
                .unwrap(),
        );
        Ok(BlindedKeyShare::<E> {
            validator_public_key: self.incoming_pubkey.encryption_key,
            blinded_key_share: new_blinded_share_element.into_affine(),
        })
    }
}

/// Prepare share updates with a given root (0 for refresh, some x coord for recovery)
/// This is a helper function for `ShareUpdate::create_share_updates_for_recovery` and `ShareUpdate::create_share_updates_for_refresh`
/// It generates a new random polynomial with a defined root and evaluates it at each of the participants' indices.
/// The result is a map of share updates.
// TODO: Use newtype type for (DomainPoint<E>, PublicKey<E>)
fn prepare_share_updates_with_root<E: Pairing>(
    domain_points_and_keys: &HashMap<u32, (DomainPoint<E>, PublicKey<E>)>,
    root: &DomainPoint<E>,
    threshold: u32,
    rng: &mut impl RngCore,
) -> UpdateTranscript<E> {
    // Generate a new random update polynomial with defined root
    let update_poly =
        make_random_polynomial_with_root::<E>(threshold - 1, root, rng);

    // Commit to the update polynomial
    let g = E::G1::generator();
    let coeff_commitments = fast_multiexp(&update_poly.coeffs, g);

    // Now, we need to evaluate the polynomial at each of participants' indices
    let share_updates: HashMap<u32, ShareUpdate<E>> = domain_points_and_keys
        .iter()
        .map(|(share_index, tuple)| {
            let (x_i, pubkey_i) = tuple;
            let eval = update_poly.evaluate(x_i);
            let update =
                E::G2::from(pubkey_i.encryption_key).mul(eval).into_affine();
            let commitment = g.mul(eval).into_affine();
            let share_update = ShareUpdate { update, commitment };
            (*share_index, share_update)
        })
        .collect::<HashMap<u32, ShareUpdate<E>>>();

    UpdateTranscript {
        coeffs: coeff_commitments,
        updates: share_updates,
    }
}

/// Generate a random polynomial with a given root
fn make_random_polynomial_with_root<E: Pairing>(
    degree: u32,
    root: &DomainPoint<E>,
    rng: &mut impl RngCore,
) -> DensePolynomial<DomainPoint<E>> {
    // [c_0, c_1, ..., c_{degree}] (Random polynomial)
    let mut poly =
        DensePolynomial::<DomainPoint<E>>::rand(degree as usize, rng);

    // [0, c_1, ... , c_{degree}]  (We zeroize the free term)
    poly[0] = DomainPoint::<E>::zero();

    // Now, we calculate a new free term so that `poly(root) = 0`
    let new_c_0 = DomainPoint::<E>::zero() - poly.evaluate(root);
    poly[0] = new_c_0;

    // Evaluating the polynomial at the root should result in 0
    debug_assert!(poly.evaluate(root) == DomainPoint::<E>::zero());
    debug_assert!(poly.coeffs.len() == (degree + 1) as usize);

    poly
}

#[cfg(test)]
mod tests_refresh {
    use std::{collections::HashMap, ops::Mul};

    use ark_ec::CurveGroup;
    use ark_poly::EvaluationDomain;
    use ark_std::{test_rng, Zero};
    use ferveo_common::Keypair;
    use ferveo_tdec::{
        lagrange_basis_at, test_common::setup_simple, DomainPoint,
    };
    use itertools::{zip_eq, Itertools};
    use test_case::test_case;

    use crate::{
        test_common::*, HandoverTranscript, UpdatableBlindedKeyShare,
        UpdateTranscript,
    };

    type ScalarField =
        <ark_bls12_381::Bls12_381 as ark_ec::pairing::Pairing>::ScalarField;
    type G2 = <ark_bls12_381::Bls12_381 as ark_ec::pairing::Pairing>::G2;

    /// `x_r` is the point at which the share is to be recovered
    fn combine_private_shares_at(
        x_r: &DomainPoint<E>,
        domain_points: &HashMap<u32, DomainPoint<E>>,
        shares: &HashMap<u32, ferveo_tdec::PrivateKeyShare<E>>,
    ) -> ferveo_tdec::PrivateKeyShare<E> {
        let mut domain_points_ = vec![];
        let mut updated_shares_ = vec![];
        for share_index in shares.keys().sorted() {
            domain_points_.push(*domain_points.get(share_index).unwrap());
            updated_shares_.push(shares.get(share_index).unwrap().0);
        }

        // Interpolate new shares to recover y_r
        let lagrange = lagrange_basis_at::<E>(&domain_points_, x_r);
        let prods =
            zip_eq(updated_shares_, lagrange).map(|(y_j, l)| y_j.mul(l));
        let y_r = prods.fold(G2::zero(), |acc, y_j| acc + y_j);
        ferveo_tdec::PrivateKeyShare(y_r.into_affine())
    }

    /// Ñ parties (where t <= Ñ <= N) jointly execute a "share refresh" algorithm.
    /// The output is M new shares (with M <= Ñ), with each of the M new shares substituting the
    /// original share (i.e., the original share is deleted).
    #[test_case(4, 3; "N is a power of 2, t is 1 + 50%")]
    #[test_case(4, 4; "N is a power of 2, t=N")]
    #[test_case(30, 16; "N is not a power of 2, t is 1 + 50%")]
    #[test_case(30, 30; "N is not a power of 2, t=N")]
    fn tdec_simple_variant_share_refreshing(
        shares_num: usize,
        security_threshold: usize,
    ) {
        let rng = &mut test_rng();
        let (_, shared_private_key, contexts) =
            setup_simple::<E>(shares_num, security_threshold, rng);

        let fft_domain =
            ark_poly::GeneralEvaluationDomain::<ScalarField>::new(shares_num)
                .unwrap();

        let domain_points_and_keys = &contexts
            .iter()
            .map(|ctxt| {
                (
                    ctxt.index as u32,
                    (
                        ctxt.public_decryption_contexts[ctxt.index].domain,
                        ctxt.public_decryption_contexts[ctxt.index]
                            .validator_public_key,
                    ),
                )
            })
            .collect::<HashMap<u32, _>>();
        let validator_keys_map = &contexts
            .iter()
            .map(|ctxt| {
                (
                    ctxt.index as u32,
                    ctxt.public_decryption_contexts[ctxt.index]
                        .validator_public_key,
                )
            })
            .collect::<HashMap<u32, _>>();

        // Each participant prepares an update transcript for each other participant:
        let update_transcripts_by_producer = contexts
            .iter()
            .map(|p| {
                let updates_transcript =
                    UpdateTranscript::<E>::create_refresh_updates(
                        domain_points_and_keys,
                        security_threshold as u32,
                        rng,
                    );
                (p.index as u32, updates_transcript)
            })
            .collect::<HashMap<u32, UpdateTranscript<E>>>();

        // Participants validate first all the update transcripts.
        for update_transcript in update_transcripts_by_producer.values() {
            update_transcript
                .verify_refresh(validator_keys_map, &fft_domain)
                .unwrap();
        }

        // Participants refresh their shares with the updates from each other:
        let refreshed_shares = contexts
            .iter()
            .map(|p| {
                let participant_index = p.index as u32;
                let blinded_key_share =
                    p.public_decryption_contexts[p.index].blinded_key_share;

                // And creates a new, refreshed share
                let updated_blinded_key_share =
                    UpdatableBlindedKeyShare(blinded_key_share)
                        .apply_share_updates(
                            &update_transcripts_by_producer,
                            participant_index,
                        );

                let validator_keypair = ferveo_common::Keypair {
                    decryption_key: p.setup_params.b,
                };
                let updated_private_share = updated_blinded_key_share
                    .0
                    .unblind(&validator_keypair)
                    .unwrap();

                (participant_index, updated_private_share)
            })
            // We only need `threshold` refreshed shares to recover the original share
            .take(security_threshold)
            .collect::<HashMap<u32, ferveo_tdec::PrivateKeyShare<E>>>();

        let domain_points = domain_points_and_keys
            .iter()
            .map(|(share_index, (domain_point, _))| {
                (*share_index, *domain_point)
            })
            .collect::<HashMap<u32, DomainPoint<E>>>();

        let x_r = ScalarField::zero();
        let new_shared_private_key =
            combine_private_shares_at(&x_r, &domain_points, &refreshed_shares);
        assert_eq!(shared_private_key, new_shared_private_key);
    }

    // TODO: Simple handover transcript unit test

    /// 2 parties follow a handover protocol. The output is a new blind share
    /// that replaces the original share, using the same domain point
    /// but different validator key.
    #[test_case(4; "N is not a power of 2, t=N")]
    fn tdec_simple_variant_share_handover(shares_num: usize) {
        // Test setup
        let rng = &mut test_rng();
        let security_threshold = shares_num;
        let (_, shared_private_key, private_contexts) =
            setup_simple::<E>(shares_num, security_threshold, rng);
        let domain_points = &private_contexts
            .iter()
            .map(|ctxt| {
                (
                    ctxt.index as u32,
                    ctxt.public_decryption_contexts[ctxt.index].domain,
                )
            })
            .collect::<HashMap<u32, DomainPoint<E>>>();

        // New participant that will receive the handover
        let incoming_validator_keypair = Keypair::<E>::new(rng);

        // For simplicity, we're going to do the handover with the last participant
        let departing_participant = private_contexts.last().unwrap();
        let handover_slot_index: u32 = departing_participant.index as u32;
        let departing_public_context = departing_participant
            .public_decryption_contexts
            .get(handover_slot_index as usize)
            .unwrap();

        let departing_blinded_share =
            departing_public_context.blinded_key_share;
        let departing_public_key = ferveo_common::PublicKey {
            encryption_key: departing_public_context
                .blinded_key_share
                .validator_public_key,
        };

        // Incoming node creates a handover transcript
        let handover_transcript = HandoverTranscript::<E>::new(
            handover_slot_index,
            &departing_blinded_share,
            departing_public_key,
            &incoming_validator_keypair,
            rng,
        );

        // Make sure handover transcript is valid. This is publicly verifiable.
        assert!(handover_transcript
            .validate(departing_public_context.share_commitment)
            .unwrap());

        // This portion shows that handover can be finalized by the departing participant,
        // and that the new blinded share contains the same private key share.
        // TODO: This is a low-level check for now. This will be part of the handover protocol.
        let departing_validator_private_key =
            departing_participant.setup_params.b;
        let departing_validator_keypair = Keypair::<E> {
            decryption_key: departing_validator_private_key,
        };
        let new_blinded_share = handover_transcript
            .finalize(
                &departing_validator_keypair,
                departing_public_context.share_commitment,
            )
            .unwrap();

        let old_private_share = departing_blinded_share
            .unblind(&departing_validator_keypair)
            .unwrap();
        let new_private_share = new_blinded_share
            .unblind(&incoming_validator_keypair)
            .unwrap();
        assert_eq!(new_private_share, old_private_share);

        // We check that the private share from the other participants plus the
        // new_private_share obtained after handover can be combined to
        // reconstruct the shared private key.
        let other_participants = private_contexts
            .iter()
            .filter(|p| p.index as u32 != handover_slot_index);

        let mut shares_map = other_participants
            .map(|p| {
                let participant_index = p.index as u32;
                let blinded_key_share =
                    p.public_decryption_contexts[p.index].blinded_key_share;
                let validator_keypair = ferveo_common::Keypair {
                    decryption_key: p.setup_params.b,
                };

                let private_share =
                    blinded_key_share.unblind(&validator_keypair).unwrap();

                (participant_index, private_share)
            })
            .collect::<HashMap<u32, ferveo_tdec::PrivateKeyShare<E>>>();

        shares_map.insert(handover_slot_index, new_private_share);

        let x_r = ScalarField::zero();
        let new_shared_private_key =
            combine_private_shares_at(&x_r, domain_points, &shares_map);
        assert_eq!(shared_private_key, new_shared_private_key);
    }
}
