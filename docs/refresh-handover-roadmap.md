# Refresh & Handover: status and the path to production

What must happen before the `experimental-refresh` feature (share refresh and
handover, `ferveo/src/refresh.rs`) can be relied on for production key
management. This is the record for the *if/when* decision; nothing here is
scheduled work.

Companion documents: `docs/security-notes.md` (the σ/proof-of-knowledge
assumption and the multi-dealer footguns — directly relevant here, since
refresh/handover are multi-party-dealing flows) and the module docs in
`ferveo/src/refresh.rs` (the authoritative known-gaps list, kept next to the
code).

## Current status

- **Gated and off by default.** The `experimental-refresh` cargo feature
  compiles the code; CI builds and tests it so it cannot rot, but the default
  build — what opacity-stack consumes — excludes it entirely.
- **Unaudited.** Ported from upstream ferveo in a half-finished state; the
  handover construction ("The Baton") is an Opacity design with no external
  security proof or review.
- **Unused.** opacity-stack rotates keys at the application layer (the director
  mints a new key version and redistributes shares). Nothing calls these APIs.
- **Recovery was deleted**, not gated: recovering a lost share at an arbitrary
  domain point had no exposed API and only `unimplemented!()` tests. If wanted
  later, re-port from git history or rebuild on the update-polynomial machinery
  that refresh still carries.

## What exists and works today (under the feature)

- **Refresh**: update-transcript creation (`create_refresh_updates`), public
  verification (`verify_refresh`: FFT-consistency of update commitments plus the
  root-at-zero check that preserves the secret), and share application
  (`apply_share_updates`). End-to-end refresh tests pass.
- **Handover**: transcript creation, public validation (two pairing checks), and
  finalization producing a share re-blinded under the incoming node's key.
  End-to-end handover tests pass.

Passing tests demonstrate the *happy path*, not adversarial soundness.

## Known implementation gaps (formerly upstream #200)

Tracked in the `refresh.rs` module docs; summarized:

1. **Composition**: `apply_share_updates` verifies each update against the
   target validator key but does **not** run the `verify_refresh`
   FFT-consistency/root checks itself — it trusts that the caller did. The
   high-level `refresh()` does; the primitive does not enforce it.
2. **Re-verifiability**: `refresh()` replaces the shares but not the aggregate's
   polynomial commitments (`coeffs`), so a refreshed `AggregatedTranscript`
   fails `verify_full`. The presumed fix is adding the update-polynomial
   commitments (`F_j ← F_j + Σ_p C_{p,j}`) — correctness unconfirmed.
3. **Robustness**: validation failures panic (`assert!`/`unwrap()`) instead of
   returning errors; an invalid update from a peer is currently a crash.
4. **Handover share validation**: `finalize_handover` calls
   `verify_validator_share(...)?`, which propagates only the `Err` arm — an
   `Ok(false)` ("share invalid") result is silently discarded, so an invalid
   re-blinded share would still be installed into the post-handover
   aggregate. Contrast `do_verify_full`, which checks the boolean.

## Open cryptographic questions (require a cryptographer)

These determine whether the *design* is sound, independent of the gaps above:

- **Refresh — validation completeness.** Is commitment-consistency + degree
  bound + root-at-zero + the per-share pairing sufficient, or must a producer
  also prove *knowledge* of its update polynomial (an analogue of the σ
  proof-of-knowledge)? See `docs/security-notes.md`: the σ soundness argument
  rests on AGM/KOE and, today, on the single-dealer deployment — refresh
  introduces **multiple dealers**, which activates exactly the assumptions that
  are currently moot.
- **Refresh — atomicity.** Is verify-then-apply as separate steps sound, or must
  validation be atomic with application?
- **Refresh — re-verifiability.** Is public re-verifiability of the refreshed
  aggregate a security requirement (nodes must be able to re-run `verify_full`)
  or an ergonomic gap? Is the `F_j` update above the correct and sufficient fix?
- **Handover — soundness.** Do the two pairing checks fully bind the
  double-blinded share to the committed share (no substitution by a malicious
  incoming node)? What does the random blinding scalar hide, and does the
  transcript leak anything about the departing share to third parties? Malicious
  outgoing-node behavior at finalization? Does this match a citable re-sharing
  primitive, or does it need its own written proof?

## Definition of done (to lift "experimental")

1. Answers to the open questions above, written down (extend
   `docs/security-notes.md`), including the multi-dealer σ decision it forces.
2. Gaps 1–4 closed: enforced (or atomic) validation, commitment update with a
   test that a refreshed aggregate passes `verify_full`, error returns instead
   of panics, and `finalize_handover` rejecting an invalid re-blinded share.
3. Adversarial tests: forged/mismatched update transcripts, wrong-degree update
   polynomials, nonzero-root "refresh", crafted handover transcripts — all
   rejected with errors, not panics.
4. A security review of the handover construction (it is ours; nothing to cite).
5. Wire-format decision: refresh/handover types are **not** covered by the
   golden vectors today. Before production use, either pin their serialization
   in `ferveo/tests/wire_format.rs` or explicitly declare them unstable.
6. Only then: remove the feature gate (or ship it on), and update
   `.agents/skills/opacity-ferveo-map/SKILL.md` and `docs/security-notes.md`
   (the single-dealer rationale changes the moment any multi-party dealing is
   enabled).

## Adoption context

The application-layer alternative (director redistributes a new key version)
covers today's rotation needs. Cryptographic refresh/handover become worth this
investment when key *continuity* matters — replacing a node or re-randomizing
shares **without changing the public key** that encrypted data is bound to, or
reducing trust in the director for rotation. Revisit this document at that
point; do not enable the feature before the definition of done is met.
