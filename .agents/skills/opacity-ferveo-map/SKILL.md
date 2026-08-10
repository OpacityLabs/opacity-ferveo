---
name: opacity-ferveo-map
description: Architecture map of opacity-ferveo — crate responsibilities, DKG/threshold-decryption protocol flow, wire-format and hash-to-curve invariants, deliberate dependency pins, and how opacity-stack consumes this repo. Load before any task that spans crates, touches serialization or cryptography, changes dependencies, or needs to know where something lives. Skip for trivial single-file edits where you already know the location.
---

# opacity-ferveo Map

Verify against code before relying on specifics; this file describes
architecture, which changes slowly, but it can lag.

## What this library is

A synchronous Distributed Key Generation (DKG) and threshold decryption
library over BLS12-381 (construction: IACR ePrint 2022/898). Validators
jointly produce a shared public key via publicly verifiable secret sharing
(PVSS); decryption requires a threshold of validators. Fork of Ferveo
(Heliax/Anoma → NuCypher → Opacity Labs), maintained solely for
opacity-stack, where the **director** crate runs the DKG ceremony and
distributes shares to **nodes**, which later produce decryption shares.

## Crate map

| Crate | Owns |
|---|---|
| `ferveo` | The DKG protocol: `dkg` (ceremony state), `pvss` (transcripts, aggregation), `refresh` (share refresh / handover), `validator`, and `ferveo::api` — the stable server/client surface opacity-stack calls |
| `ferveo-tdec` | Threshold encryption: `ciphertext` (ChaCha20Poly1305 payload + G1/G2 commitment/tag), `decryption` / `combine` (shares, Lagrange combination), `hash_to_curve` (miracl-backed G2 hash, RFC 9380), `secret_box` (zeroizing wrappers) |
| `ferveo-common` | `Keypair`/`PublicKey` (G2), `serialization` — the `ToBytes`/`FromBytes` traits and `SerdeAs` bridge between serde and arkworks |
| `subproductdomain` | Fast polynomial evaluation/interpolation (subproduct trees) used for batch operations over validator domains |

## Protocol flow (happy path)

Each validator: `Dkg::new(tau, shares_num, threshold, validators, me)` →
`generate_transcript(rng)` → broadcast. Anyone: `aggregate_transcripts`
→ `AggregatedTranscript::verify` → `public_key()`. Client encrypts with
`ferveo::api::encrypt(msg, aad, dkg_pk)`. Each validator produces
`create_decryption_share_simple` (or `_precomputed`); client
`combine_shares_simple` → `decrypt_with_shared_secret`.

**Deployment note:** the above is the library's *per-validator* protocol.
opacity-stack runs it **single-dealer** — the director performs every "each
validator" step itself (generating all transcripts) and aggregates them, rather
than validators dealing independently. This distinction is load-bearing for the
σ / proof-of-knowledge argument; see `docs/security-notes.md`.

### Decryption shares: implementation deviates from the paper

`ferveo-tdec` intentionally deviates from §4.4 of the Ferveo paper (eprint
2022/898) in what a "decryption share" is. Design note: nucypher/ferveo#42,
comment 1398953777 (cited in decryption.rs). Soundness discussion: Linear
VDN-5 ("opacity-ferveo #201: is S a sound proof of knowledge").

Notation: `U = [r]G` ∈ G1 is the ciphertext commitment. Per share index i:
`dk_i` = validator blinding scalar (`Keypair::decryption_key`),
`ek_i = [dk_i]H` ∈ G2 (validator public key), `Y_i = [f(ω_i)]ek_i` ∈ G2 =
blinded key share (public, from the aggregated transcript; `share_aggregate`
in code), `Z_i = [dk_i⁻¹]Y_i = [f(ω_i)]H` = unblinded `PrivateKeyShare` ∈ G2.

- **Paper (§4.4.3–4.4.5):** the share is the 48-byte G1 element
  `D_i = [dk_i⁻¹]U`, verified by `e(D_i, ek_i) == e(U, H)`; the *combiner*
  computes the pairings: `S = ∏ e(D_i, [λ_i(0)]Y_i)`.
- **Implementation:** the pairing is offloaded to the share creator; the
  published share is a G_T element (`decryption_share: E::TargetField`,
  ~576 B serialized):
  - Simple: `D_i = e(U, Z_i)` (decryption.rs); combine is pairing-free:
    `S = ∏ D_i^{λ_i}` (combine.rs::share_combine_simple).
  - Precomputed: `D_i = e([λ_i]U, Z_i)` with λ_i computed over a validator
    subset fixed at share-creation time
    (key_share.rs::create_decryption_share_precomputed); combine is a bare
    product `S = ∏ D_i`. Shares are bound to their subset and not reusable
    across subsets. (The `FerveoVariant::Precomputed` doc comment saying
    "n of n" predates subset support.)

  Equivalent to the paper by bilinearity:
  `e([dk_i⁻¹]U, Y_i) = e([dk_i⁻¹]U, [f(ω_i)·dk_i]H) = e(U, [f(ω_i)]H) = e(U, Z_i)`.

The paper's G1 share survives as `ValidatorShareChecksum`: `C_i = [dk_i⁻¹]U`.
A raw G_T element carries no evidence it was computed as a pairing, so share
verification checks two equations (decryption.rs::ValidatorShareChecksum::verify):
1. `D_i == e(C_i, Y_i)` — binds the G_T value to the checksum;
2. `e(C_i, ek_i) == e(U, H)` — the paper's §4.4.4 check on the checksum.
Per the design note, verification is optimistic: combine unverified shares
first, run the checks only if payload decryption fails.

## Invariants and their fences

- **Wire format**: every serialized object is bincode-1-default (fixint
  LE, u64 length prefixes) wrapping arkworks `serialize_compressed`
  points (`ferveo-common/src/serialization.rs`). Fenced by
  `ferveo/tests/wire_format.rs` golden vectors generated by pre-2026
  builds. A failure there is a compatibility break with deployed
  artifacts — never regenerate the fixture to silence it.
- **Hash-to-curve**: RFC 9380 BLS12381G2_XMD:SHA-256_SSWU_RO_ via
  miracl_core, converted to arkworks points with a byte-order transform.
  Fenced by known-answer tests in `hash_to_curve.rs`.
- **Deterministic key derivation**: `Keypair::from_secure_randomness`
  depends on rand `StdRng` stream stability; fenced by the seeded-vector
  test in `wire_format.rs`.
- **Zeroization**: secret material (keys, shares, PRF inputs, the AEAD
  key inside chacha20poly1305 via its `zeroize` feature) is scrubbed on
  drop. When touching ciphertext.rs or key types, preserve this.

## Deliberate dependency pins (July 2026)

| Dep | Pinned at | Why |
|---|---|---|
| rand / rand_core | 0.8 / 0.6 | ark-std 0.6 re-exports rand 0.8; RNGs flow into arkworks traits. Move only with arkworks |
| bincode | 1.3.3 | Upstream abandoned (3.0.0 = compile-error tombstone). Verified advisory-free; it IS the wire format. Exit options researched: wincode (byte-compat) or borsh (format break) |
| miracl_core | =2.7.0 (exact) | Fp2 byte order changed between minors before (2.3→2.7 swapped halves); bump only with KATs green |

Everything else is current as of 2026-07 (arkworks 0.6, RustCrypto 0.11
wave, serde_with 3, criterion 0.8). Toolchain 1.97.1, pinned in
`rust-toolchain.toml` + `mise.toml` — keep in sync. Effective MSRV 1.89
(enum-ordinalize, pulled in by arkworks 0.6).

## Consumption

opacity-stack consumes `ferveo` (and transitively the rest) as a
rev-pinned git dependency in its workspace `Cargo.toml`. After landing
changes here: push, update the `rev` there, run opacity-stack's tests.
Crates are not published to crates.io; crate names (`ferveo` etc.) exist
only in this git source.

## History note

The nucypher-era python bindings, wasm bindings, mdbook docs, and
per-crate changelogs were removed in July 2026 (git history has them).
Pre-fork provenance: three code comments intentionally retain nucypher
links (rust-umbral attribution in `secret_box.rs`; two issue links
explaining crypto decisions in `decryption.rs` and `pvss.rs`).
