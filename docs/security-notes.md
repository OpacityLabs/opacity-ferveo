# Security Notes

Deliberate cryptographic decisions and assumptions for opacity-ferveo.
This file is the authoritative record; keep it in sync with the code.

## 1. PVSS proof-of-knowledge (σ): AGM / KOE assumption — accepted

### Construction

Each PVSS dealer publishes a proof-of-knowledge element `σ = s·G₂` alongside the
constant-term commitment `F₀ = s·G₁` (which is also the DKG public key). The
verifier checks

```
e(F₀, G₂) == e(G₁, σ)        # PubliclyVerifiableSS::verify_optimistic
```

This is a **discrete-log-equality / proof-of-possession**, not an extractable
NIZK. It establishes that `σ` is `s·G₂` for the same `s` as `F₀ = s·G₁`.

### The assumption

Its role as a *proof of knowledge of the secret* in the aggregatable-DKG
soundness argument — i.e. precluding a dealer from choosing its contribution
adaptively as a function of honest dealers' contributions (a rogue-key style
attack) — holds only under the **Algebraic Group Model (AGM)** / a
**knowledge-of-exponent (KOE)** assumption. A bare pairing equality does not, on
its own, let a security reduction *extract* the witness `s`.

### Decision: accepted as-is (no code change)

Rationale:

1. **The aggregation reduction is sound under the AGM/KOE.** The security
   argument for PVSS transcript aggregation reduces to `σ` being a proof of
   knowledge of the dealer's secret `s` — extractability is precisely what
   prevents a dealer from choosing its contribution as a function of the others'.
   Under the AGM (equivalently, a knowledge-of-exponent assumption), the
   discrete-log-equality check `e(F₀,G₂)=e(G₁,σ)` supplies that proof of
   knowledge: an algebraic dealer's representation of its contribution exposes the
   witness, so the reduction goes through. The question is whether *this*
   reduction is sound under the AGM — it is — not whether the AGM is acceptable in
   general.
2. **Single dealer in the current deployment.** The DKG is conducted
   centrally: the opacity-stack director is the sole dealer, generating all
   shares itself and distributing them to the nodes. Rogue-key-style adaptive
   contribution requires multiple dealers and cannot arise at all today. The
   assumption becomes operative only if a multi-dealer flow is adopted — a
   p2p DKG, or the refresh/handover/recovery subsystems (multi-party update
   transcripts), none of which opacity-stack currently uses. Revisit this
   section before enabling any of those.

Independently, `σ` is **wire-format-locked**: it is serialized into every
transcript and pinned by the golden vectors in `ferveo/tests/wire_format.rs`, so
any change to its construction (for example, deriving it from a hash-to-curve
base point instead of the fixed `G₂` generator) would be a coordinated
compatibility migration regardless of the security argument.

Full background, the alternatives considered, and the notation:
Opacity crypto review brief —
<https://claude.ai/code/artifact/0728ea94-3bc0-400e-a0a0-725a141feaf2> (internal).
References: IACR ePrint 2022/898 §4.2.3; upstream NuCypher ferveo issue #44. This
topic was formerly tracked upstream as #201 (and the hash-to-curve base-point
note as #195).

### If/when the DKG becomes multi-dealer

A fully decentralized DKG — every party generating and broadcasting its own
transcript — is a plausible future direction if the system keeps its current
architecture, but it is **not planned or designed today** (too many unknowns to
commit to it). The refresh/handover subsystems (#200) are a nearer
multi-party-dealing flow. Either one introduces multiple dealers — exactly what
point 2 (single dealer) rules out today. Footguns to revisit *before* enabling
any multi-party dealing:

- **Point 1 stops being a footnote and becomes the operative security argument.**
  Today the AGM/KOE reduction is never exercised — there is no adversarial dealer.
  Under multi-dealer, a malicious dealer can try to choose its contribution as a
  function of the others' (rogue-key style), and aggregation soundness then rests
  entirely on the AGM/KOE proof-of-knowledge of `σ`. That dependency must be
  accepted deliberately (and ideally independently reviewed), not inherited
  silently.
- **`σ` is proof of *possession*, not extractable knowledge without the AGM.** A
  deployment that cannot assume the AGM would need `σ` replaced by an extractable
  PoK (Schnorr / Fiat–Shamir) — a wire-format-breaking change.
- **Attested TEEs substitute for the PoK only if *every* dealer is enclaved.**
  Leaning on enclave-honest generation instead of an extractable `σ` holds only
  when all parties run attested TEEs; a DKG across parties that are not all
  enclaved loses that out-of-band guarantee, leaving only the AGM/KOE argument.

None of this affects the current single-dealer deployment; it is recorded so the
assumption is revisited — not rediscovered — if the architecture moves that way.

### σ reuse audit

`σ` appears **only** in `ferveo/src/pvss.rs`; no other crate or module in the
workspace (`ferveo-tdec`, `ferveo-common`, `subproductdomain`, and the rest of
`ferveo`) references it. By role:

| Site | Role |
|---|---|
| `PubliclyVerifiableSS::new` | Produces `σ = s·G₂` (per transcript) |
| `aggregate()` | Produces the aggregate `σ = Σ σᵢ` |
| `verify_optimistic` | **Sole verification consumer** — `e(F₀,G₂)==e(G₁,σ)`, invoked per-transcript (`dkg::verify_transcripts`) and on the aggregate (`api::verify`) |
| `refresh()` | Copies `σ` forward unchanged into the refreshed aggregate |
| `finalize_handover()` | Copies `σ` forward unchanged into the post-handover aggregate |
| `Hash` impl | Includes `σ` in transcript identity for de-duplication — not a soundness check |
| `#[cfg(test)]` | Two references (an equality assertion and a tamper test) |

The two **copy-forward** sites (`refresh()`, `finalize_handover()`) are sound:
both operations preserve the shared secret `s = f(0)` — refresh applies update
polynomials with `g(0)=0`, and handover only re-blinds a single share — so
`F₀ = s·G₁` and `σ = s·G₂` remain the correct, matching proof-of-knowledge. The
carried-forward `σ` therefore still satisfies `verify_optimistic` against the
unchanged `F₀`; no re-derivation is needed and none is missing.

**Conclusion:** `σ` is consumed for verification in exactly one place
(`verify_optimistic`). The refresh/handover copy-forward introduces no additional
or unsound consumption of `σ`.

## 2. Degenerate-input validity gaps — fix planned

Two validity checks accept degenerate (all-identity) inputs that the protocol
should reject. Neither is a crash or a key-recovery risk, and both fixes are
verification-side only, with no wire-format consequence. The rationale below
settles the cryptographic questions, so the remaining work is mechanical.

### 2.1 An all-identity aggregate verifies against an empty message set

`AggregatedTranscript::verify(validators_num, security_threshold, messages)`
checks only an *upper* bound on the message count (`validators_num <
messages.len()`). Nothing requires at least one message, and nothing requires
the aggregate's constant term `F₀` to be a non-identity point.

Given an aggregate with `coeffs = [𝒪; t]` (length equal to the security
threshold, so the degree check passes), `shares = []` and `σ = 𝒪`:

- `verify_optimistic` computes `e(𝒪, G₂) == e(G₁, 𝒪)`, i.e. `1 == 1` — passes.
- `do_verify_full` iterates over an empty validator set — vacuously true.
- The aggregation check sums an empty transcript list to `𝒪` and compares it to
  `F₀ = 𝒪` — equal.

Concretely, `verify(4, 3, &[])` returns `Ok(true)` on such an aggregate, and
the corresponding DKG public key is the identity.

Impact is bounded — an identity public key is not a key anyone can usefully
encrypt to, and no secret is exposed — but any caller treating `verify() == Ok(true)`
as "this aggregate is a real, usable DKG result" is being told something false.
Exposure is also nil until the fix lands: under the current single-operator
deployment, `verify` is invoked only by the director, on messages it just
generated itself. The fix is made in the library regardless — a verifier's
meaning should not depend on caller topology — and once it lands, this gap
stays closed under any deployment model.

### 2.2 The all-zero ciphertext header passes the §4.4.2 validity check

`CiphertextHeader::check` implements the ciphertext-validity gate as

```
e(U, H_G2(U, ciphertext_hash, aad)) · e(-G, W) == 1
```

With `U = 𝒪` and `W = 𝒪` both pairings are the identity of the target group, so
the product is `1` and the check passes **for any `aad` and any
`ciphertext_hash`** — the gate is bypassed rather than satisfied.

Concretely, a ciphertext whose commitment and auth tag are zeroed passes
validation under an AAD unrelated to the one it was encrypted with, and
`create_decryption_share_simple` returns a share for it.

The emitted share is itself degenerate (`D_i = e(𝒪, ·) = 1`, checksum `𝒪`), so no
key material leaks. The concern is that the IND-CCA2 ciphertext-validity gate —
the check that is supposed to make a decryption oracle safe — does not hold for
this input class, and nodes can be induced to do hash-to-curve and pairing work
and emit shares for objects that `encrypt()` could never have produced.

### Rationale: rejecting identity points is safe and sufficient

The arguments are elementary and need no external cryptographic review (unlike
the §1 multi-dealer bundle, which still warrants one if it ever becomes
operative).

1. **The identity is the only degenerate point that survives deserialization.**
   Every point this library ingests goes through
   `ferveo-common/src/serialization.rs`, which uses arkworks' *validating*
   `deserialize_compressed`: curve membership, prime-subgroup membership, and
   canonical encoding are all enforced at the wire boundary. Small-subgroup and
   non-canonical-encoding inputs are already rejected; the identity passes only
   because it is a legitimate subgroup member. No explicit subgroup check is
   needed alongside these fixes.

2. **Rejecting the identity is one-sided safe.** Honest `encrypt` produces
   `U = 𝒪` (equivalently `W = 𝒪`) only when the random scalar `r = 0`,
   probability ≈ 2⁻²⁵⁵; an honest aggregate has `F₀ = 𝒪` with the same
   negligible probability. The rejection can never refuse an input an honest
   party produced, so the accept-set change carries no compatibility or
   completeness risk.

3. **Rejecting `U = 𝒪` is also sufficient to restore the §4.4.2 gate.** With
   `U ≠ 𝒪` and subgroup membership guaranteed (point 1), `r = dlog_G(U)` is
   nonzero and well-defined, and non-degeneracy of the pairing means
   `e(U, H_G2(U, hash, aad)) = e(G, W)` holds only for the unique honest tag
   `W = [r]·H_G2(U, hash, aad)`. (`W = 𝒪` with `U ≠ 𝒪` then fails the check
   unless hash-to-curve outputs the identity — negligible under the RO model.)
   Rejecting identity `W` too is free belt-and-suspenders.

4. **Enforcement belongs in `verify`, not the caller.** A function named
   `verify` returning `Ok(true)` for an unusable aggregate is a footgun
   regardless of today's call sites. The message-count contract is part of the
   same question: the current check is only an upper bound (`validators_num <
   messages.len()` errors), where exact equality with the expected validator
   count is the natural contract.

### Planned fix

- `CiphertextHeader::check`: reject an identity commitment (`U`) or auth tag
  (`W`) before the pairing check.
- `AggregatedTranscript::verify`: require a non-empty message set and a
  non-identity constant term `F₀`; settle the exact message-count contract.
- Adversarial tests mirroring both degenerate examples above, asserting
  rejection.
- Wire format untouched; both changes are verification-side only.

### Single-operator trust assumptions — re-examine if the deployment changes

The current deployment has one operator running both the director and every
node (§1, "single dealer"). Facts that are acceptable *only* under that model,
labeled here so they are revisited — not rediscovered — if it changes:

- **Nodes do not verify the director-supplied aggregate.** opacity-stack nodes
  deserialize the aggregate they receive and use it without calling `verify`
  (opacity-stack `node/src/dkg.rs`). Fine while the director is operator-run;
  a federated deployment must add node-side verification of the aggregate
  against the ceremony messages.
- **Identity-rejection does not address multi-dealer key biasing.** A rushing
  dealer in a multi-dealer flow could force `F₀` to any chosen value — `𝒪` is
  merely one of them. That is the §1 AGM/KOE σ bundle, out of scope for this
  fix and moot under a single dealer.

Deliberately **not** on this list: gap 2.2. The ciphertext-validity gate exists
precisely so the node's decryption endpoint is safe as a decryption oracle; it
must hold unconditionally, regardless of who can reach the endpoint today.
