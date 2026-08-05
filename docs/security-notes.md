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
   transcripts), none of which opacity-stack currently uses. See §3 before
   enabling any of those.

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

## 2. Degenerate-input (identity-point) rejection

Identity points satisfy pairing-based validity checks vacuously — `e(𝒪, ·) = 1`
on both sides of any equation — so every such check must exclude them
explicitly. All rejections are verification-side only, with no wire-format
consequence, and regression tests live in `ferveo/tests/degenerate_inputs.rs`.

What the checks enforce:

- **`PubliclyVerifiableSS::verify_optimistic` rejects an identity constant term
  `F₀`.** Without this, an all-identity aggregate (`coeffs = [𝒪; t]`,
  `shares = []`, `σ = 𝒪`) satisfied the proof-of-knowledge pairing as
  `e(𝒪, G₂) == e(G₁, 𝒪)`, i.e. `1 == 1`, and yielded the identity as the DKG
  public key — not usefully encryptable-to, and no secret exposed, but a
  `verify() == Ok(true)` that tells the caller something false. The check
  covers per-dealer transcripts and aggregates alike. For a single dealer an
  identity `F₀` means a zero secret (negligible probability), but an
  aggregate's `F₀` is the *sum* of dealer terms, which colluding dealers can
  drive to the identity deliberately — the rejection is load-bearing there.
- **Every dealer transcript is verified in its own right during aggregation
  verification.** `do_verify_aggregation` runs `verify_optimistic` on each
  transcript before summing. An identity transcript contributes nothing to
  that sum, so without this an aggregate produced by a *single* dealer
  verified against a message set padded out with identity transcripts — the
  caller was told a `t`-of-`n` dealer set had contributed when one dealer had,
  and that dealer alone knows the DKG secret. The DKG path already rejected
  such transcripts at dealing time (`dkg::verify_transcripts`); the standalone
  verification path did not.
- **`do_verify_full` pins the committed polynomial's degree, not just its
  coefficient count.** Trailing identity coefficients pad a lower-degree
  polynomial out to `security_threshold` entries: the count check passes while
  the effective threshold is lower. In the limit the commitment is to the
  constant `φ(x) = s`, every validator's share is `s`, and any *single* share
  reconstructs the secret while verification reports `security_threshold`.
  Coefficients are now counted up to the last non-identity one
  (`Error::InvalidTranscriptDegree`).
- **The core-layer verifiers enforce these rejections independently.**
  `do_verify_full` (hence `verify_full` and `verify_aggregation`) rejects an
  identity `F₀` and an empty validator set — the per-validator loop is the
  only place shares are checked, so an empty set would verify vacuously — and
  `do_verify_aggregation` rejects an empty transcript list
  (`Error::NoTranscriptsToVerify`). The guarantees therefore do not depend on
  entering through `ferveo::api`; they hold for any consumer of the public
  core functions, under any deployment topology.
- **`AggregatedTranscript::verify` binds the serialized `public_key` field to
  the committed polynomial** (`Error::InvalidAggregatePublicKey`). The field
  is bound to `F₀` only at construction and travels as its own serialized
  field, so before this check a deserialized aggregate could pass `verify`
  while `public_key()` returned an arbitrary attacker-chosen point — the
  identity-public-key footgun by another door.
- **`AggregatedTranscript::verify` requires a non-empty message set**
  (`Error::NoTranscriptsToVerify`). With zero messages, the per-validator and
  aggregation-sum checks below it are vacuously true. The settled
  message-count contract is `1 ≤ messages.len() ≤ validators_num`: verifying
  an aggregate built from a subset of validators is legitimate (fewer dealers
  than validators is a supported configuration), so no exact-count rule
  applies; which dealer set to expect is the caller's knowledge.
- **`CiphertextHeader::check` rejects an identity commitment `U` or auth tag
  `W`** (`Error::CiphertextVerificationFailed`). The §4.4.2 gate
  `e(U, H_G2(U, ciphertext_hash, aad)) · e(-G, W) == 1` held for `U = W = 𝒪`
  under **any** `aad` and any ciphertext hash — bypassed rather than
  satisfied — and nodes would emit (degenerate, non-secret-bearing) decryption
  shares for objects `encrypt()` could never have produced. This gate is what
  makes the decryption endpoint safe as a decryption oracle (IND-CCA2), so it
  holds unconditionally, regardless of deployment trust.

### Rationale: rejecting identity points is safe and sufficient

The arguments are elementary and need no external cryptographic review (unlike
the multi-dealer bundle in §3, which still warrants one if it ever becomes
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
   regardless of call sites — a verifier's meaning should not depend on caller
   topology.

## 3. If/when the single-operator, single-dealer model changes

Today one operator runs both the director and every node, and the director is
the sole dealer (§1). Everything in this file that is conditioned on that model
is collected here, so it is revisited — not rediscovered — when the model
changes. Two distinct triggers, which can arrive independently:

### Trigger: multiple operators (federated nodes or director)

- **Nodes do not verify the director-supplied aggregate.** opacity-stack nodes
  deserialize the aggregate they receive and use it without calling `verify`
  (opacity-stack `node/src/dkg.rs`). Fine while the director is operator-run;
  a federated deployment must add node-side verification of the aggregate
  against the ceremony messages.

Deliberately **not** conditioned on this trigger: the §2 ciphertext-validity
rejection. That gate exists precisely so the node's decryption endpoint is
safe as a decryption oracle; it must hold unconditionally, regardless of who
can reach the endpoint today.

### Trigger: multiple dealers (a p2p DKG, or the refresh/handover flows)

A fully decentralized DKG — every party generating and broadcasting its own
transcript — is a plausible future direction if the system keeps its current
architecture, but it is **not planned or designed today** (too many unknowns to
commit to it). The refresh/handover subsystems are a nearer multi-party-dealing
flow (see `docs/refresh-handover-roadmap.md`). Either one introduces multiple
dealers — exactly what §1's rationale point 2 rules out today. Footguns to
revisit *before* enabling any multi-party dealing:

- **§1's rationale point 1 stops being a footnote and becomes the operative
  security argument.** Today the AGM/KOE reduction is never exercised — there is
  no adversarial dealer. Under multi-dealer, a malicious dealer can try to
  choose its contribution as a function of the others' (rogue-key style), and
  aggregation soundness then rests entirely on the AGM/KOE proof-of-knowledge of
  `σ`. That dependency must be accepted deliberately (and ideally independently
  reviewed), not inherited silently.
- **`σ` is proof of *possession*, not extractable knowledge without the AGM.** A
  deployment that cannot assume the AGM would need `σ` replaced by an extractable
  PoK (Schnorr / Fiat–Shamir) — a wire-format-breaking change.
- **Attested TEEs substitute for the PoK only if *every* dealer is enclaved.**
  Leaning on enclave-honest generation instead of an extractable `σ` holds only
  when all parties run attested TEEs; a DKG across parties that are not all
  enclaved loses that out-of-band guarantee, leaving only the AGM/KOE argument.
- **Identity-rejection (§2) does not address multi-dealer key biasing.** A
  rushing dealer in a multi-dealer flow could force `F₀` to any chosen value —
  `𝒪` is merely one of them. Key-bias resistance rests on the σ
  proof-of-knowledge above, not on the §2 fixes.
