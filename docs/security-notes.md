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

### σ reuse audit (2026-07-23)

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
