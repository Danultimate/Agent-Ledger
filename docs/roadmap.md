# AgentLedger Roadmap

This document is the authoritative scope for AgentLedger versions beyond v1. It
exists because the original spec only implied v2/v3 through scattered non-goal
annotations (`# placeholder for v2 cryptographic binding`, "mid-chain revocation
(v3)", "AgentLedger v2 will support SPIFFE SVID verification"). Here those are
made explicit, with the trust-model rationale and concrete entry/exit criteria.

## The trust gap each version closes

AgentLedger v1 makes one honest, deliberately narrow claim:

> It **records** what an agent did and whether it matched the receipt, in a
> **tamper-evident** log. It does **not** prove the action was authorized at
> execution time by a cryptographically verified identity, and it does not
> enforce delegation by default.

Each subsequent version closes a specific part of that gap:

| Version | Closes the gap between… | …and |
|---------|------------------------|------|
| v1 (shipped) | "no record" | "tamper-evident record of intent vs. action" |
| **v2** | "record of intent" | "cryptographic proof the named agent acted within a signed delegation" |
| **v3** | "single signed delegation" | "live, revocable, multi-hop delegation chains" |

---

## v1 — Shipped (baseline)

For reference, the line v2 builds on:

- `@ledger.record` decorator (sync + async, non-blocking by default, `on_violation` opt-in)
- Advisory delegation receipts (`wimse_compatible` is a structural marker, **not** verified)
- Hash-chained, append-only JSONL proof log; chain head restored across restarts
- Verdicts, terminal/HTML reports, CLI with violation/tamper exit codes
- Silent TraceForge enrichment

**Known v1 limitations (intentional, documented):** no enforcement by default,
no crypto identity binding, single-writer storage, log not externally anchored,
unsalted truncated input digests (tamper-evidence, not confidentiality).

---

## v2 — Cryptographic delegation proof

**Theme:** turn the advisory receipt into a verifiable one. After v2, a verdict
of "within delegation" means *the named agent cryptographically proved it acted
under a signed receipt issued by the named principal* — not just "the strings
matched."

### In scope

1. **Signed receipts.** Populate the existing `Receipt.signature` field. The
   principal signs the receipt's canonical payload; AgentLedger verifies the
   signature at record time. Receipt fingerprint becomes the signed digest.
2. **SPIFFE/SPIRE SVID verification.** Verify that the workload presenting a
   receipt holds the X.509 SVID matching the receipt's `agent` identity. This is
   the "which agent are you?" layer actually being checked, not just declared.
3. **Real WIMSE WPT verification.** Validate receipts as Workload Proof Tokens
   (signature, issuer, audience, `exp`/`iat`), upgrading `wimse_compatible` from
   a marker to an enforced contract.
4. **Scope-level checks.** v1 checks `permitted_tools`; v2 also verifies
   `permitted_scopes` against a declared per-call scope, with a
   `scope_not_permitted` violation path (the `ScopeViolation` type already
   reserves `scope_required`).
5. **Pluggable key/identity providers.** An interface for resolving principal
   signing keys and agent SVIDs (local keypair, SPIRE workload API, JWKS URL).

### Explicitly NOT in v2 (pushed to v3 or out)

- Multi-hop delegation chains (v3)
- Mid-chain revocation (v3)
- A hosted key-management or PKI service (out of scope — bring your own)

### Entry criteria (do not start v2 until all true)

- [ ] v1 is published to PyPI and the trust-model docs are live and accurate.
- [ ] A written threat model exists naming exactly which attacks v2 defeats
      (forged receipt, agent impersonation, expired-but-replayed receipt) and
      which it does not (compromised signing key, malicious principal).
- [x] A canonical, versioned receipt serialization is specified and frozen.
      **Done in v1:** `Receipt.signing_payload()` / `Receipt.canonical_bytes()`
      emit a byte-stable, `agentledger.receipt.v1`-tagged payload
      (`agentledger.canonical`), locked by a golden test. v2 signs exactly these
      bytes; the proof-chain payload is likewise tagged `agentledger.chain.v1`.
- [ ] Decision on crypto dependency made (e.g. `cryptography` / `pyjwt` /
      `py-spiffe`) with maintenance and supply-chain review.

### Exit criteria (v2 is done when)

- [ ] A tampered or forged receipt signature produces a verifiable
      `signature_invalid` violation, with a test.
- [ ] An agent SVID that does not match the receipt's `agent` produces an
      `identity_mismatch` violation, with a test.
- [ ] A verdict can answer "was this action authorized?" with a cryptographic
      basis, and the README can drop the "does not prove authorization at
      execution time" caveat for the v2 path **without overclaiming**.
- [ ] Backward compatibility: v1 unsigned receipts still record (as
      `within_delegation` with an explicit `unsigned`/`unverified` marker),
      never silently treated as verified.

---

## v3 — Live, revocable, multi-hop delegation

**Theme:** move from a single signed grant to a delegation *graph* that can be
revoked while it is still in flight.

### In scope

1. **Multi-hop delegation chains.** principal → agent A → agent B. Each hop is a
   receipt that references its parent; AgentLedger verifies the whole chain back
   to the root principal and that each hop only narrows (never widens) scope.
2. **Mid-chain revocation.** A principal (or any intermediate delegator) can
   revoke a delegation, and in-flight actions under a revoked link become
   violations. Requires a revocation source of truth (revocation list, status
   endpoint, or short-lived re-issuance) — exact mechanism to be specified at
   v3 entry.
3. **Delegation introspection.** Report/verdict surfaces showing the full chain
   for a proof: who delegated what to whom, and the live revocation status of
   each hop.

### Explicitly NOT in v3

- A hosted revocation service / SaaS control plane (out of scope for the OSS lib)
- Cross-organization federation of trust roots (potential v4+)

### Entry criteria

- [ ] v2 shipped: signed receipts + identity verification are real, because a
      delegation *chain* is only as trustworthy as each *signed* link.
- [ ] Revocation mechanism chosen and its freshness/latency trade-offs
      documented (a revocation that propagates in minutes is a different product
      than one that propagates in milliseconds).
- [ ] Scope-narrowing semantics formally specified (what it means for hop B to
      be "within" hop A).

### Exit criteria

- [ ] A 3-hop chain verifies end-to-end, and widening scope at any hop is a
      tested violation.
- [ ] Revoking a mid-chain link causes subsequent actions to record a
      `delegation_revoked` violation, with a test.
- [ ] A verdict can render the full delegation provenance for any proof.

---

## Permanent non-goals (never on this roadmap)

These are out of scope at every version — listed so they are not mistaken for
"not yet":

- Replacing OAuth 2.1 or any identity provider
- Acting as a key-management / PKI / certificate authority
- Enterprise compliance deliverables (SOC 2, legal liability)
- Competing with Prefactor (enterprise) or KYA-OS (DID-based) on their terms

---

## Status

| Item | Version | Status |
|------|---------|--------|
| Action recording + tamper-evident log | v1 | ✅ Shipped |
| `on_violation` enforcement opt-in | v1 | ✅ Shipped |
| Frozen, version-tagged receipt/chain serialization | v1 | ✅ Shipped (v2 prerequisite) |
| Signed receipts (Ed25519, `Receipt.sign`) | v2 | ✅ Implemented |
| Trusted-key verification (`KeyProvider`) | v2 | ✅ Implemented |
| `require_signed` policy + scope checks | v2 | ✅ Implemented |
| Pluggable agent identity (`IdentityProvider`) | v2 | ✅ Implemented |
| SPIFFE-ID matching (`SpiffeIdentityProvider`) | v2 | 🟡 Partial (ID match; full SVID chain validation deferred) |
| `audience`/`nonce` context binding (T5) | v2.x | ⬜ Planned |
| Multi-hop delegation chains | v3 | ⬜ Planned |
| Mid-chain revocation | v3 | ⬜ Planned |
