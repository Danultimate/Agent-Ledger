# AgentLedger v2 Threat Model

This document is a **v2 entry gate** (see [roadmap.md](roadmap.md)). It defines
exactly which attacks v2's cryptographic delegation proof defeats, which it does
not, and the assumptions everything else rests on. The signing design must be
traceable back to a threat here — if a mechanism doesn't mitigate a listed
threat, it doesn't belong in v2.

It uses STRIDE (Spoofing, Tampering, Repudiation, Information disclosure, Denial
of service, Elevation of privilege) as a checklist, not a straitjacket.

---

## 1. What v2 is trying to achieve

v1 can answer: *"the recorded action's strings matched the recorded receipt, and
the log wasn't edited afterwards."*

v2 raises that to: *"the action was performed by the cryptographically
identified agent, under a delegation the principal actually signed, that had not
expired or been replayed."*

The single sentence v2 must earn the right to say:

> **A `within_delegation = True` verdict means the named agent proved, with a
> verifiable signature, that it acted under a grant the named principal issued.**

---

## 2. Assets (what we protect)

| # | Asset | Why it matters |
|---|-------|----------------|
| A1 | **Delegation authenticity** — that a receipt's grant truly came from the named principal | The whole authorization story collapses if receipts can be forged |
| A2 | **Agent identity binding** — that the workload presenting a receipt is the named agent | Without this, any process can claim any agent's delegation |
| A3 | **Proof integrity** — the tamper-evident action log (inherited from v1) | Audit value; non-repudiation |
| A4 | **Freshness** — that grants are time-bounded and not replayable | A leaked old receipt must not grant indefinite power |
| A5 | **Signing keys / SVIDs** (in the environment, not in AgentLedger) | Compromise breaks A1/A2 — explicitly out of our control (see §6) |

---

## 3. Trust boundaries & actors

```
   ┌──────────────┐  signs receipt   ┌───────────────┐  presents receipt   ┌──────────────┐
   │  Principal   │ ───────────────▶ │   Agent /     │ ──────────────────▶ │ AgentLedger  │
   │ (human/owner)│   (private key)  │   Workload    │   + agent SVID      │  (verifier)  │
   └──────────────┘                  └───────────────┘                     └──────────────┘
        A1                                  A2                                   A3/A4
```

- **Principal** — issues and signs receipts. Trusted to act in its own interest;
  **not** assumed honest toward third parties (see malicious-principal residual).
- **Agent / workload** — the entity that runs tools. May be **honest, buggy, or
  fully malicious**. This is the primary adversary v2 defends against.
- **AgentLedger (verifier)** — runs in the agent's process in v1/v2. Trusted to
  execute correctly; see the in-process-verifier residual risk (§6).
- **Key / identity infrastructure** — principal signing keys, SPIFFE/SPIRE
  issuing SVIDs. Trusted infrastructure; AgentLedger is a *consumer*, not a CA.

The boundary v2 hardens is **agent → AgentLedger**: an untrusted agent must not
be able to manufacture a passing verdict.

---

## 4. Attacker model

**Primary adversary: a malicious or compromised agent/workload** that wants a
`within_delegation = True` verdict (or a clean log) for an action it was not
delegated to perform.

Assumed attacker capabilities:
- Can call any tool with any input.
- Can read its own process memory and any receipt handed to it.
- Can craft, modify, replay, and reorder receipts it presents to AgentLedger.
- Can read and attempt to write the on-disk proof log (same-host).
- **Cannot** obtain the principal's private signing key (that's a residual, §6).
- **Cannot** obtain another agent's SVID private key from SPIRE.

Out of scope as attackers (this release): network MITM on a hardened TLS channel,
host kernel compromise, malicious AgentLedger build / supply chain (tracked
separately), and the principal itself (see §6).

---

## 5. Threats and v2 mitigations

### T1 — Forged receipt (Spoofing / Elevation) — **MITIGATED**
*Agent fabricates a receipt granting itself tools/scopes the principal never
approved.*
- **v1 status:** undetected — receipts are advisory, unsigned.
- **v2 mitigation:** receipts carry a principal signature over the frozen
  `agentledger.receipt.v1` canonical bytes. Verification recomputes the bytes
  and checks the signature against the principal's public key. A forged or
  edited receipt yields `signature_invalid`.

### T2 — Receipt tampering (Tampering / Elevation) — **MITIGATED**
*Agent takes a real narrow receipt and widens `permitted_tools`/`scopes`.*
- **v2 mitigation:** any field flip changes the canonical bytes → signature
  fails. (`_v` tag is inside the signed payload, so the format itself is bound.)

### T3 — Agent impersonation (Spoofing) — **MITIGATED (with SPIFFE)**
*Process B presents a receipt issued to agent A and acts as A.*
- **v2 mitigation:** the workload must present a SPIFFE SVID whose identity
  matches the receipt's `agent`. Mismatch → `identity_mismatch`. Without an
  identity provider configured this threat is only **partially** mitigated (the
  receipt is authentic but the bearer is unverified — see §6 residual R4).

### T4 — Receipt replay after expiry (Tampering/freshness) — **MITIGATED**
*Agent reuses a leaked, expired receipt.*
- **v2 mitigation:** `expires_at`/`issued_at` are inside the signed payload, so
  they cannot be extended; v1 already records `receipt_expired`, now on a
  *signed* basis (the expiry is authentic, not agent-asserted).

### T5 — Receipt replay across context (Tampering) — **PARTIALLY MITIGATED**
*A receipt legitimately issued for one session/audience is reused elsewhere.*
- **v2 mitigation (planned):** optional `audience`/`nonce` claims in the signed
  payload, checked at verify time. Without them, a valid unexpired receipt is
  reusable within its lifetime — documented limitation, candidate for the v2
  payload via the version tag.

### T6 — Scope under-checking (Elevation) — **MITIGATED**
*v1 checked `permitted_tools` but not `permitted_scopes`.*
- **v2 mitigation:** per-call declared scope is checked against the signed
  `permitted_scopes`; failure records `scope_not_permitted` (the
  `ScopeViolation.scope_required` field already exists for this).

### T7 — Log tampering after the fact (Tampering/Repudiation) — **MITIGATED (evidence only)**
*Attacker edits the proof log.*
- **Status:** unchanged from v1 — hash-chain makes edits **evident**, not
  impossible. An attacker with write access can rewrite the whole chain unless
  the log is externally anchored (out of v2 scope; noted as residual R3).

### T8 — Downgrade / "unsigned is fine" (Spoofing) — **MITIGATED by policy**
*Agent presents an unsigned (v1-style) receipt to dodge signature checks.*
- **v2 mitigation:** verification policy. Unsigned receipts are recorded with an
  explicit `unsigned`/`unverified` marker and **never** counted as
  `within_delegation = True` under a `require_signed` policy. Default policy must
  fail safe — an unsigned receipt must not silently read as verified (this was
  review finding D6's lesson applied to crypto).

### T9 — Signature stripping (Tampering) — **MITIGATED**
*Agent removes the signature and submits the bare payload.*
- **v2 mitigation:** same as T8 — no signature means not-verified, not pass.

### T10 — Algorithm confusion / `alg=none` (Spoofing) — **MITIGATED by design**
*If receipts are JWT/JWS-like, attacker sets `alg=none` or swaps RS↔HS.*
- **v2 mitigation:** the verifier pins the accepted algorithm(s); `none` is never
  accepted; the key type must match the pinned algorithm. (A classic JWT footgun
  — called out so the implementation forbids it explicitly.)

---

## 6. Residual risks (explicitly NOT solved by v2)

These remain true after v2 ships and **must stay in the README/security docs**:

- **R1 — Compromised principal signing key.** If the key leaks, an attacker
  signs valid receipts. AgentLedger is a verifier, not a key-management system;
  key custody, rotation, and revocation live in the principal's infrastructure.
- **R2 — Malicious principal.** A principal can legitimately grant an agent
  broad power and sign it. v2 proves the grant is authentic, not that it was
  *wise*. Authorization policy is the principal's responsibility.
- **R3 — Log not externally anchored.** Hash-chain is tamper-*evident*, not
  tamper-*proof*; an attacker with log write access can rebuild the chain.
  External anchoring (timestamping, append-only service, git) is out of scope.
- **R4 — No identity provider configured.** If SPIFFE/SPIRE (or another agent
  identity source) is not wired in, T3 is only partially mitigated: receipts are
  authentic but the *bearer* is not cryptographically bound. Must be loud in docs
  and in the verdict (e.g. `identity_unverified`).
- **R5 — In-process verifier.** In v1/v2 AgentLedger runs inside the agent's
  process; a fully compromised agent can avoid calling it at all, or tamper with
  it in memory. v2 proves authenticity *of receipts the agent chooses to
  present* — it does not make an out-of-band, independent control plane. (A
  separate verifier service is a potential future direction, not v2.)
- **R6 — Confidentiality of inputs.** Unchanged: input/output digests are
  tamper-evidence, not encryption; proof logs remain sensitive.

---

## 7. Assumptions

1. The principal's private key is held by the principal and not the agent.
2. A canonical, byte-stable, versioned receipt serialization exists and is frozen
   (✅ shipped in v1: `agentledger.receipt.v1`).
3. Clocks are roughly synchronized (NTP) for expiry checks; gross skew is a known
   v1 limitation carried forward.
4. Where agent identity binding is required, a SPIFFE/SPIRE deployment (or a
   pluggable equivalent) is available; otherwise the operator accepts R4.
5. AgentLedger executes as built (no in-process tampering) — see R5.

---

## 8. Implications for the v2 design (traceability)

Each must trace to a threat above:

- Sign the **full** canonical receipt payload incl. `_v`, `receipt_id`,
  `issued_at`, `expires_at`. → T1, T2, T4
- Pin signature algorithm(s); forbid `none` and key/alg mismatch. → T10
- Fail-safe verification policy: unsigned/stripped ⇒ not verified, never pass;
  `require_signed` option. → T8, T9
- Pluggable identity provider; verdict distinguishes
  `identity_verified` / `identity_unverified` / `identity_mismatch`. → T3, R4
- Enforce `permitted_scopes` with a `scope_not_permitted` violation. → T6
- Optional `audience`/`nonce` claims (via the version tag) for context binding.
  → T5
- Keep, and keep honest, the v1 tamper-evidence + residual-risk disclosures.
  → T7, R1–R6
