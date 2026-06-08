# Changelog

All notable changes to AgentLedger are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-06-08

### Added — v2 cryptographic delegation proof
- **Signed receipts** (Ed25519): `Receipt.sign(private_key)` signs the frozen
  `agentledger.receipt.v1` canonical bytes; `agentledger.signing` provides
  `generate_keypair`, `sign`, `verify`, and key (de)serialization. Requires the
  `crypto` extra.
- **Trusted-key verification**: `KeyProvider` / `InMemoryKeyProvider`. Signatures
  are checked only against keys the verifier already trusts — never one embedded
  in the receipt.
- **`require_signed` policy** on `@ledger.record`. Default stays graceful:
  unsigned receipts are recorded with `signature_verified=None` and never
  reported as verified; `require_signed=True` makes unsigned/unverifiable a
  violation.
- **Scope checks**: `scopes=[...]` on `@ledger.record` verifies each against the
  receipt's `permitted_scopes` (`scope_not_permitted`).
- **Pluggable agent identity** (`IdentityProvider`): `StaticIdentityProvider`
  and `SpiffeIdentityProvider` (SPIFFE-ID match; `spiffe` extra). No provider
  configured ⇒ `identity_status="unverified"` (honest marker, not failure).
- New proof fields `signature_verified` and `identity_status`, surfaced in
  verdicts; new violation types `signature_missing`, `signature_invalid`,
  `signature_unverifiable`, `identity_mismatch`, `scope_not_permitted`.
- Docs: `docs/threat-model.md`, `docs/v2-design.md`.

### Security
- v2 raises a `within_delegation=True` verdict on a signed receipt to mean *the
  named agent acted under a grant the principal cryptographically signed*. The
  `within_delegation` outcome stays hash-chained; the new crypto-status fields
  are recorded but (this release) not hash-chained — `within_delegation` is the
  load-bearing, tamper-evident outcome. Residual risks (compromised key,
  malicious principal, in-process verifier, un-anchored log) are documented in
  the threat model and remain out of scope.

## [0.1.0] - 2026-06-08

Initial release. Action-time proof and delegation verification for MCP agents.

### Added
- `@ledger.record` decorator for MCP tool handlers — works on **sync and async**
  functions with zero restructuring, and is safe to call from inside a running
  asyncio loop.
- `on_violation` policy on the decorator: `"record"` (default, audit-only),
  `"warn"`, or `"raise"` (`DelegationViolation`). The proof is always recorded
  before any signal.
- Advisory delegation receipts (`Receipt`) with `issue_receipt()`, tool/scope
  permission checks, and expiry.
- Frozen, version-tagged signable receipt serialization
  (`Receipt.signing_payload()` / `canonical_bytes()`, `agentledger.receipt.v1`)
  so v2 cryptographic signing is non-breaking.
- Tamper-evident, hash-chained append-only JSONL proof log
  (`agentledger.chain.v1`). Chain head is restored from disk on startup so
  proofs stay linked across process restarts; appends take an advisory file
  lock for concurrency safety.
- `Verifier` / `Verdict` with human-readable explanations and remediation.
- Reports: Rich terminal output and a self-contained, dependency-free HTML report.
- CLI: `init`, `report`, `verify` (exit 1 on recorded violations), `chain`
  (exit 1 on tamper). `report` always exits 0 (informational).
- Automatic, silent TraceForge (`agentrace-llm`) span enrichment when installed;
  a one-time warning makes the no-op discoverable when it is not.
- Docs: `README.md`, `docs/wimse-alignment.md`, `docs/roadmap.md`; runnable
  examples; GitHub Actions audit example.

### Security
- Honest trust model throughout: AgentLedger **records and attributes** actions;
  it does **not** enforce authorization by default, and hash-chaining is
  tamper-evidence, not proof of execution-time authorization. Input/output
  digests are tamper-evidence, not confidentiality — treat proof logs as
  sensitive.

[Unreleased]: https://github.com/Danultimate/Agent-Ledger/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Danultimate/Agent-Ledger/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Danultimate/Agent-Ledger/releases/tag/v0.1.0
