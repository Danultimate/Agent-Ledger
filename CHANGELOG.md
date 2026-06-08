# Changelog

All notable changes to AgentLedger are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Planned for v2 (cryptographic delegation proof) — see [docs/roadmap.md](docs/roadmap.md):
signed receipts, SPIFFE/SPIRE SVID verification, enforced WIMSE WPT validation,
and scope-level checks.

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

[Unreleased]: https://github.com/Danultimate/Agent-Ledger/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Danultimate/Agent-Ledger/releases/tag/v0.1.0
