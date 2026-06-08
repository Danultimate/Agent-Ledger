# WIMSE Compatibility

AgentLedger delegation receipts are structurally aligned with the IETF WIMSE
(Workload Identity in Multi-System Environments) working group draft on agent
identity. **Alignment is structural and documented, not cryptographically
implemented** in v1.

## The three-layer model

AgentLedger occupies the third layer:

| Layer | Standard | What it does |
|-------|----------|--------------|
| Authentication | OAuth 2.1 | Who are you? |
| Workload identity | WIMSE WPT + SPIFFE/SPIRE | Which agent are you? |
| Action proof | AgentLedger | What did you do, recorded against whom? |

AgentLedger does not replace layers 1 or 2. It records what happened after
authentication and identity are established.

## WIMSE WPT alignment

AgentLedger receipts use the same conceptual fields as WIMSE Workload Proof
Tokens:

- `principal` → the human owner (maps to WIMSE subject)
- `agent` → the workload acting (maps to WIMSE workload identity)
- `permitted_scopes` → the delegation scope
- `issued_at` / `expires_at` → standard JWT time claims
- `wimse_compatible: true` → explicit alignment marker (a marker, not a proof)

## SPIFFE/SPIRE

For cryptographic agent identity binding (verifying the entity presenting a
receipt is actually the named agent), SPIFFE/SPIRE provides the right
infrastructure layer via short-lived X.509 SVIDs. AgentLedger v2 will support
SPIFFE SVID verification.

## What AgentLedger does NOT claim

Hash-chain integrity proves the proof log has not been tampered with after
recording — and only while the log is immutable or externally anchored. It does
NOT prove actions were authorized at execution time by a cryptographically
verified agent identity. The hash-chain head is restored from the persisted log
on startup so proofs across process restarts stay linked, but the log itself is
not externally anchored in v1. For stronger guarantees you need SPIFFE/SPIRE +
AgentLedger v2.
