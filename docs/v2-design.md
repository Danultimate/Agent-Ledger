# AgentLedger v2 Design — Cryptographic Delegation Proof

Implements the mitigations traced in [threat-model.md](threat-model.md). Scope is
v2.0; deferred items are listed at the end.

## Decisions (locked)

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Signature scheme | **Ed25519** via `cryptography` | Small keys, fast, no padding/curve/`alg=none` footguns; signs the frozen `agentledger.receipt.v1` canonical bytes directly |
| Unsigned-receipt policy | **Graceful default + opt-in `require_signed`** | Backward-compatible with v1 receipts; never silently reports an unsigned receipt as cryptographically verified |
| Agent identity binding | **Pluggable `IdentityProvider`**, SPIFFE as one impl | Most users don't run SPIRE; absence ⇒ `identity_unverified`, not failure |

## What gets signed

The principal signs `Receipt.canonical_bytes()` — the frozen
`agentledger.receipt.v1` payload (`_v`, `receipt_id`, principal, agent, sorted
tools/scopes, `issued_at`, `expires_at`, `constraints`, `wimse_compatible`). The
signature and its algorithm marker live **outside** the signed bytes
(`Receipt.signature`, `Receipt.signature_alg`); the verifier pins accepted algs,
so an attacker-set marker cannot cause algorithm confusion (T10).

## Trust model for keys (critical)

The verifier **must** check signatures against a public key it already trusts —
never one embedded in the receipt (that would make forgery trivial, T1). Keys are
resolved by principal through a `KeyProvider`:

```python
class KeyProvider(Protocol):
    def public_key_for(self, principal: str) -> Ed25519PublicKey | None: ...
```

Ship `InMemoryKeyProvider({principal: public_key})`. If a signed receipt's
principal has no trusted key, the signature is **unverifiable** — treated as
not-verified (graceful) or a violation (`require_signed`).

## API surface

```python
# Principal side (holds the private key)
from agentledger.signing import generate_keypair
priv, pub = generate_keypair()

receipt = ledger.issue_receipt(principal="user:d", agent="agent:a",
                               permitted_tools=["get_rates"],
                               permitted_scopes=["read:rates"])
receipt.sign(priv)                      # sets .signature + .signature_alg="ed25519"

# Verifier side (holds only trusted public keys)
from agentledger.keys import InMemoryKeyProvider
ledger = Ledger(
    proof_log="...",
    key_provider=InMemoryKeyProvider({"user:d": pub}),
    identity_provider=None,             # optional; None => identity_unverified
)

@ledger.record(receipt=receipt, require_signed=True, scopes=["read:rates"])
async def get_rates(params, context=None): ...
```

## Verification pipeline (per call)

Order and outcomes (all violations are recorded; the tool still runs unless
`on_violation="raise"`):

1. **Signature.**
   - Unsigned + `require_signed` → `signature_missing` violation; `signature_verified=False`.
   - Unsigned + graceful → `signature_verified=None` (marker: unverified).
   - Signed, no trusted key for principal → `signature_unverifiable`
     (violation only under `require_signed`); `signature_verified=None`.
   - Signed, key present, bad sig → `signature_invalid`; `signature_verified=False`.
   - Signed, key present, good sig → `signature_verified=True`.
   - Disallowed `signature_alg` (not in pinned set) → `signature_invalid`.
2. **Identity.** If an `IdentityProvider` is configured: `verified` /
   `mismatch` (→ `identity_mismatch` violation) / `unverified`. If none
   configured: `identity_status="unverified"` (no violation).
3. **Expiry.** `receipt_expired` (now on a signed basis when signed).
4. **Tool.** `tool_not_permitted` (unchanged from v1).
5. **Scopes.** For each scope in the call's `scopes=[...]` not in
   `permitted_scopes` → `scope_not_permitted` (`scope_required` set).

`within_delegation = (no violations)`. Two new proof fields carry the crypto
story independently so a `True` is never mistaken for "verified":

- `signature_verified: bool | None` — None=unsigned/unverifiable, True/False otherwise.
- `identity_status: str | None` — `"verified" | "unverified" | "mismatch"`.

## New violation types

`signature_missing`, `signature_invalid`, `signature_unverifiable`,
`identity_mismatch`, `scope_not_permitted`. Each ships with explanation +
remediation, like v1.

## Backward compatibility

- v1 unsigned receipts keep working under the graceful default (recorded,
  `signature_verified=None`).
- The signed payload format is unchanged (`agentledger.receipt.v1`) — v1 already
  froze it, so v1 and v2 compute identical canonical bytes.
- **Chain payload stays `agentledger.chain.v1`.** The new `signature_verified` /
  `identity_status` fields are recorded in JSONL but *not* added to the hashed
  payload, so existing v1 logs still verify with zero migration. The
  load-bearing authorization outcome (`within_delegation`) remains hash-chained.
  Chaining the crypto-status fields is a future `agentledger.chain.v2`.

## Dependencies

- `cryptography` → optional extra `[crypto]` (lazy-imported; signing/verifying
  raises a clear error if missing). Graceful unsigned flow needs no new deps.
- `py-spiffe` → optional extra `[spiffe]` for `SpiffeIdentityProvider`.

## Deferred (post-v2.0)

- `audience`/`nonce` claims for context-binding (T5) — would be
  `agentledger.receipt.v2` via the version tag.
- Full SPIRE workload-API SVID chain validation (v2.0 ships the interface + a
  best-effort SPIFFE-ID match; documented).
- Externally anchored logs (T7/R3) and an out-of-process verifier (R5).
