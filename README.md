# AgentLedger

> Your agent executed a tool. AgentLedger **records** — tamper-evidently — which
> action ran, on whose authority, and whether it stayed within the delegation it
> was given.

```bash
pip install agentledger-llm
```

> **What this is and isn't.** AgentLedger is an **audit layer**, not an
> enforcement layer. By default a tool call that violates its receipt is
> **recorded as a proof and still runs** — it is not blocked. Hash-chaining
> makes the log **tamper-evident**; it does **not** prove an action was
> authorized at execution time by a cryptographically verified identity. See
> [Security note](#security-note).

---

## The problem

OAuth tells you who authenticated. It doesn't tell you which specific action was
authorized, by whom, through what delegation, with what record.

AgentLedger fills that gap — it records the delegation intent and an attributable,
tamper-evident proof of each tool call against it.

---

## 20-second quickstart

```python
import asyncio
from agentledger import Ledger

ledger = Ledger()

receipt = ledger.issue_receipt(
    principal="user:daniel",
    agent="agent:financial-assistant",
    permitted_tools=["get_exchange_rates"],
    permitted_scopes=["read:rates"],
    expires_in=3600,
)

@ledger.record(receipt=receipt)
async def get_exchange_rates(params, context=None):
    return {"base": "USD", "GBP": 0.79, "EUR": 0.92}

async def main():
    await get_exchange_rates({"base": "USD"})
    ledger.report()
    ledger.verify(ledger.last().proof_id).print()

asyncio.run(main())
```

Want violations to **block** instead of just record? Opt in:

```python
@ledger.record(receipt=receipt, on_violation="raise")  # "record" (default) | "warn" | "raise"
async def delete_alert(params, context=None):
    ...
```

---

## The three-layer model

AgentLedger sits *after* authentication, not instead of it:

| Layer | Standard | What it does |
|-------|----------|--------------|
| Authentication | OAuth 2.1 | Who are you? |
| Workload identity | WIMSE WPT + SPIFFE/SPIRE | Which agent are you? |
| Action proof | **AgentLedger** | What did you do, recorded against whom? |

---

## What it records

For every tool call:

- Which tool was called, by which agent, for which principal
- Whether the call was within the delegation receipt
- Any scope violations — each with an explanation **and** a remediation
- A hash-chained, tamper-evident proof record
- Latency and error state

---

## What it does NOT do

AgentLedger v1 explicitly does not:

- Replace OAuth or any identity provider
- **Enforce** authorization by default (it records; opt in with `on_violation="raise"`)
- Provide mid-chain revocation *(v3 — see [roadmap](docs/roadmap.md))*
- Handle multi-hop delegation chains *(v3)*
- Bind agent identity cryptographically *(v2 — SPIFFE/SPIRE + signed receipts)*
- Provide enterprise compliance (SOC 2, legal)
- Compete with Prefactor (enterprise) or KYA-OS (DID-based)

See **[docs/roadmap.md](docs/roadmap.md)** for v2/v3 scope and entry criteria.

---

## vs alternatives

| Tool          | Open source | pip install | Action record | WIMSE-aligned | Developer-first |
|---------------|-------------|-------------|---------------|---------------|-----------------|
| AgentLedger   | ✅           | ✅           | ✅             | ✅             | ✅               |
| Prefactor     | ❌           | ❌           | ✅             | ✅             | ❌ (enterprise)  |
| KYA-OS        | ✅           | ✅           | ✅             | ✅             | ⚠️ (DID-heavy)   |
| FinMCP inline | ✅           | N/A         | ✅             | ❌             | ✅ (one server)  |

---

## CLI

| Command | What it does | Exit code |
|---------|--------------|-----------|
| `agentledger init` | Scaffold `agentledger.yaml` + working `agent_example.py` | 0 |
| `agentledger report [--log PATH] [--format terminal\|html]` | Summarize the proof log | 0 always (informational) |
| `agentledger verify <proof_id> [--log PATH]` | Verdict for one proof | 1 if violations recorded |
| `agentledger chain [--log PATH]` | Verify hash-chain integrity | 1 if tampered |

---

## TraceForge integration

If [`agentrace-llm`](https://pypi.org/project/agentrace-llm/) is installed,
AgentLedger automatically attaches proof metadata (`agentledger.proof_id`,
`agentledger.tool`, `agentledger.within_delegation`, …) to the active TraceForge
span. If it isn't installed, enrichment is a silent no-op (a one-time warning
makes the no-op discoverable). Zero configuration required.

```bash
pip install "agentledger-llm[traceforge]"
```

---

## Security note

Hash-chain integrity proves the proof log has not been tampered with **after
recording** — and only while the log is read-only or externally anchored; an
attacker with write access to the log can rewrite the whole chain. It does
**not** prove actions were authorized at execution time by a cryptographically
verified agent identity. Input/output digests are **tamper-evidence**, not
confidentiality — low-entropy inputs can be recovered by guessing, so treat
proof logs as sensitive. For cryptographic identity binding you need
SPIFFE/SPIRE + AgentLedger v2. See [docs/wimse-alignment.md](docs/wimse-alignment.md).

---

## Built by

Daniel Blanco · danblanco.dev · hello@danblanco.dev · Apache-2.0
