"""
AgentLedger v2 — cryptographically signed delegation.

The principal signs the receipt (Ed25519); the verifier checks it against a
public key it already trusts. A within-delegation verdict on a signed receipt
means the grant was provably issued by the principal — not just string-matched.

Run:
    pip install "agentledger-llm[crypto]"
    python examples/signed_receipts.py
"""
import asyncio

from agentledger import InMemoryKeyProvider, Ledger, StaticIdentityProvider
from agentledger.signing import generate_keypair

# --- Principal side: hold a private key, sign the grant ---------------------- #
priv, pub = generate_keypair()

# --- Verifier side: trust only the principal's PUBLIC key -------------------- #
ledger = Ledger(
    proof_log="./logs/signed-proofs.jsonl",
    key_provider=InMemoryKeyProvider({"user:daniel": pub}),
    identity_provider=StaticIdentityProvider(trusted={"agent:assistant"}),
)

receipt = ledger.issue_receipt(
    principal="user:daniel",
    agent="agent:assistant",
    permitted_tools=["get_exchange_rates"],
    permitted_scopes=["read:rates"],
    expires_in=3600,
)
receipt.sign(priv)


@ledger.record(receipt=receipt, require_signed=True, scopes=["read:rates"])
async def get_exchange_rates(params, context=None):
    return {"base": params.get("base", "USD"), "rates": {"GBP": 0.79}}


async def main():
    await get_exchange_rates({"base": "USD"})
    verdict = ledger.verify(ledger.last().proof_id)
    verdict.print()  # shows Signed: verified · Identity: verified


if __name__ == "__main__":
    asyncio.run(main())
