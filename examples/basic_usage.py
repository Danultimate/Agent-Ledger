"""
AgentLedger — 20-line quickstart.

Records what an agent did, on whose authority, tamper-evidently.
(Records — does not block. See on_violation= for opt-in enforcement.)

Run:
    pip install agentledger-llm
    python examples/basic_usage.py
"""
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
