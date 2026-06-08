"""
AgentLedger integrated into a real MCP tool handler.

Compatible with any MCP server using the official Python SDK. The
``@ledger.record`` decorator wraps the handler with zero restructuring and is
safe to use inside the server's running asyncio loop.

Note: violations are RECORDED, not blocked, by default. Pass
on_violation="raise" to record-then-block.
"""
from agentledger import Ledger
from mcp.server import Server  # pip install mcp

ledger = Ledger(proof_log="./logs/mcp-proofs.jsonl")

# Issue a receipt when the agent session starts
receipt = ledger.issue_receipt(
    principal="user:merchant-admin",
    agent="agent:payroc-assistant",
    permitted_tools=["get_transaction", "list_transactions"],
    permitted_scopes=["read:transactions"],
    expires_in=1800,
)

server = Server("financial-mcp")


@server.call_tool()
@ledger.record(receipt=receipt)
async def get_transaction(params, context=None):
    """Retrieve a transaction by ID."""
    transaction_id = params.get("transaction_id")
    # ... real implementation
    return {"transaction_id": transaction_id, "amount": 450.00, "status": "settled"}


@server.call_tool()
@ledger.record(receipt=receipt)
async def delete_transaction(params, context=None):
    """NOT in the receipt — a violation is recorded (and the tool still runs)."""
    return {"deleted": True}
