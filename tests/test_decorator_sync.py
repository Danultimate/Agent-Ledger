"""D2: the decorator must work on sync handlers, including when called from
inside a running asyncio event loop (the common MCP server setup). The old spec
used asyncio.run() inside the sync wrapper, which crashes in that scenario."""

import asyncio

from agentledger import Ledger


def test_sync_handler_outside_loop(tmp_path):
    ledger = Ledger(proof_log=str(tmp_path / "p.jsonl"))
    receipt = ledger.issue_receipt(
        principal="u", agent="a", permitted_tools=["calc"], permitted_scopes=[],
    )

    @ledger.record(receipt=receipt)
    def calc(params, context=None):
        return {"sum": params["a"] + params["b"]}

    assert calc({"a": 2, "b": 3}) == {"sum": 5}
    assert ledger.last().within_delegation is True


def test_sync_handler_inside_running_loop(tmp_path):
    ledger = Ledger(proof_log=str(tmp_path / "p.jsonl"))

    @ledger.record()
    def calc(params, context=None):
        return params["a"] * 2

    async def driver():
        # Calling a sync-wrapped handler from within a running loop must NOT
        # raise "asyncio.run() cannot be called from a running event loop".
        return calc({"a": 21})

    result = asyncio.run(driver())
    assert result == 42
    assert ledger.last() is not None
