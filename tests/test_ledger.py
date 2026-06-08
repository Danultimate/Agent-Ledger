import asyncio
import warnings

import pytest

from agentledger import DelegationViolation, Ledger


@pytest.fixture
def log_path(tmp_path):
    return str(tmp_path / "proofs.jsonl")


def test_async_within_delegation(log_path):
    ledger = Ledger(proof_log=log_path)
    receipt = ledger.issue_receipt(
        principal="user:d", agent="agent:a",
        permitted_tools=["get_rates"], permitted_scopes=["read:rates"],
    )

    @ledger.record(receipt=receipt)
    async def get_rates(params, context=None):
        return {"GBP": 0.79}

    result = asyncio.run(get_rates({"base": "USD"}))
    assert result == {"GBP": 0.79}
    proof = ledger.last()
    assert proof.within_delegation is True
    assert proof.passed is True
    assert proof.violations == []


def test_violation_recorded_not_blocked(log_path):
    ledger = Ledger(proof_log=log_path)
    receipt = ledger.issue_receipt(
        principal="user:d", agent="agent:a",
        permitted_tools=["get_rates"], permitted_scopes=["read:rates"],
    )

    @ledger.record(receipt=receipt)
    async def delete_alert(params, context=None):
        return {"deleted": True}

    # Default on_violation="record": tool STILL runs.
    result = asyncio.run(delete_alert({"id": 1}))
    assert result == {"deleted": True}
    proof = ledger.last()
    assert proof.within_delegation is False
    assert proof.violations[0].violation_type == "tool_not_permitted"
    assert proof.violations[0].remediation  # actionable


def test_on_violation_raise_records_then_raises(log_path):
    ledger = Ledger(proof_log=log_path)
    receipt = ledger.issue_receipt(
        principal="u", agent="a",
        permitted_tools=["allowed"], permitted_scopes=[],
    )

    @ledger.record(receipt=receipt, on_violation="raise")
    async def blocked(params, context=None):
        return {"ok": True}

    with pytest.raises(DelegationViolation):
        asyncio.run(blocked({}))
    # Proof was still written before raising.
    assert ledger.last() is not None
    assert ledger.last().within_delegation is False


def test_on_violation_warn(log_path):
    ledger = Ledger(proof_log=log_path)
    receipt = ledger.issue_receipt(
        principal="u", agent="a", permitted_tools=["ok"], permitted_scopes=[],
    )

    @ledger.record(receipt=receipt, on_violation="warn")
    async def nope(params, context=None):
        return 1

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        asyncio.run(nope({}))
    assert any(issubclass(w.category, UserWarning) for w in caught)


def test_no_receipt_is_unverified(log_path):
    ledger = Ledger(proof_log=log_path)

    @ledger.record()
    async def anything(params, context=None):
        return {"x": 1}

    asyncio.run(anything({}))
    proof = ledger.last()
    assert proof.within_delegation is None
    assert proof.passed is True  # nothing to violate


def test_expired_receipt_violation(log_path):
    ledger = Ledger(proof_log=log_path, auto_integrate_traceforge=False)
    receipt = ledger.issue_receipt(
        principal="u", agent="a",
        permitted_tools=["get_rates"], permitted_scopes=[],
        expires_in=1,
    )
    # Force expiry.
    from datetime import datetime, timezone, timedelta
    receipt.expires_at = datetime.now(timezone.utc) - timedelta(seconds=5)

    @ledger.record(receipt=receipt)
    async def get_rates(params, context=None):
        return {}

    asyncio.run(get_rates({}))
    types = {v.violation_type for v in ledger.last().violations}
    assert "receipt_expired" in types


def test_invalid_on_violation_rejected(log_path):
    ledger = Ledger(proof_log=log_path)
    with pytest.raises(ValueError):
        ledger.record(on_violation="explode")


def test_error_is_recorded_and_reraised(log_path):
    ledger = Ledger(proof_log=log_path, auto_integrate_traceforge=False)

    @ledger.record()
    async def boom(params, context=None):
        raise RuntimeError("kaboom")

    with pytest.raises(RuntimeError):
        asyncio.run(boom({}))
    proof = ledger.last()
    assert proof is not None
    assert "kaboom" in proof.error
