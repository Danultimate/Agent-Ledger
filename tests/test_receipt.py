from datetime import datetime, timedelta, timezone

from agentledger.receipt import Receipt


def test_receipt_id_prefix():
    r = Receipt(principal="user:a", agent="agent:b",
                permitted_tools=["t"], permitted_scopes=["s"])
    assert r.receipt_id.startswith("rcpt_")


def test_not_expired_without_expiry():
    r = Receipt(principal="u", agent="a", permitted_tools=[], permitted_scopes=[])
    assert r.is_expired is False


def test_expired_in_the_past():
    past = datetime.now(timezone.utc) - timedelta(seconds=10)
    r = Receipt(principal="u", agent="a", permitted_tools=[],
                permitted_scopes=[], expires_at=past)
    assert r.is_expired is True


def test_permits_helpers():
    r = Receipt(principal="u", agent="a",
                permitted_tools=["get_rates"], permitted_scopes=["read:rates"])
    assert r.permits_tool("get_rates")
    assert not r.permits_tool("delete_rates")
    assert r.permits_scope("read:rates")
    assert not r.permits_scope("write:rates")


def test_fingerprint_stable_and_order_independent():
    a = Receipt(principal="u", agent="a",
                permitted_tools=["x", "y"], permitted_scopes=["s2", "s1"])
    b = Receipt(principal="u", agent="a",
                permitted_tools=["y", "x"], permitted_scopes=["s1", "s2"])
    assert a.fingerprint == b.fingerprint
