"""Lock the frozen wire formats.

These tests fail if anyone changes canonical serialization, the receipt signing
payload, or the chain payload — which would silently break v2 signatures and
existing hash chains. If a change here is intentional, it must come with a NEW
version tag (agentledger.receipt.v2 / agentledger.chain.v2), not an edit to v1.
"""

from datetime import datetime, timezone

from agentledger.canonical import canonical_json
from agentledger.chain import CHAIN_PAYLOAD_VERSION
from agentledger.receipt import RECEIPT_PAYLOAD_VERSION, Receipt


def test_canonical_json_is_sorted_and_compact():
    assert canonical_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'
    # No whitespace between tokens.
    assert " " not in canonical_json({"x": [1, 2, 3]})


def test_canonical_json_ascii_escaped():
    # Non-ASCII is escaped so output is locale/encoding independent.
    assert canonical_json({"k": "café"}) == '{"k":"caf\\u00e9"}'


def _fixed_receipt() -> Receipt:
    return Receipt(
        receipt_id="rcpt_TEST",
        principal="user:d",
        agent="agent:a",
        permitted_tools=["b", "a"],          # deliberately unsorted
        permitted_scopes=["y", "x"],         # deliberately unsorted
        issued_at=datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        expires_at=datetime(2026, 1, 1, 1, 0, 0, tzinfo=timezone.utc),
        constraints={"max": 5},
        wimse_compatible=True,
    )


def test_receipt_signing_payload_has_version_tag():
    payload = _fixed_receipt().signing_payload()
    assert payload["_v"] == RECEIPT_PAYLOAD_VERSION == "agentledger.receipt.v1"
    assert "signature" not in payload  # never sign the signature itself


def test_receipt_canonical_bytes_golden():
    """Exact frozen layout v2 will sign. Do not 'fix' — bump the version tag."""
    expected = (
        '{"_v":"agentledger.receipt.v1",'
        '"agent":"agent:a",'
        '"constraints":{"max":5},'
        '"expires_at":"2026-01-01T01:00:00+00:00",'
        '"issued_at":"2026-01-01T00:00:00+00:00",'
        '"permitted_scopes":["x","y"],'
        '"permitted_tools":["a","b"],'
        '"principal":"user:d",'
        '"receipt_id":"rcpt_TEST",'
        '"wimse_compatible":true}'
    ).encode("utf-8")
    assert _fixed_receipt().canonical_bytes() == expected


def test_receipt_canonical_bytes_order_independent():
    a = Receipt(receipt_id="r", principal="p", agent="g",
                permitted_tools=["x", "y"], permitted_scopes=["b", "a"],
                issued_at=datetime(2026, 1, 1, tzinfo=timezone.utc))
    b = Receipt(receipt_id="r", principal="p", agent="g",
                permitted_tools=["y", "x"], permitted_scopes=["a", "b"],
                issued_at=datetime(2026, 1, 1, tzinfo=timezone.utc))
    assert a.canonical_bytes() == b.canonical_bytes()


def test_chain_payload_version_constant():
    assert CHAIN_PAYLOAD_VERSION == "agentledger.chain.v1"
