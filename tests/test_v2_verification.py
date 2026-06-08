"""v2 end-to-end verification through the Ledger: signatures, policy, scopes,
identity binding. Each test maps to a threat in docs/threat-model.md."""

import asyncio


from agentledger import (
    InMemoryKeyProvider,
    Ledger,
    StaticIdentityProvider,
)
from agentledger.signing import generate_keypair


def _run(coro):
    return asyncio.run(coro)


def _ledger(tmp_path, **kw):
    return Ledger(proof_log=str(tmp_path / "p.jsonl"),
                  auto_integrate_traceforge=False, **kw)


def _signed_receipt(ledger, priv, **kw):
    r = ledger.issue_receipt(
        principal="user:d", agent="agent:a",
        permitted_tools=["get_rates"], permitted_scopes=["read:rates"], **kw
    )
    r.sign(priv)
    return r


# --- T1/T2: signed receipt verifies; tampering breaks it -------------------- #

def test_signed_receipt_verifies(tmp_path):
    priv, pub = generate_keypair()
    ledger = _ledger(tmp_path, key_provider=InMemoryKeyProvider({"user:d": pub}))
    receipt = _signed_receipt(ledger, priv)

    @ledger.record(receipt=receipt, require_signed=True)
    async def get_rates(params, context=None):
        return {"GBP": 0.79}

    _run(get_rates({"base": "USD"}))
    p = ledger.last()
    assert p.signature_verified is True
    assert p.within_delegation is True
    assert p.passed is True


def test_tampered_grant_fails_signature(tmp_path):
    priv, pub = generate_keypair()
    ledger = _ledger(tmp_path, key_provider=InMemoryKeyProvider({"user:d": pub}))
    receipt = _signed_receipt(ledger, priv)
    receipt.permitted_tools.append("delete_all")  # widen after signing (T2)

    @ledger.record(receipt=receipt, require_signed=True)
    async def delete_all(params, context=None):
        return {"deleted": True}

    _run(delete_all({}))
    p = ledger.last()
    assert p.signature_verified is False
    assert p.within_delegation is False
    assert any(v.violation_type == "signature_invalid" for v in p.violations)


# --- T8/T9: unsigned under policy ------------------------------------------- #

def test_unsigned_graceful_is_recorded_not_verified(tmp_path):
    ledger = _ledger(tmp_path)  # no key provider, graceful default
    receipt = ledger.issue_receipt(
        principal="user:d", agent="agent:a",
        permitted_tools=["get_rates"], permitted_scopes=[],
    )

    @ledger.record(receipt=receipt)  # require_signed defaults False
    async def get_rates(params, context=None):
        return {}

    _run(get_rates({}))
    p = ledger.last()
    # within_delegation may be True (tool matched) but signature is NOT verified.
    assert p.signature_verified is None
    assert p.within_delegation is True


def test_unsigned_with_require_signed_is_violation(tmp_path):
    ledger = _ledger(tmp_path)
    receipt = ledger.issue_receipt(
        principal="user:d", agent="agent:a",
        permitted_tools=["get_rates"], permitted_scopes=[],
    )

    @ledger.record(receipt=receipt, require_signed=True)
    async def get_rates(params, context=None):
        return {}

    _run(get_rates({}))
    p = ledger.last()
    assert p.within_delegation is False
    assert any(v.violation_type == "signature_missing" for v in p.violations)


def test_signed_but_no_trusted_key_unverifiable(tmp_path):
    priv, _pub = generate_keypair()
    ledger = _ledger(tmp_path)  # no key provider configured
    receipt = _signed_receipt(ledger, priv)

    @ledger.record(receipt=receipt, require_signed=True)
    async def get_rates(params, context=None):
        return {}

    _run(get_rates({}))
    p = ledger.last()
    assert p.signature_verified is None
    assert any(v.violation_type == "signature_unverifiable" for v in p.violations)


# --- T6: scope checks ------------------------------------------------------- #

def test_scope_not_permitted(tmp_path):
    priv, pub = generate_keypair()
    ledger = _ledger(tmp_path, key_provider=InMemoryKeyProvider({"user:d": pub}))
    receipt = _signed_receipt(ledger, priv)  # permits scope read:rates only

    @ledger.record(receipt=receipt, scopes=["write:alerts"])
    async def get_rates(params, context=None):
        return {}

    _run(get_rates({}))
    p = ledger.last()
    v = [x for x in p.violations if x.violation_type == "scope_not_permitted"]
    assert v and v[0].scope_required == "write:alerts"


def test_scope_permitted_passes(tmp_path):
    priv, pub = generate_keypair()
    ledger = _ledger(tmp_path, key_provider=InMemoryKeyProvider({"user:d": pub}))
    receipt = _signed_receipt(ledger, priv)

    @ledger.record(receipt=receipt, scopes=["read:rates"], require_signed=True)
    async def get_rates(params, context=None):
        return {}

    _run(get_rates({}))
    assert ledger.last().passed is True


# --- T3 / R4: identity binding ---------------------------------------------- #

def test_identity_verified(tmp_path):
    priv, pub = generate_keypair()
    ledger = _ledger(
        tmp_path,
        key_provider=InMemoryKeyProvider({"user:d": pub}),
        identity_provider=StaticIdentityProvider(trusted={"agent:a"}),
    )
    receipt = _signed_receipt(ledger, priv)

    @ledger.record(receipt=receipt, require_signed=True)
    async def get_rates(params, context=None):
        return {}

    _run(get_rates({}))
    p = ledger.last()
    assert p.identity_status == "verified"
    assert p.passed is True


def test_identity_mismatch_is_violation(tmp_path):
    priv, pub = generate_keypair()
    ledger = _ledger(
        tmp_path,
        key_provider=InMemoryKeyProvider({"user:d": pub}),
        identity_provider=StaticIdentityProvider(trusted={"agent:other"}),
    )
    receipt = _signed_receipt(ledger, priv)

    @ledger.record(receipt=receipt, require_signed=True)
    async def get_rates(params, context=None):
        return {}

    _run(get_rates({}))
    p = ledger.last()
    assert p.identity_status == "mismatch"
    assert p.within_delegation is False
    assert any(v.violation_type == "identity_mismatch" for v in p.violations)


def test_no_identity_provider_marks_unverified(tmp_path):
    priv, pub = generate_keypair()
    ledger = _ledger(tmp_path, key_provider=InMemoryKeyProvider({"user:d": pub}))
    receipt = _signed_receipt(ledger, priv)

    @ledger.record(receipt=receipt, require_signed=True)
    async def get_rates(params, context=None):
        return {}

    _run(get_rates({}))
    p = ledger.last()
    assert p.identity_status == "unverified"  # R4: honest marker, not failure
    assert p.passed is True


# --- persistence: v2 fields survive the round-trip -------------------------- #

def test_v1_format_log_still_verifies(tmp_path):
    """A pre-v2 log line (no signature_verified/identity_status keys) must still
    parse and chain-verify under v2 code — the chain payload is unchanged."""
    import json

    from agentledger.chain import HashChain
    from agentledger.proof import ActionProof

    log = tmp_path / "v1.jsonl"
    chain = HashChain()
    p = ActionProof(tool_name="t", tool_input_hash="abc",
                    within_delegation=True, previous_proof_hash=None)
    p.proof_hash = chain.append(p)

    d = json.loads(p.model_dump_json())
    d.pop("signature_verified", None)   # v1 never wrote these
    d.pop("identity_status", None)
    log.write_text(json.dumps(d) + "\n")

    ledger2 = Ledger(proof_log=str(log), auto_integrate_traceforge=False)
    assert ledger2.verify_chain() is True
    assert ledger2.verify(p.proof_id).signature_verified is None


def test_v2_fields_persist(tmp_path):
    priv, pub = generate_keypair()
    log = str(tmp_path / "p.jsonl")
    ledger = Ledger(proof_log=log, auto_integrate_traceforge=False,
                    key_provider=InMemoryKeyProvider({"user:d": pub}))
    receipt = _signed_receipt(ledger, priv)

    @ledger.record(receipt=receipt, require_signed=True)
    async def get_rates(params, context=None):
        return {}

    _run(get_rates({}))
    pid = ledger.last().proof_id

    # Fresh ledger reads from disk; v2 fields must be intact and chain valid.
    ledger2 = Ledger(proof_log=log, auto_integrate_traceforge=False)
    verdict = ledger2.verify(pid)
    assert verdict.signature_verified is True
    assert ledger2.verify_chain() is True
