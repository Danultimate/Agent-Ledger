import asyncio

from agentledger import Ledger, Verifier
from agentledger.proof import ActionProof, ScopeViolation


def test_verifier_class_exists_and_produces_verdict():
    """D1: Verifier was referenced but undefined in the original spec."""
    proof = ActionProof(tool_name="t", tool_input_hash="abc", within_delegation=True)
    verdict = Verifier().verdict(proof)
    assert verdict.tool_name == "t"
    assert verdict.passed is True
    assert "within delegation" in verdict.explanation.lower()


def test_verdict_for_violation():
    proof = ActionProof(
        tool_name="delete",
        tool_input_hash="x",
        within_delegation=False,
        violations=[
            ScopeViolation(
                violation_type="tool_not_permitted",
                tool_called="delete",
                explanation="not allowed",
                remediation="add it",
            )
        ],
    )
    verdict = Verifier().verdict(proof)
    assert verdict.passed is False
    assert "VIOLATIONS RECORDED" in verdict.explanation


def test_verdict_unverified_when_no_receipt():
    proof = ActionProof(tool_name="t", tool_input_hash="x", within_delegation=None)
    verdict = Verifier().verdict(proof)
    assert verdict.within_delegation is None
    assert "not checked" in verdict.explanation


def test_ledger_verify_roundtrip(tmp_path):
    ledger = Ledger(proof_log=str(tmp_path / "p.jsonl"),
                    auto_integrate_traceforge=False)

    @ledger.record()
    async def t(params, context=None):
        return {"x": 1}

    asyncio.run(t({}))
    verdict = ledger.verify(ledger.last().proof_id)
    assert verdict.proof_id == ledger.last().proof_id
