import asyncio
import json

from agentledger import Ledger
from agentledger.chain import HashChain
from agentledger.storage.jsonl_store import JSONLStore


def _record(ledger, name="t"):
    @ledger.record()
    async def tool(params, context=None):
        return {"ok": True, "name": name}

    asyncio.run(tool({"name": name}))


def test_chain_verifies_clean_log(tmp_path):
    log = str(tmp_path / "p.jsonl")
    ledger = Ledger(proof_log=log, auto_integrate_traceforge=False)
    for i in range(5):
        _record(ledger, f"t{i}")
    assert ledger.verify_chain() is True


def test_chain_roundtrips_through_disk(tmp_path):
    """D12: serialize -> reload -> verify must hold (datetime/isoformat round-trip)."""
    log = str(tmp_path / "p.jsonl")
    ledger = Ledger(proof_log=log, auto_integrate_traceforge=False)
    for i in range(3):
        _record(ledger, f"t{i}")

    # Fresh store reads everything back from disk and re-verifies.
    proofs = JSONLStore(log).all()
    assert len(proofs) == 3
    assert HashChain().verify(proofs) is True


def test_chain_links_across_process_restart(tmp_path):
    """D3: a new Ledger over an existing log must restore the head so the next
    proof links to the previous one instead of re-genesis-ing."""
    log = str(tmp_path / "p.jsonl")

    ledger1 = Ledger(proof_log=log, auto_integrate_traceforge=False)
    for i in range(3):
        _record(ledger1, f"a{i}")

    # Simulate restart: brand-new Ledger instance over the same file.
    ledger2 = Ledger(proof_log=log, auto_integrate_traceforge=False)
    _record(ledger2, "after-restart")

    proofs = JSONLStore(log).all()
    assert len(proofs) == 4
    # The 4th proof must link to the 3rd, not to None.
    assert proofs[3].previous_proof_hash == proofs[2].proof_hash
    assert HashChain().verify(proofs) is True


def test_chain_detects_tampering(tmp_path):
    log = str(tmp_path / "p.jsonl")
    ledger = Ledger(proof_log=log, auto_integrate_traceforge=False)
    for i in range(3):
        _record(ledger, f"t{i}")

    # Tamper: rewrite the tool_name of the middle proof on disk.
    lines = [json.loads(line) for line in open(log) if line.strip()]
    lines[1]["tool_name"] = "tampered"
    with open(log, "w") as f:
        for obj in lines:
            f.write(json.dumps(obj) + "\n")

    proofs = JSONLStore(log).all()
    assert HashChain().verify(proofs) is False
