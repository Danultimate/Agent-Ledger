"""TraceForge (agentrace-llm) integration helpers.

The Ledger auto-enriches the active TraceForge span when ``agentrace-llm`` is
installed (see ``Ledger._enrich_traceforge_span``). This module exposes the same
enrichment for callers that want to attach a proof to a span explicitly.

All functions are no-ops when TraceForge is not installed — they never raise.
"""

from __future__ import annotations

from agentledger.proof import ActionProof


def is_available() -> bool:
    try:
        import traceforge  # noqa: F401
    except ImportError:
        return False
    return True


def enrich_span(proof: ActionProof) -> bool:
    """Attach proof metadata to the active TraceForge span.

    Returns True if a span was enriched, False otherwise (not installed or no
    active span).
    """
    try:
        from traceforge import active_span
    except ImportError:
        return False

    span = active_span()
    if not span:
        return False
    span.set_attribute("agentledger.proof_id", proof.proof_id)
    span.set_attribute("agentledger.tool", proof.tool_name)
    span.set_attribute("agentledger.within_delegation", str(proof.within_delegation))
    if proof.receipt_id:
        span.set_attribute("agentledger.receipt_id", proof.receipt_id)
    if proof.violations:
        span.set_attribute("agentledger.violations", str(len(proof.violations)))
    return True
