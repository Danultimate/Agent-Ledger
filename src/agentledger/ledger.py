"""The Ledger — AgentLedger's primary API."""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
import warnings
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any, Callable, Optional

from agentledger.chain import HashChain
from agentledger.proof import ActionProof, ScopeViolation
from agentledger.receipt import Receipt
from agentledger.storage.jsonl_store import JSONLStore
from agentledger.verifier import Verdict, Verifier


class DelegationViolation(Exception):
    """Raised after a violating call *only* when ``on_violation='raise'``.

    The proof is always recorded first; this exception is an opt-in
    enforcement hook, not the default behavior.
    """

    def __init__(self, proof: ActionProof):
        self.proof = proof
        summary = "; ".join(v.explanation for v in proof.violations)
        super().__init__(f"Delegation violation on '{proof.tool_name}': {summary}")


class Ledger:
    """AgentLedger primary API.

    AgentLedger *records and attributes* tool calls — it does not enforce
    authorization by default. A violating call is recorded as a proof and the
    tool still runs. Use ``record(..., on_violation='raise')`` to opt into
    blocking after the proof is written.

    Quickstart::

        from agentledger import Ledger

        ledger = Ledger(proof_log="./logs/agent-proofs.jsonl")

        receipt = ledger.issue_receipt(
            principal="user:daniel",
            agent="agent:analyst",
            permitted_tools=["get_rates", "set_alert"],
            permitted_scopes=["read:rates", "write:alerts"],
            expires_in=3600,
        )

        @ledger.record(receipt=receipt)
        async def set_alert(params, context=None):
            return {"alert_id": "alert_123", "status": "active"}

        result = await set_alert({"currency": "GBP", "threshold": 1.25})

        ledger.verify(ledger.last().proof_id).print()
    """

    def __init__(
        self,
        proof_log: str = "./logs/agent-proofs.jsonl",
        auto_integrate_traceforge: bool = True,
    ):
        self._store = JSONLStore(proof_log)
        self._chain = HashChain()
        # D3: seed the chain head from the existing log so proofs appended
        # across process restarts stay linked instead of re-genesis-ing.
        self._chain.restore_from(self._store.all())
        self._verifier = Verifier()
        self._last_proof: Optional[ActionProof] = None
        self._auto_traceforge = auto_integrate_traceforge

    # ------------------------------------------------------------------ #
    # Receipts
    # ------------------------------------------------------------------ #
    def issue_receipt(
        self,
        principal: str,
        agent: str,
        permitted_tools: list[str],
        permitted_scopes: list[str],
        expires_in: Optional[int] = None,
        constraints: Optional[dict] = None,
    ) -> Receipt:
        """Issue a delegation receipt recording what a principal permits an agent to do.

        The receipt is advisory metadata, not an auth token, and is not
        cryptographically bound to the agent in v1.
        """
        expires_at = None
        if expires_in:
            expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
        return Receipt(
            principal=principal,
            agent=agent,
            permitted_tools=permitted_tools,
            permitted_scopes=permitted_scopes,
            expires_at=expires_at,
            constraints=constraints or {},
        )

    # ------------------------------------------------------------------ #
    # Decorator
    # ------------------------------------------------------------------ #
    def record(
        self,
        receipt: Optional[Receipt] = None,
        tool_name: Optional[str] = None,
        on_violation: str = "record",
    ):
        """Decorator for MCP tool handlers. Records an action proof per call.

        Works on both ``async def`` and plain ``def`` handlers with zero
        restructuring. Sync handlers are executed synchronously (no hidden
        event loop), so the decorator is safe to call from inside a running
        asyncio loop — the most common MCP server setup.

        ``on_violation`` controls behavior when a call falls outside the
        receipt. The proof is recorded in every case:

        * ``"record"`` (default) — record and continue. Audit, not enforcement.
        * ``"warn"``  — record, emit a ``UserWarning``, and continue.
        * ``"raise"`` — record, then raise :class:`DelegationViolation`.

        Usage::

            @ledger.record(receipt=my_receipt)
            async def my_tool(params, context=None):
                ...
        """
        if on_violation not in ("record", "warn", "raise"):
            raise ValueError(
                "on_violation must be 'record', 'warn', or 'raise', "
                f"got {on_violation!r}"
            )

        def decorator(func: Callable):
            actual_tool_name = tool_name or func.__name__

            if asyncio.iscoroutinefunction(func):

                @wraps(func)
                async def async_wrapper(*args, **kwargs):
                    return await self._record_async(
                        func, actual_tool_name, receipt, on_violation, args, kwargs
                    )

                return async_wrapper

            @wraps(func)
            def sync_wrapper(*args, **kwargs):
                return self._record_sync(
                    func, actual_tool_name, receipt, on_violation, args, kwargs
                )

            return sync_wrapper

        return decorator

    # ------------------------------------------------------------------ #
    # Recording (sync + async share prep/finalize)
    # ------------------------------------------------------------------ #
    def _record_sync(self, func, tool_name, receipt, on_violation, args, kwargs):
        input_hash, within, violations = self._prepare(receipt, tool_name, args, kwargs)
        start = time.time()
        error = None
        result = None
        try:
            result = func(*args, **kwargs)
        except Exception as e:
            error = str(e)
            raise
        finally:
            self._finalize(
                tool_name, receipt, input_hash, within, violations,
                result, error, start,
            )
        self._maybe_signal(on_violation)
        return result

    async def _record_async(self, func, tool_name, receipt, on_violation, args, kwargs):
        input_hash, within, violations = self._prepare(receipt, tool_name, args, kwargs)
        start = time.time()
        error = None
        result = None
        try:
            result = await func(*args, **kwargs)
        except Exception as e:
            error = str(e)
            raise
        finally:
            self._finalize(
                tool_name, receipt, input_hash, within, violations,
                result, error, start,
            )
        self._maybe_signal(on_violation)
        return result

    def _prepare(self, receipt, tool_name, args, kwargs):
        tool_input = args[0] if args else kwargs.get("params", kwargs)
        input_hash = self._hash(tool_input)
        within_delegation = None
        violations: list[ScopeViolation] = []
        if receipt:
            within_delegation, violations = self._check_receipt(receipt, tool_name)
        return input_hash, within_delegation, violations

    def _finalize(
        self, tool_name, receipt, input_hash, within, violations,
        result, error, start,
    ):
        latency_ms = int((time.time() - start) * 1000)
        output_hash = self._hash(result) if result is not None else None

        proof = ActionProof(
            receipt_id=receipt.receipt_id if receipt else None,
            principal=receipt.principal if receipt else None,
            agent=receipt.agent if receipt else None,
            tool_name=tool_name,
            tool_input_hash=input_hash,
            tool_output_hash=output_hash,
            within_delegation=within,
            violations=violations,
            latency_ms=latency_ms,
            error=self._truncate_error(error),
            previous_proof_hash=self._chain.head,
        )
        proof.proof_hash = self._chain.append(proof)
        self._last_proof = proof
        self._store.append(proof)

        if self._auto_traceforge:
            self._enrich_traceforge_span(proof)

    def _maybe_signal(self, on_violation: str) -> None:
        """Apply the post-record violation policy. The proof is already stored."""
        proof = self._last_proof
        if not proof or proof.within_delegation is not False:
            return
        if on_violation == "warn":
            warnings.warn(
                f"Delegation violation recorded on '{proof.tool_name}' "
                f"(proof {proof.proof_id}). Tool executed anyway.",
                UserWarning,
                stacklevel=3,
            )
        elif on_violation == "raise":
            raise DelegationViolation(proof)

    def _check_receipt(
        self, receipt: Receipt, tool_name: str
    ) -> tuple[bool, list[ScopeViolation]]:
        violations: list[ScopeViolation] = []

        if receipt.is_expired:
            violations.append(
                ScopeViolation(
                    violation_type="receipt_expired",
                    receipt_id=receipt.receipt_id,
                    explanation=(
                        f"Delegation receipt {receipt.receipt_id} expired at "
                        f"{receipt.expires_at}"
                    ),
                    remediation="Re-issue a new receipt from the principal.",
                )
            )

        if not receipt.permits_tool(tool_name):
            violations.append(
                ScopeViolation(
                    violation_type="tool_not_permitted",
                    tool_called=tool_name,
                    receipt_id=receipt.receipt_id,
                    explanation=(
                        f"Agent called '{tool_name}' but delegation only permits: "
                        f"{receipt.permitted_tools}"
                    ),
                    remediation=(
                        f"Re-issue receipt with '{tool_name}' in permitted_tools, "
                        f"or restrict agent from calling this tool."
                    ),
                )
            )

        return (len(violations) == 0, violations)

    # ------------------------------------------------------------------ #
    # Verification & reporting
    # ------------------------------------------------------------------ #
    def verify(self, proof_id: str) -> Verdict:
        """Verify a specific proof by ID."""
        proof = self._store.get(proof_id)
        if not proof:
            raise FileNotFoundError(f"No proof found with ID {proof_id!r}")
        return self._verifier.verdict(proof)

    def verify_all(self) -> list[Verdict]:
        """Verify every proof in the log."""
        return [self._verifier.verdict(p) for p in self._store.all()]

    def verify_chain(self) -> bool:
        """Verify hash-chain integrity of the entire proof log."""
        return self._chain.verify(self._store.all())

    def last(self) -> Optional[ActionProof]:
        """Return the most recent proof recorded by this Ledger instance."""
        return self._last_proof

    def report(self, output: str = "terminal", path: Optional[str] = None) -> Optional[str]:
        """Print or save a summary report of all proofs."""
        proofs = self._store.all()
        if output == "terminal":
            from agentledger.report.terminal import print_report

            print_report(proofs)
            return None
        if output == "html":
            from agentledger.report.html_report import save_report

            return save_report(proofs, path or "agentledger-report.html")
        raise ValueError(f"Unknown report output {output!r}")

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _hash(obj: Any) -> str:
        """Digest of a tool input/output.

        This is a stable fingerprint for tamper-evidence and de-duplication,
        NOT a confidentiality mechanism: low-entropy inputs can be recovered by
        guessing, and the digest is unsalted. Treat proof logs as sensitive.
        """
        payload = json.dumps(obj, sort_keys=True, default=str)
        return hashlib.sha256(payload.encode()).hexdigest()[:16]

    @staticmethod
    def _truncate_error(error: Optional[str], limit: int = 500) -> Optional[str]:
        if error is None:
            return None
        if len(error) <= limit:
            return error
        return error[:limit] + "...[truncated]"

    def _enrich_traceforge_span(self, proof: ActionProof) -> None:
        """Auto-attach delegation context to the active TraceForge span if present.

        Silent no-op when TraceForge is not installed (never raises). Emits a
        single debug warning the first time so the no-op is discoverable.
        """
        try:
            from traceforge import active_span
        except ImportError:
            if self._auto_traceforge and not getattr(self, "_tf_warned", False):
                self._tf_warned = True
                warnings.warn(
                    "auto_integrate_traceforge=True but 'agentrace-llm' is not "
                    "installed; TraceForge span enrichment is a no-op. Install "
                    "agentledger-llm[traceforge] to enable it.",
                    UserWarning,
                    stacklevel=2,
                )
            return

        span = active_span()
        if not span:
            return
        span.set_attribute("agentledger.proof_id", proof.proof_id)
        span.set_attribute("agentledger.tool", proof.tool_name)
        span.set_attribute(
            "agentledger.within_delegation", str(proof.within_delegation)
        )
        if proof.receipt_id:
            span.set_attribute("agentledger.receipt_id", proof.receipt_id)
        if proof.violations:
            span.set_attribute("agentledger.violations", str(len(proof.violations)))
