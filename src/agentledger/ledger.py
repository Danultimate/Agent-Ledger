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
from agentledger.identity import MISMATCH, UNVERIFIED, IdentityProvider
from agentledger.keys import KeyProvider
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
        key_provider: Optional[KeyProvider] = None,
        identity_provider: Optional[IdentityProvider] = None,
    ):
        self._store = JSONLStore(proof_log)
        self._chain = HashChain()
        # D3: seed the chain head from the existing log so proofs appended
        # across process restarts stay linked instead of re-genesis-ing.
        self._chain.restore_from(self._store.all())
        self._verifier = Verifier()
        self._last_proof: Optional[ActionProof] = None
        self._auto_traceforge = auto_integrate_traceforge
        # v2: trusted-key resolution and optional agent identity binding.
        self._key_provider = key_provider
        self._identity_provider = identity_provider

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
        require_signed: bool = False,
        scopes: Optional[list[str]] = None,
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

        v2 options:

        * ``require_signed`` — when True, an unsigned or unverifiable receipt is
          a violation. Default False (graceful): unsigned receipts are recorded
          with ``signature_verified=None`` and never reported as verified.
        * ``scopes`` — scopes this call requires; each is checked against the
          receipt's ``permitted_scopes`` (records ``scope_not_permitted``).

        Usage::

            @ledger.record(receipt=my_receipt, require_signed=True, scopes=["read:rates"])
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
                        func, actual_tool_name, receipt, on_violation,
                        require_signed, scopes, args, kwargs,
                    )

                return async_wrapper

            @wraps(func)
            def sync_wrapper(*args, **kwargs):
                return self._record_sync(
                    func, actual_tool_name, receipt, on_violation,
                    require_signed, scopes, args, kwargs,
                )

            return sync_wrapper

        return decorator

    # ------------------------------------------------------------------ #
    # Recording (sync + async share prep/finalize)
    # ------------------------------------------------------------------ #
    def _record_sync(
        self, func, tool_name, receipt, on_violation, require_signed, scopes,
        args, kwargs,
    ):
        ctx = self._prepare(receipt, tool_name, require_signed, scopes, args, kwargs)
        start = time.time()
        error = None
        result = None
        try:
            result = func(*args, **kwargs)
        except Exception as e:
            error = str(e)
            raise
        finally:
            self._finalize(tool_name, receipt, ctx, result, error, start)
        self._maybe_signal(on_violation)
        return result

    async def _record_async(
        self, func, tool_name, receipt, on_violation, require_signed, scopes,
        args, kwargs,
    ):
        ctx = self._prepare(receipt, tool_name, require_signed, scopes, args, kwargs)
        start = time.time()
        error = None
        result = None
        try:
            result = await func(*args, **kwargs)
        except Exception as e:
            error = str(e)
            raise
        finally:
            self._finalize(tool_name, receipt, ctx, result, error, start)
        self._maybe_signal(on_violation)
        return result

    def _prepare(self, receipt, tool_name, require_signed, scopes, args, kwargs):
        tool_input = args[0] if args else kwargs.get("params", kwargs)
        input_hash = self._hash(tool_input)
        # The handler context (where a presented identity credential lives).
        context = kwargs.get("context")
        if context is None and len(args) > 1:
            context = args[1]

        within = None
        violations: list[ScopeViolation] = []
        signature_verified = None
        identity_status = None
        if receipt:
            within, violations, signature_verified, identity_status = (
                self._verify_receipt(
                    receipt, tool_name, require_signed, scopes, context
                )
            )
        return {
            "input_hash": input_hash,
            "within": within,
            "violations": violations,
            "signature_verified": signature_verified,
            "identity_status": identity_status,
        }

    def _finalize(self, tool_name, receipt, ctx, result, error, start):
        latency_ms = int((time.time() - start) * 1000)
        output_hash = self._hash(result) if result is not None else None

        proof = ActionProof(
            receipt_id=receipt.receipt_id if receipt else None,
            principal=receipt.principal if receipt else None,
            agent=receipt.agent if receipt else None,
            tool_name=tool_name,
            tool_input_hash=ctx["input_hash"],
            tool_output_hash=output_hash,
            within_delegation=ctx["within"],
            signature_verified=ctx["signature_verified"],
            identity_status=ctx["identity_status"],
            violations=ctx["violations"],
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

    def _verify_receipt(
        self, receipt: Receipt, tool_name: str, require_signed: bool,
        scopes: Optional[list[str]], context,
    ) -> tuple[bool, list[ScopeViolation], Optional[bool], Optional[str]]:
        violations: list[ScopeViolation] = []

        signature_verified = self._check_signature(receipt, require_signed, violations)
        identity_status = self._check_identity(receipt, context, violations)

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

        for scope in scopes or []:
            if not receipt.permits_scope(scope):
                violations.append(
                    ScopeViolation(
                        violation_type="scope_not_permitted",
                        tool_called=tool_name,
                        scope_required=scope,
                        receipt_id=receipt.receipt_id,
                        explanation=(
                            f"Call required scope '{scope}' but delegation only "
                            f"permits: {receipt.permitted_scopes}"
                        ),
                        remediation=(
                            f"Re-issue receipt with '{scope}' in permitted_scopes."
                        ),
                    )
                )

        return (len(violations) == 0, violations, signature_verified, identity_status)

    def _check_signature(
        self, receipt: Receipt, require_signed: bool, violations: list[ScopeViolation]
    ) -> Optional[bool]:
        """Verify the receipt signature against a trusted key. See v2-design.md."""
        if not receipt.is_signed:
            if require_signed:
                violations.append(
                    ScopeViolation(
                        violation_type="signature_missing",
                        receipt_id=receipt.receipt_id,
                        explanation=(
                            f"require_signed is set but receipt {receipt.receipt_id} "
                            f"is unsigned."
                        ),
                        remediation="Sign the receipt: receipt.sign(principal_private_key).",
                    )
                )
                return False
            return None  # graceful: recorded but not cryptographically verified

        pub = (
            self._key_provider.public_key_for(receipt.principal)
            if self._key_provider
            else None
        )
        if pub is None:
            if require_signed:
                violations.append(
                    ScopeViolation(
                        violation_type="signature_unverifiable",
                        receipt_id=receipt.receipt_id,
                        explanation=(
                            f"Receipt {receipt.receipt_id} is signed but no trusted "
                            f"public key is configured for principal "
                            f"'{receipt.principal}'."
                        ),
                        remediation=(
                            "Register the principal's public key via a KeyProvider, "
                            "e.g. InMemoryKeyProvider({principal: public_key})."
                        ),
                    )
                )
            return None

        from agentledger.signing import verify as verify_signature

        ok = verify_signature(
            receipt.canonical_bytes(), receipt.signature, pub, receipt.signature_alg
        )
        if not ok:
            violations.append(
                ScopeViolation(
                    violation_type="signature_invalid",
                    receipt_id=receipt.receipt_id,
                    explanation=(
                        f"Receipt {receipt.receipt_id} signature did not verify "
                        f"against the trusted key for '{receipt.principal}' "
                        f"(alg={receipt.signature_alg})."
                    ),
                    remediation=(
                        "Re-issue and re-sign the receipt with the principal's "
                        "current key; ensure the trusted key matches."
                    ),
                )
            )
        return ok

    def _check_identity(
        self, receipt: Receipt, context, violations: list[ScopeViolation]
    ) -> Optional[str]:
        """Bind the presenting workload to the receipt's agent (threat T3)."""
        if self._identity_provider is None:
            return UNVERIFIED  # residual R4: no provider configured
        status = self._identity_provider.check(receipt.agent, context)
        if status == MISMATCH:
            violations.append(
                ScopeViolation(
                    violation_type="identity_mismatch",
                    receipt_id=receipt.receipt_id,
                    explanation=(
                        f"Presented identity does not match the receipt's agent "
                        f"'{receipt.agent}'."
                    ),
                    remediation=(
                        "Ensure the workload presents the SVID/identity that "
                        "matches the receipt's agent, or correct the receipt."
                    ),
                )
            )
        return status

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
