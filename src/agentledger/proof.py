"""Action proofs.

Action proofs are tamper-evident records of what an agent did, tied to the
delegation receipt that recorded what it was permitted to do.

SECURITY NOTE:
Hash-chain integrity proves the log has not been tampered with after the fact.
It does NOT prove the action was authorized at execution time. AgentLedger
records what happened and whether it matched the receipt. It does not prevent
unauthorized actions.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field
from ulid import ULID


def _new_proof_id() -> str:
    return f"act_{ULID()}"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ScopeViolation(BaseModel):
    # v1: "tool_not_permitted" | "scope_not_permitted" | "receipt_expired"
    # v2: + "signature_missing" | "signature_invalid" | "signature_unverifiable"
    #       | "identity_mismatch"
    violation_type: str
    tool_called: Optional[str] = None
    scope_required: Optional[str] = None
    receipt_id: Optional[str] = None
    explanation: str
    remediation: str


class ActionProof(BaseModel):
    proof_id: str = Field(default_factory=_new_proof_id)
    receipt_id: Optional[str] = None
    principal: Optional[str] = None
    agent: Optional[str] = None
    tool_name: str
    tool_input_hash: str       # SHA256 digest of input — not raw input
    tool_output_hash: Optional[str] = None
    within_delegation: Optional[bool] = None  # None if no receipt provided
    # v2 crypto status, recorded independently so within_delegation=True is never
    # mistaken for "cryptographically verified":
    #   signature_verified: None = unsigned/unverifiable, True/False = checked
    #   identity_status:    None = no receipt / no provider, else
    #                       "verified" | "unverified" | "mismatch"
    signature_verified: Optional[bool] = None
    identity_status: Optional[str] = None
    violations: list[ScopeViolation] = Field(default_factory=list)
    executed_at: datetime = Field(default_factory=_utcnow)
    latency_ms: Optional[int] = None
    error: Optional[str] = None
    previous_proof_hash: Optional[str] = None  # hash-chain link
    proof_hash: Optional[str] = None           # hash of this proof

    @property
    def passed(self) -> bool:
        """True when the action was within delegation (or unverified) and clean.

        Note ``within_delegation is None`` means *no receipt was provided*, i.e.
        the action was recorded but not checked. Such a proof reports
        ``passed = True`` because there was nothing to violate; inspect
        ``within_delegation`` directly if you need to distinguish "verified OK"
        from "not verified".
        """
        return self.within_delegation is not False and not self.violations
