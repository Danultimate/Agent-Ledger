"""Delegation receipts.

Delegation receipts are advisory metadata — not auth tokens. They record what a
principal intended to permit an agent to do. They are structurally aligned with
WIMSE WPT conventions (IETF draft), but AgentLedger does NOT perform
cryptographic verification of them in v1.

AgentLedger sits after authentication, not instead of it. OAuth 2.1 validates
the token. AgentLedger records the delegation intent and records whether the
agent acted within it.

The ``constraints`` field is advisory only: AgentLedger records that a
constraint was stated, not that it was enforced.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field
from ulid import ULID

from agentledger.canonical import canonical_bytes, canonical_json

# Version tag for the signable receipt payload. v2 receipt signing will sign
# exactly the bytes produced by `Receipt.canonical_bytes()` for this version.
# This layout is FROZEN — to change it, introduce "agentledger.receipt.v2" and
# branch on the tag; never edit the v1 layout in place.
RECEIPT_PAYLOAD_VERSION = "agentledger.receipt.v1"


def _new_receipt_id() -> str:
    return f"rcpt_{ULID()}"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Receipt(BaseModel):
    receipt_id: str = Field(default_factory=_new_receipt_id)
    principal: str                # "user:daniel@company.com"
    agent: str                    # "agent:financial-analyst-v2"
    permitted_tools: list[str]    # ["get_exchange_rates", "set_price_alert"]
    permitted_scopes: list[str]   # ["read:rates", "write:alerts"]
    issued_at: datetime = Field(default_factory=_utcnow)
    expires_at: Optional[datetime] = None
    constraints: dict = Field(default_factory=dict)  # advisory only
    wimse_compatible: bool = True  # structural alignment marker, not verified
    signature: Optional[str] = None       # base64 Ed25519 signature (v2)
    signature_alg: Optional[str] = None   # e.g. "ed25519"; pinned set verified

    @property
    def is_expired(self) -> bool:
        if not self.expires_at:
            return False
        return _utcnow() > self.expires_at

    @property
    def fingerprint(self) -> str:
        """Stable, non-secret identifier for this receipt's *intent*.

        Covers principal/agent/tools/scopes only — not time or receipt_id — so
        two receipts granting the same thing share a fingerprint. Truncated for
        readability. This is an identifier, not a privacy or integrity guarantee
        — do not treat it as a secret. For the full signable grant, use
        :meth:`canonical_bytes`.
        """
        payload = canonical_json(
            {
                "principal": self.principal,
                "agent": self.agent,
                "permitted_tools": sorted(self.permitted_tools),
                "permitted_scopes": sorted(self.permitted_scopes),
            }
        )
        return hashlib.sha256(payload.encode()).hexdigest()[:16]

    def signing_payload(self) -> dict:
        """The version-tagged set of fields a principal signs (v2).

        Excludes ``signature`` itself. Unlike :attr:`fingerprint`, this is the
        *full grant* — receipt_id and time bounds included — so each issued
        receipt has a unique, replay-resistant signature. The layout is FROZEN
        for ``RECEIPT_PAYLOAD_VERSION``; see ``agentledger.canonical``.
        """
        return {
            "_v": RECEIPT_PAYLOAD_VERSION,
            "receipt_id": self.receipt_id,
            "principal": self.principal,
            "agent": self.agent,
            "permitted_tools": sorted(self.permitted_tools),
            "permitted_scopes": sorted(self.permitted_scopes),
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "constraints": self.constraints,
            "wimse_compatible": self.wimse_compatible,
        }

    def canonical_bytes(self) -> bytes:
        """Byte-stable serialization of :meth:`signing_payload` for signing/verify."""
        return canonical_bytes(self.signing_payload())

    def sign(self, private_key) -> "Receipt":
        """Sign this receipt with the principal's Ed25519 private key (v2).

        Sets ``signature`` and ``signature_alg`` in place and returns self.
        Requires the ``crypto`` extra (``pip install 'agentledger-llm[crypto]'``).
        """
        from agentledger.signing import SIGNATURE_ALG, sign

        self.signature = sign(self.canonical_bytes(), private_key)
        self.signature_alg = SIGNATURE_ALG
        return self

    @property
    def is_signed(self) -> bool:
        return bool(self.signature)

    def permits_tool(self, tool_name: str) -> bool:
        return tool_name in self.permitted_tools

    def permits_scope(self, scope: str) -> bool:
        return scope in self.permitted_scopes
