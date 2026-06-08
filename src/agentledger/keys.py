"""Key resolution for receipt signature verification (v2).

The verifier resolves a principal's **trusted** public key through a
``KeyProvider``. Keys must come from a trust source the verifier already holds —
never from the receipt itself (an embedded key would make forgery trivial, T1).
"""

from __future__ import annotations

from typing import Any, Optional, Protocol, runtime_checkable

from agentledger.signing import coerce_public_key


@runtime_checkable
class KeyProvider(Protocol):
    def public_key_for(self, principal: str) -> Optional[Any]:
        """Return the trusted Ed25519 public key for ``principal``, or None."""
        ...


class InMemoryKeyProvider:
    """Trust store backed by a dict of ``{principal: public_key}``.

    Values may be ``Ed25519PublicKey`` objects or base64 raw-key strings.
    """

    def __init__(self, keys: Optional[dict[str, Any]] = None):
        self._keys: dict[str, Any] = {}
        for principal, key in (keys or {}).items():
            self.add(principal, key)

    def add(self, principal: str, key: Any) -> None:
        self._keys[principal] = coerce_public_key(key)

    def public_key_for(self, principal: str) -> Optional[Any]:
        return self._keys.get(principal)
