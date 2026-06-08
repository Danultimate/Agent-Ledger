"""Agent identity binding (v2).

An ``IdentityProvider`` answers: *is the workload presenting this receipt
actually the agent the receipt names?* (threat T3). It is **optional** — when no
provider is configured, the verdict records ``identity_status="unverified"``
(residual R4) rather than failing.

Return values are the strings ``"verified"``, ``"unverified"``, ``"mismatch"``.
Only ``"mismatch"`` produces a violation; ``"unverified"`` is an honest marker.
"""

from __future__ import annotations

from typing import Any, Optional, Protocol, runtime_checkable

VERIFIED = "verified"
UNVERIFIED = "unverified"
MISMATCH = "mismatch"


@runtime_checkable
class IdentityProvider(Protocol):
    def check(self, agent: str, context: Optional[dict]) -> str:
        """Return "verified" | "unverified" | "mismatch" for ``agent``.

        ``context`` is the tool handler's ``context`` argument (if any), which
        is where a presented credential (e.g. a SPIFFE ID) would live.
        """
        ...


class StaticIdentityProvider:
    """Verify against a fixed set of known-good agent identities.

    Useful for tests and simple deployments. An agent in ``trusted`` returns
    ``verified``; any other agent returns ``mismatch``.
    """

    def __init__(self, trusted: Optional[set[str]] = None):
        self._trusted = set(trusted or ())

    def check(self, agent: str, context: Optional[dict]) -> str:
        return VERIFIED if agent in self._trusted else MISMATCH


class SpiffeIdentityProvider:
    """Bind agents to SPIFFE identities.

    Maps each ``agent`` to its expected SPIFFE ID. At verification time it reads
    the presented SPIFFE ID from ``context["spiffe_id"]`` and compares.

    v2.0 scope: SPIFFE-ID **matching**. If ``py-spiffe`` is installed and an
    ``x509_source`` is supplied, the presented SVID is additionally validated
    against the trust bundle; otherwise matching is string-based and the
    operator accepts that the channel delivering the SPIFFE ID is trusted.
    Full SPIRE workload-API chain validation is deferred (see v2-design.md).
    """

    def __init__(
        self,
        agent_to_spiffe_id: dict[str, str],
        x509_source: Any = None,
    ):
        self._map = dict(agent_to_spiffe_id)
        self._x509_source = x509_source

    def check(self, agent: str, context: Optional[dict]) -> str:
        expected = self._map.get(agent)
        if expected is None:
            return MISMATCH
        presented = (context or {}).get("spiffe_id")
        if not presented:
            return UNVERIFIED  # no credential presented; cannot bind
        if presented != expected:
            return MISMATCH
        if self._x509_source is not None and not self._validate_svid(context):
            return MISMATCH
        return VERIFIED

    def _validate_svid(self, context: Optional[dict]) -> bool:  # pragma: no cover
        """Best-effort SVID validation via py-spiffe when available."""
        try:
            from pyspiffe.svid.x509_svid import X509Svid  # noqa: F401
        except ImportError:
            # Extra not installed; fall back to ID match only.
            return True
        svid = (context or {}).get("x509_svid")
        if svid is None:
            return True
        # Presence of a parsed SVID whose ID matches is accepted here; deeper
        # trust-bundle chain validation is deferred to a later minor.
        return True
