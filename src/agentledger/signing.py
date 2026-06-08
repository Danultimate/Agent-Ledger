"""Ed25519 signing for delegation receipts (v2).

The principal signs ``Receipt.canonical_bytes()`` — the frozen
``agentledger.receipt.v1`` payload — and the signature is stored in
``Receipt.signature`` (base64) with ``Receipt.signature_alg = "ed25519"``.

The accepted algorithm set is **pinned** here. ``alg`` markers on a receipt are
informational; verification only ever uses an algorithm from ``ACCEPTED_ALGS``,
which forbids algorithm-confusion and ``none`` attacks (threat T10).

``cryptography`` is an optional dependency (extra ``crypto``). Functions raise a
clear error if it is not installed; the unsigned/graceful flow needs no crypto.
"""

from __future__ import annotations

import base64
from typing import Any, Optional

SIGNATURE_ALG = "ed25519"
ACCEPTED_ALGS = frozenset({SIGNATURE_ALG})


class CryptoUnavailable(RuntimeError):
    """Raised when a crypto operation is attempted without `cryptography`."""


def _require_crypto():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ImportError as e:  # pragma: no cover - exercised only without extra
        raise CryptoUnavailable(
            "Ed25519 signing/verification requires the 'cryptography' package. "
            "Install with: pip install 'agentledger-llm[crypto]'"
        ) from e
    return Ed25519PrivateKey, Ed25519PublicKey


def generate_keypair():
    """Return a fresh ``(private_key, public_key)`` Ed25519 pair."""
    Ed25519PrivateKey, _ = _require_crypto()
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def sign(payload: bytes, private_key) -> str:
    """Sign ``payload`` bytes, returning a base64 signature string."""
    _require_crypto()
    return base64.b64encode(private_key.sign(payload)).decode("ascii")


def verify(
    payload: bytes,
    signature_b64: str,
    public_key,
    alg: Optional[str] = SIGNATURE_ALG,
) -> bool:
    """Verify a base64 Ed25519 signature over ``payload``.

    Returns False on any failure (bad signature, malformed base64, or a
    non-accepted algorithm marker) — never raises for an invalid signature.
    """
    if alg is not None and alg not in ACCEPTED_ALGS:
        return False
    try:
        from cryptography.exceptions import InvalidSignature
    except ImportError as e:  # pragma: no cover
        raise CryptoUnavailable(
            "Signature verification requires the 'cryptography' package. "
            "Install with: pip install 'agentledger-llm[crypto]'"
        ) from e
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (ValueError, TypeError):
        return False
    try:
        public_key.verify(signature, payload)
        return True
    except InvalidSignature:
        return False


# --- key serialization helpers (raw 32-byte, base64) ------------------------- #

def public_key_to_b64(public_key) -> str:
    from cryptography.hazmat.primitives import serialization

    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def public_key_from_b64(data: str):
    _, Ed25519PublicKey = _require_crypto()
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(data))


def private_key_to_b64(private_key) -> str:
    from cryptography.hazmat.primitives import serialization

    raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return base64.b64encode(raw).decode("ascii")


def private_key_from_b64(data: str):
    Ed25519PrivateKey, _ = _require_crypto()
    return Ed25519PrivateKey.from_private_bytes(base64.b64decode(data))


def coerce_public_key(key: Any):
    """Accept an Ed25519PublicKey or a base64 raw key string; return the object."""
    if isinstance(key, str):
        return public_key_from_b64(key)
    return key
