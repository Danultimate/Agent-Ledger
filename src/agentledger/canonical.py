"""Canonical, byte-stable JSON serialization.

These bytes are LOAD-BEARING and FROZEN: receipt signatures (v2) and proof-chain
hashes will sign / hash exactly this output. Any change to key ordering,
separators, or encoding silently invalidates every existing signature and breaks
every existing hash chain.

Do NOT change this function in place. To evolve a signed/hashed structure,
bump the ``_v`` version tag inside that structure's payload (see
``RECEIPT_PAYLOAD_VERSION`` / ``CHAIN_PAYLOAD_VERSION``) and branch on it, so old
records remain verifiable.
"""

from __future__ import annotations

import json
from typing import Any


def canonical_json(obj: Any) -> str:
    """Deterministic JSON: sorted keys, no whitespace, ASCII-escaped.

    ``ensure_ascii=True`` is intentional — it makes the output independent of
    locale and terminal encoding, which matters for reproducible signatures.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def canonical_bytes(obj: Any) -> bytes:
    return canonical_json(obj).encode("utf-8")
