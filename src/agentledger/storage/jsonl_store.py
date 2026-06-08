"""Append-only JSONL storage for action proofs.

Each proof is one line of JSON. The log is never overwritten or rewritten in
place — only appended to.

Concurrency: appends take an advisory file lock (``fcntl`` on POSIX,
``msvcrt`` on Windows) so concurrent tool handlers in the same or different
processes do not interleave partial lines. The lock is best-effort; on
platforms or filesystems without lock support the append still happens.

Scale note: this is dev-grade storage. ``all()`` reads and parses the entire
log into memory; use ``iter()`` for large logs, and migrate to a database
backend beyond ~100k proofs.
"""

from __future__ import annotations

import contextlib
from pathlib import Path
from typing import Iterator, Optional

from agentledger.proof import ActionProof

try:  # POSIX
    import fcntl

    _HAVE_FCNTL = True
except ImportError:  # pragma: no cover - Windows
    _HAVE_FCNTL = False

try:  # Windows
    import msvcrt

    _HAVE_MSVCRT = True
except ImportError:
    _HAVE_MSVCRT = False


@contextlib.contextmanager
def _locked(file_obj):
    """Best-effort exclusive lock around a write."""
    locked = False
    try:
        if _HAVE_FCNTL:
            fcntl.flock(file_obj.fileno(), fcntl.LOCK_EX)
            locked = True
        elif _HAVE_MSVCRT:  # pragma: no cover - Windows
            try:
                msvcrt.locking(file_obj.fileno(), msvcrt.LK_LOCK, 1)
                locked = True
            except OSError:
                locked = False
        yield
    finally:
        if locked and _HAVE_FCNTL:
            fcntl.flock(file_obj.fileno(), fcntl.LOCK_UN)
        elif locked and _HAVE_MSVCRT:  # pragma: no cover - Windows
            with contextlib.suppress(OSError):
                msvcrt.locking(file_obj.fileno(), msvcrt.LK_UNLCK, 1)


class JSONLStore:
    def __init__(self, path: str):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if not self._path.exists():
            self._path.touch()

    @property
    def path(self) -> Path:
        return self._path

    def append(self, proof: ActionProof) -> None:
        line = proof.model_dump_json()
        with self._path.open("a", encoding="utf-8") as f:
            with _locked(f):
                f.write(line + "\n")
                f.flush()

    def iter(self) -> Iterator[ActionProof]:
        """Stream proofs one at a time. Skips blank lines.

        A single corrupt line raises; callers that must survive corruption
        should catch and continue. We surface it by default so silent data
        loss does not masquerade as a clean log.
        """
        with self._path.open("r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    yield ActionProof.model_validate_json(line)

    def all(self) -> list[ActionProof]:
        return list(self.iter())

    def get(self, proof_id: str) -> Optional[ActionProof]:
        for proof in self.iter():
            if proof.proof_id == proof_id:
                return proof
        return None

    def last(self) -> Optional[ActionProof]:
        last_proof: Optional[ActionProof] = None
        for proof in self.iter():
            last_proof = proof
        return last_proof
