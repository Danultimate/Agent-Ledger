"""Hash-chain integrity for the proof log.

Each proof's hash incorporates the previous proof's hash, so any modification,
reordering, insertion, or deletion in the middle of the log is detectable.

IMPORTANT: the hash-chain proves the log has not been modified after recording.
It does NOT prove actions were authorized at execution time. Do not make
stronger claims than this to users.

The chain head is in-memory, but is restored from the persisted log on startup
(see ``Ledger.__init__`` -> ``HashChain.restore_from``) so that proofs appended
across process restarts remain linked. Without that restore step a restarted
process would link its first new proof to ``None`` and silently break the chain.
"""

from __future__ import annotations

import hashlib
from typing import Optional

from agentledger.canonical import canonical_bytes

# Version tag for the hashed proof payload. proof_hash values are persisted in
# every log line, so this layout is FROZEN — to change it, introduce
# "agentledger.chain.v2" and branch on the tag so old logs still verify.
CHAIN_PAYLOAD_VERSION = "agentledger.chain.v1"


class HashChain:
    def __init__(self) -> None:
        self._head: Optional[str] = None

    @property
    def head(self) -> Optional[str]:
        return self._head

    def restore_from(self, proofs: list) -> Optional[str]:
        """Seed the head from an existing (on-disk) log.

        Sets the head to the last proof's stored ``proof_hash`` so the next
        appended proof links correctly. Returns the restored head.
        """
        if proofs:
            self._head = proofs[-1].proof_hash
        else:
            self._head = None
        return self._head

    def append(self, proof) -> str:
        """Compute this proof's hash (linking the current head) and advance."""
        proof_hash = self._compute(proof, self._head)
        self._head = proof_hash
        return proof_hash

    def verify(self, proofs: list) -> bool:
        """Verify chain integrity across all proofs. Returns False if tampered."""
        prev_hash: Optional[str] = None
        for proof in proofs:
            # A proof must declare the predecessor it was chained to.
            if proof.previous_proof_hash != prev_hash:
                return False
            expected = self._compute(proof, prev_hash)
            if expected != proof.proof_hash:
                return False
            prev_hash = proof.proof_hash
        return True

    @staticmethod
    def _compute(proof, previous_hash: Optional[str]) -> str:
        payload = {
            "_v": CHAIN_PAYLOAD_VERSION,
            "proof_id": proof.proof_id,
            "tool_name": proof.tool_name,
            "tool_input_hash": proof.tool_input_hash,
            "executed_at": proof.executed_at.isoformat(),
            "receipt_id": proof.receipt_id,
            "within_delegation": proof.within_delegation,
            "previous_hash": previous_hash,
        }
        return hashlib.sha256(canonical_bytes(payload)).hexdigest()
