"""AgentLedger — action-time proof and delegation verification for MCP agents.

AgentLedger records tamper-evident proofs of what an agent did, tied to the
delegation receipt that recorded what a principal permitted it to do.

It sits *after* authentication, not instead of it:

    OAuth 2.1     -> who are you?
    WIMSE WPT     -> which agent are you?
    AgentLedger   -> what did you do, recorded against whom?

IMPORTANT: AgentLedger records and attributes actions. It does NOT enforce
authorization — a violating tool call is recorded, not blocked (see
``Ledger.record`` for the ``on_violation`` option). Hash-chain integrity makes
the log tamper-evident; it does not prove an action was authorized at execution
time by a cryptographically verified identity.
"""

from agentledger.ledger import Ledger, DelegationViolation
from agentledger.receipt import Receipt
from agentledger.proof import ActionProof, ScopeViolation
from agentledger.verifier import Verifier, Verdict

__version__ = "0.1.0"

__all__ = [
    "Ledger",
    "DelegationViolation",
    "Receipt",
    "ActionProof",
    "ScopeViolation",
    "Verifier",
    "Verdict",
    "__version__",
]
