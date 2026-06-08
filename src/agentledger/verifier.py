"""Verifier and Verdict.

A ``Verdict`` re-states what a proof already recorded: which tool ran, for which
principal, whether it was within delegation, and any violations. The
``Verifier`` produces a ``Verdict`` from a stored proof.

This is interpretation of a record, not re-execution or re-authorization.
"""

from __future__ import annotations

from agentledger.proof import ActionProof
from rich.console import Console
from rich.panel import Panel

console = Console()


class Verifier:
    """Produces a :class:`Verdict` for a recorded proof."""

    def verdict(self, proof: ActionProof) -> "Verdict":
        return Verdict(proof)


class Verdict:
    """Structured result of verifying a proof against its receipt.

    Attributes:
        within_delegation: True | False | None (None = no receipt was provided)
        violations:        list of ScopeViolation
        explanation:       human-readable summary
        passed:            True if there were no violations
    """

    def __init__(self, proof: ActionProof):
        self.proof_id = proof.proof_id
        self.tool_name = proof.tool_name
        self.principal = proof.principal
        self.agent = proof.agent
        self.within_delegation = proof.within_delegation
        self.violations = proof.violations
        self.executed_at = proof.executed_at
        self.passed = proof.passed
        self.explanation = self._build_explanation(proof)

    def _build_explanation(self, proof: ActionProof) -> str:
        if proof.within_delegation is None:
            return (
                f"Agent called '{proof.tool_name}' at {proof.executed_at.isoformat()}. "
                f"No delegation receipt provided — action recorded but not "
                f"checked against intent."
            )
        if proof.within_delegation:
            return (
                f"Agent '{proof.agent}' called '{proof.tool_name}' "
                f"on behalf of '{proof.principal}' at {proof.executed_at.isoformat()}. "
                f"Action was within delegation."
            )
        violation_summary = "; ".join(v.explanation for v in proof.violations)
        return (
            f"Agent '{proof.agent}' called '{proof.tool_name}' "
            f"on behalf of '{proof.principal}' at {proof.executed_at.isoformat()}. "
            f"VIOLATIONS RECORDED: {violation_summary}"
        )

    def print(self) -> None:
        color = "green" if self.passed else "red"
        status = "WITHIN DELEGATION" if self.passed else "VIOLATION RECORDED"
        console.print()
        console.print(
            Panel.fit(
                f"[bold]{status}[/bold]\n"
                f"Proof:  [dim]{self.proof_id}[/dim]\n"
                f"Tool:   {self.tool_name}\n"
                f"Agent:  {self.agent or 'unknown'}\n"
                f"For:    {self.principal or 'unknown'}\n\n"
                f"{self.explanation}",
                border_style=color,
            )
        )
        if self.violations:
            for v in self.violations:
                console.print(f"\n[red]  VIOLATION: {v.violation_type}[/red]")
                console.print(f"  [dim]{v.explanation}[/dim]")
                console.print(f"  [yellow]Fix: {v.remediation}[/yellow]")
        console.print()
