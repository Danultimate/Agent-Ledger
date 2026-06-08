"""Rich terminal report over a list of proofs."""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from agentledger.proof import ActionProof

console = Console()


def print_report(proofs: list[ActionProof]) -> None:
    if not proofs:
        console.print("[dim]No proofs recorded yet.[/dim]")
        return

    total = len(proofs)
    passed = sum(1 for p in proofs if p.within_delegation is True)
    violations = sum(1 for p in proofs if p.violations)
    no_receipt = sum(1 for p in proofs if p.within_delegation is None)

    console.print()
    console.print(
        Panel.fit(
            "[bold]AgentLedger Proof Report[/bold]\n"
            f"Total proofs: {total}  ·  "
            f"Within delegation: [green]{passed}[/green]  ·  "
            f"Violations: [red]{violations}[/red]  ·  "
            f"No receipt: [dim]{no_receipt}[/dim]",
            border_style="dim",
        )
    )
    console.print()

    table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    table.add_column("Proof ID", style="dim")
    table.add_column("Tool")
    table.add_column("Agent")
    table.add_column("Status")
    table.add_column("When")

    for proof in proofs:
        if proof.within_delegation is None:
            status = "[dim]unverified[/dim]"
        elif proof.within_delegation:
            status = "[green]within delegation[/green]"
        else:
            status = f"[red]VIOLATION ({len(proof.violations)})[/red]"

        table.add_row(
            proof.proof_id[:12] + "...",
            proof.tool_name,
            proof.agent or "unknown",
            status,
            proof.executed_at.strftime("%H:%M:%S"),
        )

    console.print(table)

    for proof in proofs:
        if proof.violations:
            console.print(f"\n[red]Violations in {proof.proof_id}:[/red]")
            for v in proof.violations:
                console.print(f"  [bold]{v.violation_type}[/bold]")
                console.print(f"  {v.explanation}")
                console.print(f"  [yellow]Fix: {v.remediation}[/yellow]\n")
