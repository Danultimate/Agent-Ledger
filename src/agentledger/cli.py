"""AgentLedger CLI."""

from __future__ import annotations

from pathlib import Path

import click

DEFAULT_LOG = "./logs/agent-proofs.jsonl"


@click.group()
@click.version_option(package_name="agentledger-llm")
def cli():
    """AgentLedger — action-time proof for MCP agents."""


@cli.command()
def init():
    """Scaffold agentledger.yaml and a working example."""
    Path("agentledger.yaml").write_text(
        f"proof_log: {DEFAULT_LOG}\n"
        "auto_integrate_traceforge: true\n",
        encoding="utf-8",
    )

    Path("agent_example.py").write_text(_EXAMPLE, encoding="utf-8")

    click.echo("Created agentledger.yaml")
    click.echo("Created agent_example.py")
    click.echo("\nNext: python agent_example.py")


@cli.command(name="report")
@click.option("--log", default=DEFAULT_LOG, show_default=True, help="Proof log path")
@click.option(
    "--format", "fmt", default="terminal",
    type=click.Choice(["terminal", "html"]), show_default=True,
)
@click.option("--out", default="agentledger-report.html", show_default=True,
              help="Output path for --format html")
def report_cmd(log, fmt, out):
    """Print a proof report from a log file (always exits 0 — informational)."""
    from agentledger.storage.jsonl_store import JSONLStore

    store = JSONLStore(log)
    proofs = store.all()
    if not proofs:
        click.echo("No proofs found.")
        return
    if fmt == "terminal":
        from agentledger.report.terminal import print_report

        print_report(proofs)
    else:
        from agentledger.report.html_report import save_report

        click.echo(f"Wrote {save_report(proofs, out)}")


@cli.command()
@click.argument("proof_id")
@click.option("--log", default=DEFAULT_LOG, show_default=True)
def verify(proof_id, log):
    """Verify a specific proof by ID. Exits 1 if violations were recorded."""
    from agentledger.storage.jsonl_store import JSONLStore
    from agentledger.verifier import Verifier

    store = JSONLStore(log)
    proof = store.get(proof_id)
    if not proof:
        click.echo(f"No proof found: {proof_id}")
        raise SystemExit(1)
    verdict = Verifier().verdict(proof)
    verdict.print()
    if not verdict.passed:
        raise SystemExit(1)


@cli.command()
@click.option("--log", default=DEFAULT_LOG, show_default=True)
def chain(log):
    """Verify hash-chain integrity of the proof log. Exits 1 if tampered."""
    from agentledger.chain import HashChain
    from agentledger.storage.jsonl_store import JSONLStore

    store = JSONLStore(log)
    proofs = store.all()
    intact = HashChain().verify(proofs)
    if intact:
        click.echo(f"Chain intact — {len(proofs)} proofs verified")
    else:
        click.echo("Chain tampered — log may have been modified")
        raise SystemExit(1)


_EXAMPLE = '''"""
AgentLedger quickstart — action-time proof for MCP tool calls.

NOTE: AgentLedger RECORDS and attributes tool calls. By default it does not
block them — a call that violates the receipt is recorded as a proof and the
tool still runs. Pass on_violation="raise" to record-then-block.

Run: python agent_example.py
"""
import asyncio
from agentledger import Ledger

ledger = Ledger(proof_log="./logs/agent-proofs.jsonl")

# Issue a delegation receipt (advisory metadata, not an auth token)
receipt = ledger.issue_receipt(
    principal="user:you",
    agent="agent:my-financial-assistant",
    permitted_tools=["get_exchange_rates", "set_price_alert"],
    permitted_scopes=["read:rates", "write:alerts"],
    expires_in=3600,
)


@ledger.record(receipt=receipt)
async def get_exchange_rates(params, context=None):
    """Simulated MCP tool handler."""
    return {"base": params.get("base", "USD"), "rates": {"GBP": 0.79, "EUR": 0.92}}


@ledger.record(receipt=receipt)
async def delete_alert(params, context=None):
    """NOT in the receipt — this records a violation (and still runs)."""
    return {"deleted": True}


async def main():
    # Within delegation
    print("Rates:", await get_exchange_rates({"base": "USD"}))

    # Exceeds delegation — recorded as a violation, not blocked
    await delete_alert({"alert_id": "alert_123"})

    # Report, verdict, chain integrity
    ledger.report()
    ledger.verify(ledger.last().proof_id).print()
    intact = ledger.verify_chain()
    print("\\nChain integrity:", "intact" if intact else "tampered")


if __name__ == "__main__":
    asyncio.run(main())
'''


if __name__ == "__main__":
    cli()
