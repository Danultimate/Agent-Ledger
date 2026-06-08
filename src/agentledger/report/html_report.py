"""Self-contained HTML report.

Built with plain string formatting (no template engine) so the package keeps a
minimal dependency footprint. Output is a single static .html file with no
external assets.
"""

from __future__ import annotations

import html
from pathlib import Path

from agentledger.proof import ActionProof

_STYLE = """
body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem;
       color: #1a1a1a; background: #fafafa; }
h1 { font-size: 1.4rem; }
.summary { display: flex; gap: 1.5rem; margin: 1rem 0 2rem; }
.summary div { padding: .75rem 1rem; border-radius: 8px; background: #fff;
               border: 1px solid #e5e5e5; }
.ok { color: #15803d; } .bad { color: #b91c1c; } .muted { color: #71717a; }
table { width: 100%; border-collapse: collapse; background: #fff;
        border: 1px solid #e5e5e5; border-radius: 8px; overflow: hidden; }
th, td { text-align: left; padding: .6rem .8rem; border-bottom: 1px solid #f0f0f0;
         font-size: .9rem; }
th { background: #f6f6f6; }
.viol { background: #fef2f2; border: 1px solid #fecaca; border-radius: 8px;
        padding: 1rem; margin-top: 1rem; }
code { font-family: ui-monospace, Menlo, monospace; font-size: .82rem; }
.note { font-size: .8rem; color: #71717a; margin-top: 2rem; }
"""

_SECURITY_NOTE = (
    "Hash-chain integrity makes this log tamper-evident — it records that the "
    "log has not been modified after the fact. It does not prove actions were "
    "authorized at execution time by a cryptographically verified identity."
)


def _status_cell(proof: ActionProof) -> str:
    if proof.within_delegation is None:
        return '<span class="muted">unverified</span>'
    if proof.within_delegation:
        return '<span class="ok">within delegation</span>'
    return f'<span class="bad">VIOLATION ({len(proof.violations)})</span>'


def render_report(proofs: list[ActionProof]) -> str:
    total = len(proofs)
    passed = sum(1 for p in proofs if p.within_delegation is True)
    violations = sum(1 for p in proofs if p.violations)
    no_receipt = sum(1 for p in proofs if p.within_delegation is None)

    rows = []
    for p in proofs:
        rows.append(
            "<tr>"
            f"<td><code>{html.escape(p.proof_id)}</code></td>"
            f"<td>{html.escape(p.tool_name)}</td>"
            f"<td>{html.escape(p.agent or 'unknown')}</td>"
            f"<td>{_status_cell(p)}</td>"
            f"<td>{html.escape(p.executed_at.isoformat())}</td>"
            "</tr>"
        )

    viol_blocks = []
    for p in proofs:
        for v in p.violations:
            viol_blocks.append(
                '<div class="viol">'
                f"<strong>{html.escape(v.violation_type)}</strong> "
                f"in <code>{html.escape(p.proof_id)}</code>"
                f"<p>{html.escape(v.explanation)}</p>"
                f"<p><em>Fix:</em> {html.escape(v.remediation)}</p>"
                "</div>"
            )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>AgentLedger Proof Report</title>
<style>{_STYLE}</style>
</head>
<body>
<h1>AgentLedger Proof Report</h1>
<div class="summary">
  <div>Total proofs<br><strong>{total}</strong></div>
  <div>Within delegation<br><strong class="ok">{passed}</strong></div>
  <div>Violations<br><strong class="bad">{violations}</strong></div>
  <div>No receipt<br><strong class="muted">{no_receipt}</strong></div>
</div>
<table>
<thead><tr><th>Proof ID</th><th>Tool</th><th>Agent</th><th>Status</th><th>When</th></tr></thead>
<tbody>
{''.join(rows)}
</tbody>
</table>
{''.join(viol_blocks)}
<p class="note">{html.escape(_SECURITY_NOTE)}</p>
</body>
</html>
"""


def save_report(proofs: list[ActionProof], path: str = "agentledger-report.html") -> str:
    out = Path(path)
    out.write_text(render_report(proofs), encoding="utf-8")
    return str(out)
