"""Report generation for the evasion subsystem.

Two HTML artifacts are produced per scan, deliberately kept as separate
files rather than nested inside one page:

  - report.html
        CHIMERA's own normalized report: the CHIMERA score (with its
        rationale), every tool's native (unweighted) summary side by side,
        the combined checks table across all tools, and links to every raw
        artifact. This is the "CHIMERA normalized evasion score" half of the
        required distinction.

  - raw/perdedor/perdedor-native-report.html
        PERDEDOR's OWN renderer (perdedor_common.report.render_html), run
        unmodified over the raw report exactly as the `perdedor report` CLI
        command would produce it - byte-identical to what the upstream tool
        generates from the same JSON. This is the "tool-native result" half
        of the distinction, and satisfies the project's requirement for
        independently verifiable, unmodified native output.

perdedor_common.report.render_html() returns a *complete* standalone HTML
document (its own <!doctype>/<html>/<head>/<style>) - embedding that string
inside report.html's own <body> would nest two documents and produce broken
markup, which is why it is written as its own sibling file and linked to,
never inlined.

evasion.json is the third artifact: EvasionScanMetadata.store_to_dict(),
which already contains every ToolResult, NormalizedCheck and EvasionScore
produced by the adapters (Phase B) and scoring module (Phase C) - this
module only serializes it to disk.
"""

from __future__ import annotations

import html as html_lib
import json
import logging
import pathlib
from typing import Any, List, Optional

from drakrun.evasion.constants import REPORT_FILENAME, RESULT_FILENAME
from drakrun.evasion.models import EvasionScanMetadata, NormalizedCheck, ToolResult
from drakrun.evasion.scoring import PRIMARY_TOOL_ID

logger = logging.getLogger(__name__)


def write_evasion_json(
    scan_dir: pathlib.Path, metadata: EvasionScanMetadata
) -> pathlib.Path:
    """Write the full normalized scan record (per-tool results, every
    NormalizedCheck, and the EvasionScore) to evasion.json."""
    path = scan_dir / RESULT_FILENAME
    path.write_text(json.dumps(metadata.store_to_dict(), indent=2), encoding="utf-8")
    return path


def write_perdedor_native_report(scan_dir: pathlib.Path) -> Optional[pathlib.Path]:
    """Render PERDEDOR's own raw report through its own perdedor_common
    renderer, unmodified.

    Returns None (and never raises) if no raw PERDEDOR report is present, or
    it fails to parse or validate - PERDEDOR's raw JSON itself is untouched
    either way, since raw artifacts are never deleted regardless of whether
    a derived rendering succeeds.
    """
    raw_report_path = scan_dir / "raw" / PRIMARY_TOOL_ID / "windows-report.json"
    if not raw_report_path.exists():
        return None

    try:
        from perdedor_common.report import aggregate_reports, render_html
        from perdedor_common.validation import ValidationError
    except ImportError:
        logger.warning(
            "perdedor_common is not installed; skipping native report rendering."
        )
        return None

    try:
        raw_report = json.loads(raw_report_path.read_text(encoding="utf-8"))
        aggregate = aggregate_reports([raw_report])
        native_html = render_html(aggregate)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValidationError) as exc:
        logger.warning("Could not render PERDEDOR's native report: %s", exc)
        return None

    out_path = raw_report_path.parent / "perdedor-native-report.html"
    out_path.write_text(native_html, encoding="utf-8")
    return out_path


_STATE_LABELS = {
    "pass": "PASS",
    "warn": "WARN",
    "fail": "FAIL",
    "incomplete": "INCOMPLETE - no score available",
}


def _fmt_evidence(evidence: Any) -> str:
    if evidence is None:
        return ""
    if isinstance(evidence, str):
        return html_lib.escape(evidence)
    try:
        return html_lib.escape(json.dumps(evidence))
    except TypeError:
        return html_lib.escape(str(evidence))


def _tool_summary_rows(tool_scores: dict) -> str:
    rows = []
    for tool_id, summary in tool_scores.items():
        weighted = summary.get("weighted_score")
        if weighted is not None:
            weighted_cell = f"{weighted:.2f}"
        elif tool_id == PRIMARY_TOOL_ID:
            weighted_cell = "n/a"
        else:
            weighted_cell = "n/a (no native scoring)"
        rows.append(
            "<tr>"
            f"<td>{html_lib.escape(tool_id)}</td>"
            f"<td>{html_lib.escape(str(summary.get('tool_version') or '-'))}</td>"
            f"<td>{html_lib.escape(summary.get('status', ''))}</td>"
            f"<td>{html_lib.escape(summary.get('raw_score', ''))}</td>"
            f"<td>{summary.get('detected', 0)}</td>"
            f"<td>{summary.get('errored', 0)}</td>"
            f"<td>{summary.get('skipped', 0)}</td>"
            f"<td>{weighted_cell}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def _checks_table_rows(tool_results: List[ToolResult]) -> str:
    rows = []
    for result in tool_results:
        for check in result.checks:
            rows.append(_check_row(check))
    return "\n".join(rows)


def _check_row(check: NormalizedCheck) -> str:
    return (
        "<tr>"
        f"<td>{html_lib.escape(check.tool)}</td>"
        f"<td>{html_lib.escape(check.category.value)}</td>"
        f'<td class="status-{html_lib.escape(check.status.value)}">{html_lib.escape(check.status.value)}</td>'
        f"<td>{html_lib.escape(check.severity.value)}</td>"
        f"<td>{html_lib.escape(check.name)}</td>"
        f"<td>{html_lib.escape(check.description)}</td>"
        f"<td>{_fmt_evidence(check.evidence)}</td>"
        f"<td>{html_lib.escape(check.remediation or '')}</td>"
        "</tr>"
    )


_CSS = """
body { font-family: system-ui, sans-serif; margin: 2rem; color: #1a1a1a; }
h1 { margin-bottom: 0.25rem; }
.meta { color: #555; margin-top: 0; }
.score-card { display: inline-block; padding: 1rem 1.5rem; border-radius: 8px; margin-right: 1rem; }
.score-card.pass { background: #e6f4ea; border: 1px solid #1a7f37; }
.score-card.warn { background: #fff8e1; border: 1px solid #9a6700; }
.score-card.fail { background: #fdecea; border: 1px solid #cf222e; }
.score-card.incomplete { background: #f1f2f4; border: 1px solid #57606a; }
.score-num { font-size: 2rem; font-weight: bold; }
table { border-collapse: collapse; width: 100%; margin-top: 1rem; font-size: 0.85rem; }
th, td { border: 1px solid #ddd; padding: 0.4rem 0.6rem; text-align: left; vertical-align: top; }
th { background: #f6f8fa; }
td.status-detected { color: #cf222e; font-weight: bold; }
td.status-clean { color: #1a7f37; }
td.status-error, td.status-skipped { color: #9a6700; }
ul.rationale li { margin-bottom: 0.25rem; }
.downloads a { display: inline-block; margin-right: 1rem; }
"""


def render_html_report(scan_dir: pathlib.Path, metadata: EvasionScanMetadata) -> str:
    """Build CHIMERA's own normalized report page. Never raises: this is a
    read-only rendering of data that has already been validated when it was
    produced, so any interpolation here is presentational only."""
    score = metadata.score
    state_value = score.state.value if score else "incomplete"
    state_label = _STATE_LABELS.get(state_value, state_value)
    chimera_score_text = (
        f"{score.chimera_score:.2f} / 100"
        if score and score.chimera_score is not None
        else "Not available"
    )

    rationale_html = ""
    if score and score.rationale:
        items = "".join(f"<li>{html_lib.escape(r)}</li>" for r in score.rationale)
        rationale_html = f'<ul class="rationale">{items}</ul>'

    tool_rows = _tool_summary_rows(score.tool_scores if score else {})
    check_rows = _checks_table_rows(metadata.tool_results)

    native_report_link = ""
    native_path = scan_dir / "raw" / PRIMARY_TOOL_ID / "perdedor-native-report.html"
    if native_path.exists():
        rel = native_path.relative_to(scan_dir).as_posix()
        native_report_link = (
            f'<a href="{html_lib.escape(rel)}">PERDEDOR native report (unmodified)</a>'
        )

    sandbox = metadata.sandbox or {}

    return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>CHIMERA Sandbox Evasion Report</title>
<style>{_CSS}</style>
</head>
<body>
<header>
  <h1>CHIMERA Sandbox Evasion Report</h1>
  <p class="meta">
    Scan {html_lib.escape(metadata.id)} &middot;
    Sandbox {html_lib.escape(str(sandbox.get('display_name', sandbox.get('id', '-'))))}
    ({html_lib.escape(str(sandbox.get('platform', '-')))}) &middot;
    Profile {html_lib.escape(metadata.options.profile)}
  </p>
</header>

<section>
  <div class="score-card {html_lib.escape(state_value)}">
    <div class="score-num">{html_lib.escape(chimera_score_text)}</div>
    <div class="score-label">CHIMERA evasion score &mdash; {html_lib.escape(state_label)}</div>
  </div>
  {rationale_html}
</section>

<section>
  <h2>Tool-native results</h2>
  <p class="meta">
    Each tool's own, unweighted counts. Only {html_lib.escape(PRIMARY_TOOL_ID)} contributes a
    weighted score to the CHIMERA evasion score above; every other tool is corroborating
    evidence only and is never averaged in.
  </p>
  <table>
    <tr>
      <th>Tool</th><th>Version</th><th>Status</th><th>Clean/Applicable</th>
      <th>Detected</th><th>Errored</th><th>Skipped</th><th>Native weighted score</th>
    </tr>
    {tool_rows}
  </table>
</section>

<section>
  <h2>Normalized checks (all tools)</h2>
  <table>
    <tr>
      <th>Tool</th><th>Category</th><th>Status</th><th>Severity</th>
      <th>Check</th><th>Description</th><th>Evidence</th><th>Remediation</th>
    </tr>
    {check_rows}
  </table>
</section>

<section class="downloads">
  <h2>Downloads</h2>
  <a href="{html_lib.escape(RESULT_FILENAME)}">Normalized JSON</a>
  {native_report_link}
</section>
</body>
</html>
"""


def write_html_report(
    scan_dir: pathlib.Path, metadata: EvasionScanMetadata
) -> pathlib.Path:
    write_perdedor_native_report(scan_dir)
    html_text = render_html_report(scan_dir, metadata)
    path = scan_dir / REPORT_FILENAME
    path.write_text(html_text, encoding="utf-8")
    return path


__all__ = [
    "write_evasion_json",
    "write_perdedor_native_report",
    "render_html_report",
    "write_html_report",
]
