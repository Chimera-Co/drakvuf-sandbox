"""Tests for drakrun.evasion.report.

Covers that the two required distinctions actually show up in the generated
artifacts:
  - report.html is CHIMERA's own normalized rendering, and clearly labels
    which tool contributed the CHIMERA score versus which are corroborating.
  - raw/perdedor/perdedor-native-report.html is PERDEDOR's own, unmodified
    renderer output over the raw report - a genuinely separate artifact, not
    inlined into report.html (which would be invalid nested HTML, since
    perdedor_common.report.render_html returns a full standalone document).
  - an incomplete scan (no usable score) renders "Not available" rather than
    inventing a number, and evasion.json always reflects exactly what
    EvasionScanMetadata carries - no silent transformation at write time.
"""

import json

from drakrun.evasion.constants import CheckStatus, Severity, ToolStatus
from drakrun.evasion.models import (
    EvasionScanMetadata,
    EvasionScanOptions,
    NormalizedCheck,
    ToolResult,
)
from drakrun.evasion.report import (
    render_html_report,
    write_evasion_json,
    write_html_report,
    write_perdedor_native_report,
)
from drakrun.evasion.scoring import compute_score
from drakrun.evasion.storage import build_artifacts_zip, list_scan_files

_RAW_PERDEDOR_REPORT = {
    "perdedor_version": "0.1.0",
    "platform": "windows",
    "hostname": "test-guest",
    "generated_at": "2024-01-01T00:00:00+00:00",
    "agent_metadata": {},
    "findings": [
        {
            "id": "windows.environment_artifact.smbios",
            "category": "environment_artifact",
            "platform": "windows",
            "name": "SMBIOS vendor",
            "description": "d",
            "status": "detected",
            "severity": "high",
            "evidence": "QEMU",
            "remediation": "Spoof SMBIOS vendor strings.",
            "error_detail": None,
        }
    ],
    "summary": {
        "total": 1,
        "clean": 0,
        "detected": 1,
        "errored": 0,
        "skipped": 0,
        "raw_score": "0/1",
        "weighted_score": 35.0,
    },
}


def _metadata(tool_results):
    score = compute_score(tool_results)
    return EvasionScanMetadata(
        id="11111111-1111-4111-8111-111111111111",
        status="finished",
        sandbox={
            "id": "default",
            "display_name": "Windows 10 -- Current",
            "platform": "windows",
        },
        options=EvasionScanOptions(
            sandbox_id="default", tools=["perdedor", "alkhaser"], profile="full"
        ),
        tool_results=tool_results,
        score=score,
    )


def test_write_evasion_json_roundtrips_metadata(tmp_path):
    perdedor_result = ToolResult(
        tool="perdedor",
        tool_version="0.1.0",
        status=ToolStatus.ok,
        checks=[
            NormalizedCheck(
                id="windows.environment_artifact.smbios",
                category="environment_artifact",
                name="SMBIOS vendor",
                description="d",
                status=CheckStatus.detected,
                severity=Severity.high,
                tool="perdedor",
                evidence="QEMU",
            )
        ],
    )
    metadata = _metadata([perdedor_result])

    path = write_evasion_json(tmp_path, metadata)
    written = json.loads(path.read_text(encoding="utf-8"))

    assert written["id"] == metadata.id
    assert written["score"]["chimera_score"] == 35.0
    assert written["tool_results"][0]["checks"][0]["evidence"] == "QEMU"


def test_perdedor_native_report_is_a_separate_unmodified_artifact(tmp_path):
    raw_dir = tmp_path / "raw" / "perdedor"
    raw_dir.mkdir(parents=True)
    (raw_dir / "windows-report.json").write_text(json.dumps(_RAW_PERDEDOR_REPORT))

    native_path = write_perdedor_native_report(tmp_path)

    assert native_path is not None
    assert native_path.name == "perdedor-native-report.html"
    text = native_path.read_text(encoding="utf-8")
    # PERDEDOR's own renderer produces a full standalone document.
    assert text.strip().startswith("<!doctype html>")
    assert "PERDEDOR" in text


def test_missing_raw_report_yields_no_native_artifact_not_an_error(tmp_path):
    # Nothing under raw/perdedor/ at all.
    assert write_perdedor_native_report(tmp_path) is None


def test_malformed_raw_report_yields_no_native_artifact_not_an_exception(tmp_path):
    raw_dir = tmp_path / "raw" / "perdedor"
    raw_dir.mkdir(parents=True)
    (raw_dir / "windows-report.json").write_text("{not valid json")

    assert write_perdedor_native_report(tmp_path) is None


def test_report_html_links_to_native_report_and_shows_real_score(tmp_path):
    raw_dir = tmp_path / "raw" / "perdedor"
    raw_dir.mkdir(parents=True)
    (raw_dir / "windows-report.json").write_text(json.dumps(_RAW_PERDEDOR_REPORT))

    perdedor_result = ToolResult(
        tool="perdedor",
        tool_version="0.1.0",
        status=ToolStatus.ok,
        checks=[
            NormalizedCheck(
                id="windows.environment_artifact.smbios",
                category="environment_artifact",
                name="SMBIOS vendor",
                description="d",
                status=CheckStatus.detected,
                severity=Severity.high,
                tool="perdedor",
                evidence="QEMU",
                remediation="Spoof SMBIOS vendor strings.",
            )
        ],
    )
    metadata = _metadata([perdedor_result])

    path = write_html_report(tmp_path, metadata)
    text = path.read_text(encoding="utf-8")

    assert "35.00 / 100" in text
    assert "QEMU" in text
    assert "Spoof SMBIOS vendor strings." in text
    assert "PERDEDOR native report (unmodified)" in text
    assert 'href="raw/perdedor/perdedor-native-report.html"' in text


def test_report_html_shows_not_available_for_incomplete_scan(tmp_path):
    """An unsupported/errored/timed-out primary tool must render as
    'Not available', never as a number - and never silently as 100."""
    perdedor_result = ToolResult(
        tool="perdedor", status=ToolStatus.unsupported, error="pwsh missing"
    )
    metadata = _metadata([perdedor_result])

    text = render_html_report(tmp_path, metadata)

    assert "Not available" in text
    assert "100.00 / 100" not in text
    assert "pwsh missing" in text


def test_report_html_separates_tool_native_from_chimera_score(tmp_path):
    perdedor_clean = ToolResult(
        tool="perdedor",
        status=ToolStatus.ok,
        checks=[
            NormalizedCheck(
                id="p1",
                category="timing",
                name="p1",
                description="d",
                status=CheckStatus.clean,
                severity=Severity.low,
                tool="perdedor",
            )
        ],
    )
    alkhaser_detected = ToolResult(
        tool="alkhaser",
        status=ToolStatus.ok,
        checks=[
            NormalizedCheck(
                id="a1",
                category="design_specific",
                name="a1",
                description="d",
                status=CheckStatus.detected,
                severity=Severity.critical,
                tool="alkhaser",
            )
        ],
    )
    metadata = _metadata([perdedor_clean, alkhaser_detected])

    text = render_html_report(tmp_path, metadata)

    # CHIMERA score must stay 100 (perdedor-only), unaffected by al-khaser's detection.
    assert "100.00 / 100" in text
    # al-khaser's own row must show it has no native weighted score.
    assert "no native scoring" in text


def test_build_artifacts_zip_excludes_normalized_json_and_report(tmp_path):
    (tmp_path / "raw" / "perdedor").mkdir(parents=True)
    (tmp_path / "raw" / "perdedor" / "windows-report.json").write_text("{}")
    (tmp_path / "evasion.json").write_text("{}")
    (tmp_path / "report.html").write_text("<html></html>")

    zip_path = build_artifacts_zip(tmp_path)

    import zipfile

    with zipfile.ZipFile(zip_path) as zf:
        names = zf.namelist()
    assert any("windows-report.json" in n for n in names)
    assert not any(n.endswith("evasion.json") for n in names)
    assert not any(n.endswith("report.html") for n in names)


def test_list_scan_files_returns_posix_relative_paths(tmp_path):
    (tmp_path / "raw" / "alkhaser").mkdir(parents=True)
    (tmp_path / "raw" / "alkhaser" / "log.txt").write_text("x")
    (tmp_path / "evasion.json").write_text("{}")

    files = list_scan_files(tmp_path)

    assert "evasion.json" in files
    assert "raw/alkhaser/log.txt" in files
