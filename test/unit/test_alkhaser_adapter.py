"""Tests for drakrun.evasion.verifiers.alkhaser.AlKhaserAdapter.run().

Covers the four distinct outcome states the adapter must always keep
separate (ToolStatus.unsupported / error / timeout / ok-with-findings never
collapse into one another), plus the argv/validation regression coverage in
test_alkhaser_adapter's sibling test_alkhaser_parsers.py.
"""

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from fake_guest_session import FakeGuestSession  # noqa: E402

from drakrun.evasion.constants import CheckStatus, ToolStatus  # noqa: E402
from drakrun.evasion.verifiers.alkhaser import AlKhaserAdapter  # noqa: E402
from drakrun.evasion.verifiers.base import VerifierTimeout  # noqa: E402


@pytest.fixture
def alkhaser_binary(tmp_path):
    binary = tmp_path / "al-khaser_x64.exe"
    binary.write_bytes(b"MZ-fake-pe-binary-for-testing")
    return binary


def test_unsupported_when_no_host_binary_configured(tmp_path):
    adapter = AlKhaserAdapter()
    session = FakeGuestSession()
    result = adapter.run(session, {}, tmp_path, deadline=__import__("time").time() + 60)

    assert result.status == ToolStatus.unsupported
    assert "host_binary_path" in result.error or "al-khaser_x64.exe" in result.error
    # Nothing should have been launched in the guest.
    assert session.run_calls == []


def test_error_on_invalid_options(tmp_path, alkhaser_binary):
    adapter = AlKhaserAdapter()
    session = FakeGuestSession()
    options = {
        "host_binary_path": str(alkhaser_binary),
        "checks": ["DEBUG", "NOT_A_REAL_CHECK"],
    }

    result = adapter.run(
        session, options, tmp_path, deadline=__import__("time").time() + 60
    )

    assert result.status == ToolStatus.error
    assert "NOT_A_REAL_CHECK" in result.error
    # Validation must fail before anything is launched in the guest.
    assert session.run_calls == []


def test_timeout_is_distinct_from_error(tmp_path, alkhaser_binary):
    adapter = AlKhaserAdapter()
    session = FakeGuestSession(raise_on_run=VerifierTimeout())
    options = {"host_binary_path": str(alkhaser_binary)}

    result = adapter.run(
        session, options, tmp_path, deadline=__import__("time").time() + 60
    )

    assert result.status == ToolStatus.timeout
    assert result.status != ToolStatus.error
    assert (
        "sleep" in result.error.lower()
        or "timed" in result.error.lower()
        or "budget" in result.error.lower()
    )


def test_error_on_guest_launch_failure(tmp_path, alkhaser_binary):
    adapter = AlKhaserAdapter()
    session = FakeGuestSession(raise_on_run=RuntimeError("injector write_file failed"))
    options = {"host_binary_path": str(alkhaser_binary)}

    result = adapter.run(
        session, options, tmp_path, deadline=__import__("time").time() + 60
    )

    assert result.status == ToolStatus.error
    assert "injector write_file failed" in result.error


def test_completed_run_with_findings(tmp_path, alkhaser_binary):
    """The full happy path: guest launch succeeds, log.txt is retrievable,
    and normalized checks come back with the right detected/clean states."""
    log_bytes = (
        b"[Mon Jan 01 00:00:00 2024] [*] TLS process attach callback  -> 0\n"
        b"[Mon Jan 01 00:00:00 2024] [*] TLS thread attach callback  -> 1\n"
    )
    session = FakeGuestSession(
        run_result=(0, b"", b""),
        files={
            r"C:\Users\Public\alkhaser\log.txt": log_bytes,
            r"C:\Users\Public\alkhaser\stdout.txt": b"stdout not needed when log.txt present",
        },
    )
    adapter = AlKhaserAdapter()
    options = {
        "host_binary_path": str(alkhaser_binary),
        "checks": ["TLS"],
        "sleep_seconds": 5,
    }

    result = adapter.run(
        session, options, tmp_path, deadline=__import__("time").time() + 60
    )

    assert result.status == ToolStatus.ok
    assert result.exit_code == 0
    assert len(result.checks) == 2
    by_id = {c.id: c for c in result.checks}
    assert (
        by_id["alkhaser.design_specific.tls_process_attach_callback"].status
        == CheckStatus.clean
    )
    assert (
        by_id["alkhaser.design_specific.tls_thread_attach_callback"].status
        == CheckStatus.detected
    )
    # Raw artifacts (log.txt, command.txt) must be preserved on disk, not just parsed.
    assert result.raw_artifacts
    for rel_path in result.raw_artifacts:
        assert (tmp_path / rel_path).exists()
    # The al-khaser binary was actually transferred into the guest.
    assert len(session.put_file_calls) == 1
    # --sleep was passed explicitly and stdin was redirected from NUL.
    launched_argv = session.run_calls[0][0]
    joined = " ".join(launched_argv)
    assert "--sleep 5" in joined
    assert "< NUL" in joined


def test_error_when_neither_log_nor_stdout_retrievable(tmp_path, alkhaser_binary):
    """If al-khaser ran (exit 0, as always) but produced nothing retrievable,
    that must be status=error, not a silently-empty ok result."""
    session = FakeGuestSession(run_result=(0, b"", b""), files={})
    adapter = AlKhaserAdapter()
    options = {"host_binary_path": str(alkhaser_binary)}

    result = adapter.run(
        session, options, tmp_path, deadline=__import__("time").time() + 60
    )

    assert result.status == ToolStatus.error
    assert result.checks == []
