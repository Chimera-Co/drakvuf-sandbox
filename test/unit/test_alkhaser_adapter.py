"""Tests for drakrun.evasion.verifiers.alkhaser.AlKhaserAdapter.run().

Covers the four distinct outcome states the adapter must always keep
separate (ToolStatus.unsupported / error / timeout / ok-with-findings never
collapse into one another), plus the argv/validation regression coverage in
test_alkhaser_adapter's sibling test_alkhaser_parsers.py.
"""

import hashlib
import json
import pathlib
import sys
import time

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from fake_guest_session import FakeGuestSession  # noqa: E402

from drakrun.evasion.constants import CheckStatus, ToolStatus  # noqa: E402
from drakrun.evasion.guest_runner import (  # noqa: E402
    DRAKSHELL_MAX_CMDLINE_BYTES,
    InjectorReadError,
    encoded_cmdline_size,
)
from drakrun.evasion.verifiers.alkhaser import (  # noqa: E402
    _PROBE_ATTR_MARKER,
    _PROBE_EXISTS_MARKER,
    _PROBE_SIZE_MARKER,
    _READ_EXPECTED_MARKER,
    _READ_HASHMATCH_MARKER,
    _READ_TESTPATH_MARKER,
    READ_PROBE_CLASS_HASH_DIFFERS,
    READ_PROBE_CLASS_HASH_MATCHES,
    READ_PROBE_CLASS_INCONCLUSIVE,
    READ_PROBE_CLASS_MISSING,
    READ_PROBE_CLASS_UNOPENABLE,
    AlKhaserAdapter,
    _build_metadata_probe_argv,
    _build_read_probe_argv,
    _build_read_probe_script,
    _diagnose_uploaded_binary,
    _parse_metadata_probe_output,
    _parse_read_probe_output,
    _probe_guest_file_metadata,
    _probe_guest_file_read,
    _win32_error_from_hresult,
    build_argv,
    read_probe_script_guest_path,
)
from drakrun.evasion.verifiers.base import VerifierTimeout  # noqa: E402


@pytest.fixture
def alkhaser_binary(tmp_path):
    binary = tmp_path / "al-khaser_x64.exe"
    binary.write_bytes(b"MZ-fake-pe-binary-for-testing")
    return binary


@pytest.mark.parametrize("filename", ["log.txt", "stdout.txt"])
def test_oversized_report_is_error_even_with_other_valid_output(
    tmp_path, alkhaser_binary, monkeypatch, filename
):
    monkeypatch.setattr(
        "drakrun.evasion.verifiers.base.MAX_REPORT_BYTES", 256, raising=False
    )
    files = {
        r"C:\Users\Public\alkhaser\log.txt": b"[*] TLS process attach callback  -> 0\n",
        r"C:\Users\Public\alkhaser\stdout.txt": b"[*] TLS process attach callback  -> 0\n",
    }
    files["C:\\Users\\Public\\alkhaser\\" + filename] = b" " * 257
    session = FakeGuestSession(files=files)
    original_open = pathlib.Path.open

    def guarded_open(path, *args, **kwargs):
        mode = args[0] if args else kwargs.get("mode", "r")
        if (
            path.name == filename
            and path.exists()
            and path.stat().st_size > 256
            and "r" in mode
        ):
            pytest.fail("oversized report opened for reading")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(pathlib.Path, "open", guarded_open)
    result = AlKhaserAdapter().run(
        session,
        {"host_binary_path": str(alkhaser_binary), "checks": ["TLS"]},
        tmp_path,
        time.time() + 60,
    )
    assert result.status == ToolStatus.error
    assert "report too large" in result.error.lower()
    assert result.checks == []
    assert "raw/alkhaser/" + filename in result.raw_artifacts


def test_truncation_flag_survives_adapter(tmp_path, alkhaser_binary):
    from drakrun.evasion.verifiers.base import GuestCommandResult

    session = FakeGuestSession(
        run_result=GuestCommandResult(0, b"[output truncated]", b"", truncated=True),
        files={
            r"C:\Users\Public\alkhaser\log.txt": b"[*] TLS process attach callback  -> 0\n"
        },
    )
    result = AlKhaserAdapter().run(
        session,
        {"host_binary_path": str(alkhaser_binary), "checks": ["TLS"]},
        tmp_path,
        time.time() + 60,
    )
    assert result.status == ToolStatus.ok
    assert result.to_dict()["truncated"] is True


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
    # The al-khaser binary was actually transferred into the guest, exactly
    # once. The read/hash probe also uses put_file() to deliver its .ps1, so
    # select the binary rather than asserting a bare call count.
    binary_uploads = [c for c in session.put_file_calls if c[1] == GUEST_BINARY_PATH]
    assert len(binary_uploads) == 1
    # --sleep was passed explicitly and stdin was redirected from NUL. The
    # metadata-probe diagnostics also go through run(), so select the real
    # al-khaser launch rather than assuming it is the only run() call.
    (launched_argv,) = [
        argv for (argv, _t, _c) in session.run_calls if "--sleep" in " ".join(argv)
    ]
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


# Regression tests for the confirmed real-Xen quoting bug: build_argv() used
# to quote with POSIX shlex.quote(), which wraps any path containing a
# backslash in SINGLE quotes - a character cmd.exe assigns no meaning to at
# all. A real scan (05833a28-7c8f-44b6-94b3-4637cb420ac5) captured the exact
# broken command cmd.exe received:
#   cmd /c 'C:\Users\Public\alkhaser\al-khaser_x64.exe' --sleep 30 < NUL > 'C:\Users\Public\alkhaser\stdout.txt' 2>&1
# cmd.exe could not resolve the literally-apostrophe-wrapped filename, so
# al-khaser never launched (exit_code=1 in ~4s, not the 30+s a real
# --sleep 30 run takes), and neither stdout.txt nor log.txt was ever created
# at its real path. build_argv() now uses subprocess.list2cmdline() - the
# same Windows command-line quoting drakrun.evasion.guest_runner.GuestSession
# already uses - instead.


def test_build_argv_does_not_use_posix_single_quoting():
    argv = build_argv(
        None,
        30,
        r"C:\Users\Public\alkhaser\al-khaser_x64.exe",
        r"C:\Users\Public\alkhaser\stdout.txt",
    )

    assert argv[0] == "cmd"
    assert argv[1] == "/c"
    command_str = argv[2]
    # The literal bug: shlex.quote() wraps a backslash-containing path in
    # single quotes. No single quote must appear anywhere in the guest
    # command line cmd.exe actually receives.
    assert "'" not in command_str
    # Both the executable path and the redirection target must appear
    # exactly as real, unquoted Windows paths - not garbled by quoting.
    assert r"C:\Users\Public\alkhaser\al-khaser_x64.exe" in command_str
    assert r"C:\Users\Public\alkhaser\stdout.txt" in command_str


def test_build_argv_full_scan_command_for_real_paths():
    """Exact full-scan command construction for the real provisioned
    al-khaser v1.1.0 guest paths and a Full-profile (checks=None) --sleep 30
    run - the precise scenario that failed against real Xen."""
    guest_binary_path = r"C:\Users\Public\alkhaser\al-khaser_x64.exe"
    guest_stdout_path = r"C:\Users\Public\alkhaser\stdout.txt"

    argv = build_argv(None, 30, guest_binary_path, guest_stdout_path)

    assert argv == [
        "cmd",
        "/c",
        f"{guest_binary_path} --sleep 30 < NUL > {guest_stdout_path} 2>&1",
    ]


def test_build_argv_with_checks_still_avoids_single_quoting():
    """The Custom-profile path (explicit --check flags) must be just as
    immune to the quoting bug as the Full-profile path above."""
    argv = build_argv(
        ["DEBUG", "TLS"],
        10,
        r"C:\Users\Public\alkhaser\al-khaser_x64.exe",
        r"C:\Users\Public\alkhaser\stdout.txt",
    )

    command_str = argv[2]
    assert "'" not in command_str
    assert command_str == (
        r"C:\Users\Public\alkhaser\al-khaser_x64.exe --check DEBUG --check TLS "
        r"--sleep 10 < NUL > C:\Users\Public\alkhaser\stdout.txt 2>&1"
    )


def test_build_argv_quotes_paths_containing_spaces_for_cmd_exe():
    """subprocess.list2cmdline() only wraps a token in double quotes when it
    actually needs it (space, empty string, or embedded quote) - the plain
    backslash-only paths this adapter normally uses never need quoting, but
    a path containing a space (e.g. a "Program Files"-style install) must
    still come out correctly double-quoted for cmd.exe, while the shell
    redirection operators around it stay bare, unquoted tokens."""
    guest_binary_path = r"C:\Program Files\alkhaser\al-khaser_x64.exe"
    guest_stdout_path = r"C:\Program Files\alkhaser\stdout.txt"

    argv = build_argv(None, 30, guest_binary_path, guest_stdout_path)

    assert argv == [
        "cmd",
        "/c",
        f'"{guest_binary_path}" --sleep 30 < NUL > "{guest_stdout_path}" 2>&1',
    ]
    command_str = argv[2]
    # cmd.exe quoting (double quotes), never the broken POSIX single-quote
    # form the real bug produced.
    assert "'" not in command_str
    assert f'"{guest_binary_path}"' in command_str
    assert f'"{guest_stdout_path}"' in command_str
    # The redirection operators themselves are shell syntax, not path
    # tokens - they must remain bare and unquoted either side of them.
    assert " < NUL " in command_str
    assert command_str.endswith(" 2>&1")


def test_build_argv_preserves_structure_stdin_and_stderr_redirection():
    """--sleep behavior, stdin-from-NUL (getchar() workaround), and 2>&1
    stderr merging must all survive the quoting change unchanged."""
    argv = build_argv(
        None,
        45,
        r"C:\Users\Public\alkhaser\al-khaser_x64.exe",
        r"C:\Users\Public\alkhaser\stdout.txt",
    )
    command_str = argv[2]

    assert "--sleep 45" in command_str
    assert "< NUL" in command_str
    assert command_str.endswith("2>&1")
    # One stdout redirection ("> path") plus the "2>&1" stderr merge - two
    # ">" characters total, not garbled by quoting into anything else.


# Regression tests for the read-only upload/tampering diagnostic added to
# investigate the confirmed combined-scan al-khaser launch failure
# ("The system cannot execute the specified program.", scan
# d21be3bc-f39f-42d4-a34f-0642149fd6f4): _diagnose_uploaded_binary() reads
# the just-uploaded guest binary back via GuestSession.get_file() and hashes
# it against the host original, so a future real-Xen run can show whether
# the bytes were ever wrong (upload/write corruption) or changed between
# upload and launch (something else acting on the file in between). It must
# never raise and never affect ToolStatus - every failure mode is captured
# as a diagnostic field instead.

GUEST_BINARY_PATH = r"C:\Users\Public\alkhaser\al-khaser_x64.exe"
ALKHASER_GUEST_DIR = r"C:\Users\Public\alkhaser"


def test_diagnose_uploaded_binary_matches_when_guest_bytes_correct(
    tmp_path, alkhaser_binary
):
    session = FakeGuestSession(files={GUEST_BINARY_PATH: alkhaser_binary.read_bytes()})

    diagnostic = _diagnose_uploaded_binary(
        session, str(alkhaser_binary), GUEST_BINARY_PATH, tmp_path, "post_upload"
    )

    expected_sha256 = hashlib.sha256(alkhaser_binary.read_bytes()).hexdigest()
    assert diagnostic["guest_exists"] is True
    assert diagnostic["host_sha256"] == expected_sha256
    assert diagnostic["guest_sha256"] == expected_sha256
    assert (
        diagnostic["host_size"]
        == diagnostic["guest_size"]
        == len(alkhaser_binary.read_bytes())
    )
    assert "host_error" not in diagnostic
    assert "guest_error" not in diagnostic

    # The diagnostic JSON artifact must be persisted, with matching content.
    diag_path = tmp_path / "diag_post_upload.json"
    assert diag_path.exists()
    on_disk = json.loads(diag_path.read_text(encoding="utf-8"))
    assert on_disk["guest_sha256"] == expected_sha256
    assert on_disk["label"] == "post_upload"


def test_diagnose_uploaded_binary_detects_corrupted_guest_bytes(
    tmp_path, alkhaser_binary
):
    """The guest file exists but its bytes differ from the host original -
    exactly the write-corruption hypothesis this diagnostic exists to
    distinguish from post-upload tampering."""
    session = FakeGuestSession(files={GUEST_BINARY_PATH: b"truncated-or-corrupted"})

    diagnostic = _diagnose_uploaded_binary(
        session, str(alkhaser_binary), GUEST_BINARY_PATH, tmp_path, "post_upload"
    )

    assert diagnostic["guest_exists"] is True
    assert diagnostic["guest_sha256"] != diagnostic["host_sha256"]
    assert diagnostic["guest_size"] != diagnostic["host_size"]


def test_diagnose_uploaded_binary_records_guest_missing_without_raising(
    tmp_path, alkhaser_binary
):
    """If the guest file cannot be read back at all (e.g. it was deleted or
    never existed), the diagnostic must record that fact and must not raise
    - a diagnostic-retrieval failure must never itself mask or replace the
    real launch failure being investigated."""
    session = FakeGuestSession(files={})  # nothing registered for the guest path

    diagnostic = _diagnose_uploaded_binary(
        session, str(alkhaser_binary), GUEST_BINARY_PATH, tmp_path, "pre_run"
    )

    assert diagnostic["guest_exists"] is False
    assert "guest_error" in diagnostic
    assert "guest_sha256" not in diagnostic


def test_diagnose_uploaded_binary_records_host_read_error_without_raising(tmp_path):
    session = FakeGuestSession(files={GUEST_BINARY_PATH: b"whatever"})
    missing_host_path = str(tmp_path / "does-not-exist.exe")

    diagnostic = _diagnose_uploaded_binary(
        session, missing_host_path, GUEST_BINARY_PATH, tmp_path, "post_upload"
    )

    assert "host_error" in diagnostic
    assert "host_sha256" not in diagnostic
    # The guest-side half of the diagnostic must still be attempted
    # independently of the host-side failure.
    assert diagnostic["guest_exists"] is True


def test_diagnose_uploaded_binary_does_not_leave_readback_copy_on_disk(
    tmp_path, alkhaser_binary
):
    """Only the hash/size diagnostic JSON is kept - al-khaser is not
    redistributed by this project, so the retrieved binary itself must be
    cleaned up immediately after hashing."""
    session = FakeGuestSession(files={GUEST_BINARY_PATH: alkhaser_binary.read_bytes()})

    _diagnose_uploaded_binary(
        session, str(alkhaser_binary), GUEST_BINARY_PATH, tmp_path, "post_upload"
    )

    leftover_readback_copies = list(tmp_path.glob("_diag_readback_*"))
    assert leftover_readback_copies == []
    assert (tmp_path / "diag_post_upload.json").exists()


def test_run_captures_diagnostic_twice_without_affecting_result(
    tmp_path, alkhaser_binary
):
    """The full happy path (mirrors test_completed_run_with_findings) must
    still produce two diagnostic snapshots - one immediately after
    put_file(), one immediately before run() - without changing the
    adapter's actual status/checks/parser output in any way."""
    log_bytes = b"[Mon Jan 01 00:00:00 2024] [*] TLS process attach callback  -> 0\n"
    session = FakeGuestSession(
        run_result=(0, b"", b""),
        files={
            r"C:\Users\Public\alkhaser\log.txt": log_bytes,
            r"C:\Users\Public\alkhaser\stdout.txt": b"unused",
        },
    )
    adapter = AlKhaserAdapter()
    options = {"host_binary_path": str(alkhaser_binary), "checks": ["TLS"]}

    result = adapter.run(session, options, tmp_path, deadline=time.time() + 60)

    assert result.status == ToolStatus.ok
    assert len(result.checks) == 2

    raw_dir = tmp_path / "raw" / "alkhaser"
    post_upload = json.loads((raw_dir / "diag_post_upload.json").read_text())
    pre_run = json.loads((raw_dir / "diag_pre_run.json").read_text())
    assert post_upload["guest_exists"] is True
    assert pre_run["guest_exists"] is True
    # Both diagnostics were retrieved via GuestSession.get_file() (not a
    # guest-side shell command), and both must have happened strictly
    # before al-khaser was launched.
    assert session.get_file_calls[0][0] == GUEST_BINARY_PATH
    assert session.get_file_calls[1][0] == GUEST_BINARY_PATH
    # Exactly one real al-khaser launch; the metadata probes also use run().
    launches = [
        argv for (argv, _t, _c) in session.run_calls if "--sleep" in " ".join(argv)
    ]
    assert len(launches) == 1
    assert str((raw_dir / "diag_post_upload.json").relative_to(tmp_path)) in (
        result.raw_artifacts
    )
    assert str((raw_dir / "diag_pre_run.json").relative_to(tmp_path)) in (
        result.raw_artifacts
    )


def test_run_diagnostic_can_detect_drift_between_upload_and_pre_run(
    tmp_path, alkhaser_binary
):
    """Proves the two-snapshot design actually distinguishes upload
    corruption from post-upload tampering: a session whose guest copy of the
    binary changes between the two diagnostic calls must produce two
    diag_*.json files with DIFFERENT guest_sha256 values, even though
    put_file() only ran once."""

    class DriftingGuestSession(FakeGuestSession):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._alkhaser_get_file_count = 0

        def get_file(self, remote_path, local_path):
            if remote_path == GUEST_BINARY_PATH:
                self._alkhaser_get_file_count += 1
                if self._alkhaser_get_file_count >= 2:
                    # Simulate something having altered the guest file
                    # between the post-upload and pre-run snapshots.
                    pathlib.Path(local_path).parent.mkdir(parents=True, exist_ok=True)
                    pathlib.Path(local_path).write_bytes(b"tampered-bytes")
                    return
            super().get_file(remote_path, local_path)

    session = DriftingGuestSession(
        run_result=(0, b"", b""),
        files={
            GUEST_BINARY_PATH: alkhaser_binary.read_bytes(),
            r"C:\Users\Public\alkhaser\stdout.txt": b"unused",
        },
    )
    adapter = AlKhaserAdapter()
    options = {"host_binary_path": str(alkhaser_binary)}

    adapter.run(session, options, tmp_path, deadline=time.time() + 60)

    raw_dir = tmp_path / "raw" / "alkhaser"
    post_upload = json.loads((raw_dir / "diag_post_upload.json").read_text())
    pre_run = json.loads((raw_dir / "diag_pre_run.json").read_text())
    assert (
        post_upload["guest_sha256"]
        == hashlib.sha256(alkhaser_binary.read_bytes()).hexdigest()
    )
    assert pre_run["guest_sha256"] == hashlib.sha256(b"tampered-bytes").hexdigest()
    assert post_upload["guest_sha256"] != pre_run["guest_sha256"]


# Regression tests for the guest-side metadata probe. The existing
# Injector.read_file() diagnostic above reported guest_exists=false at BOTH
# checkpoints of scan e9448742-194d-4913-9acf-5a29d36d11cc, with DRAKVUF's
# single "Couldn't open guest file" string - which cannot distinguish "the
# file is not in the namespace" from "the file is there but cannot be opened
# right now", because readfile's CreateFileW(GENERIC_READ, OPEN_EXISTING)
# opens the data stream and DRAKVUF never surfaces the underlying
# GetLastError(). The probe asks Windows itself over the SAME guest-side
# path used to launch al-khaser (drakshell -> cmd.exe), using metadata-only
# lookups (if exist + FOR %~z/%~a) that never open the data stream.

PROBE_STDOUT_PRESENT = (
    b"CHIMERA_PROBE_EXISTS:1\r\n"
    b"CHIMERA_PROBE_SIZE:280576\r\n"
    b"CHIMERA_PROBE_ATTR:--a------\r\n"
)
# A missing file yields an empty %~zI/%~aI expansion, not a zero.
PROBE_STDOUT_MISSING = (
    b"CHIMERA_PROBE_EXISTS:0\r\nCHIMERA_PROBE_SIZE:\r\nCHIMERA_PROBE_ATTR:\r\n"
)


def _is_read_probe_invocation(argv):
    """Recognise the user-mode read probe's `-File <script>.ps1` invocation.

    The probe is no longer an inline -EncodedCommand payload: real-Xen scan
    34ae2d08-dcf0-471b-88c8-5bead0cf40eb showed that form produced a
    7792-byte UTF-16LE command line against drakshell's 2048-byte ceiling
    and was rejected host-side without ever reaching Windows. The script is
    now uploaded and run by path."""
    return (
        len(argv) >= 2
        and argv[0] == "powershell.exe"
        and "-File" in argv
        and argv[-1].endswith(".ps1")
        and "__chimera_read_probe_" in argv[-1]
    )


def _read_probe_stdout_ok(sha256, length=280576):
    """Exactly what the guest emits when the file opens and hashes cleanly."""
    return (
        "CHIMERA_READ_TESTPATH:True\r\n"
        f"CHIMERA_READ_LENGTH:{length}\r\n"
        "CHIMERA_READ_ATTRS:Archive\r\n"
        "CHIMERA_READ_LASTWRITE:2026-09-21T18:00:00.0000000Z\r\n"
        "CHIMERA_READ_OPEN:OK\r\n"
        f"CHIMERA_READ_BYTES:{length}\r\n"
        f"CHIMERA_READ_SHA256:{sha256}\r\n"
    ).encode()


# The file is in the namespace and Get-Item can stat it, but the data stream
# will not open. -2147024891 == 0x80070005: FACILITY_WIN32, low word 5 ==
# ERROR_ACCESS_DENIED - the same numbering space as the injector's own
# ErrorCode, which is what makes the two directly comparable.
READ_STDOUT_ACCESS_DENIED = (
    b"CHIMERA_READ_TESTPATH:True\r\n"
    b"CHIMERA_READ_LENGTH:280576\r\n"
    b"CHIMERA_READ_ATTRS:Archive\r\n"
    b"CHIMERA_READ_LASTWRITE:2026-09-21T18:00:00.0000000Z\r\n"
    b"CHIMERA_READ_OPEN:FAIL\r\n"
    b"CHIMERA_READ_EXCTYPE:System.UnauthorizedAccessException\r\n"
    b"CHIMERA_READ_HRESULT:-2147024891\r\n"
    b"CHIMERA_READ_EXCMSG:Access to the path is denied.\r\n"
)

# 0x80070020 == ERROR_SHARING_VIOLATION (32).
READ_STDOUT_SHARING_VIOLATION = (
    b"CHIMERA_READ_TESTPATH:True\r\n"
    b"CHIMERA_READ_LENGTH:280576\r\n"
    b"CHIMERA_READ_OPEN:FAIL\r\n"
    b"CHIMERA_READ_EXCTYPE:System.IO.IOException\r\n"
    b"CHIMERA_READ_HRESULT:-2147024864\r\n"
    b"CHIMERA_READ_EXCMSG:The process cannot access the file.\r\n"
)

READ_STDOUT_NOT_FOUND = (
    b"CHIMERA_READ_TESTPATH:False\r\n"
    b"CHIMERA_READ_STATERROR:System.Management.Automation.ItemNotFoundException "
    b"Cannot find path.\r\n"
    b"CHIMERA_READ_OPEN:FAIL\r\n"
    b"CHIMERA_READ_EXCTYPE:System.IO.FileNotFoundException\r\n"
    b"CHIMERA_READ_HRESULT:-2147024894\r\n"
    b"CHIMERA_READ_EXCMSG:Could not find file.\r\n"
)


class ProbeScriptedGuestSession(FakeGuestSession):
    """FakeGuestSession that answers the metadata probe and the PowerShell
    user-mode read probe with scripted marker output (or a scripted
    exception), while leaving every other run() call - notably al-khaser's
    real launch - on the normal FakeGuestSession path."""

    def __init__(
        self,
        *args,
        probe_stdout=PROBE_STDOUT_PRESENT,
        probe_exit_code=0,
        probe_error=None,
        read_probe_stdout=None,
        read_probe_exit_code=0,
        read_probe_error=None,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.probe_stdout = probe_stdout
        self.probe_exit_code = probe_exit_code
        self.probe_error = probe_error
        self.probe_runs = []
        self.read_probe_stdout = read_probe_stdout
        self.read_probe_exit_code = read_probe_exit_code
        self.read_probe_error = read_probe_error
        self.read_probe_runs = []

    def run(self, argv, timeout, cwd=None):
        if len(argv) == 3 and _PROBE_EXISTS_MARKER in argv[2]:
            self.probe_runs.append((argv, timeout, cwd))
            self.run_calls.append((argv, timeout, cwd))
            if self.probe_error is not None:
                raise self.probe_error
            return (self.probe_exit_code, self.probe_stdout, b"")
        if _is_read_probe_invocation(argv):
            self.read_probe_runs.append((argv, timeout, cwd))
            self.run_calls.append((argv, timeout, cwd))
            if self.read_probe_error is not None:
                raise self.read_probe_error
            return (self.read_probe_exit_code, self.read_probe_stdout or b"", b"")
        return super().run(argv, timeout, cwd)


def test_build_metadata_probe_argv_is_a_self_contained_cmd_c_script():
    """The argv must be exactly ["cmd", "/c", <script>] so that, when run
    with cwd, GuestSession._build_final_argv() takes its splice branch and
    forwards the script to drakshell as one untouched str. Any other shape
    would be re-quoted by mslex.join(), which backslash-escapes the inner
    quotes into a form cmd.exe does not understand."""
    argv = _build_metadata_probe_argv(GUEST_BINARY_PATH)

    assert len(argv) == 3
    assert argv[0] == "cmd"
    assert argv[1] == "/c"
    script = argv[2]
    assert "if exist" in script
    assert "%~zI" in script and "%~aJ" in script
    assert f'"{GUEST_BINARY_PATH}"' in script
    # POSIX single-quoting is the exact bug that broke a previous real scan.
    assert "'" not in script
    # Metadata-only: nothing here opens or executes the target file.
    assert "type " not in script.lower()
    assert "--sleep" not in script


def test_build_metadata_probe_argv_does_not_let_else_swallow_the_size_lookup():
    """Regression test for the precedence defect proven by real-Xen scan
    a1e7c574-cbe1-4dfc-8692-d8c0875c9b06.

    The old script was
        if exist X (echo EXISTS:1) else (echo EXISTS:0) & for ... do (...)
    and cmd.exe binds a trailing `& <cmd>` to the ELSE branch - so with the
    file PRESENT the FOR never ran, and the Windows-reported size was never
    captured. Guarding that specific shape: the IF/ELSE must be last, with
    nothing chained after it."""
    script = _build_metadata_probe_argv(GUEST_BINARY_PATH)[2]

    else_index = script.lower().index(" else ")
    # Nothing may be chained after the IF/ELSE - that trailing `&` is the bug.
    assert "&" not in script[else_index:]
    # ...and both size and attribute lookups precede it, so neither can be
    # swallowed by a branch.
    assert script.index(_PROBE_SIZE_MARKER) < else_index
    assert script.index(_PROBE_ATTR_MARKER) < else_index


def test_build_metadata_probe_argv_uses_distinct_for_variables():
    """The two FOR statements must not share a variable letter. cmd.exe may
    treat a FOR's DO body as extending across `&` (nesting the second FOR
    inside the first); distinct letters make the script produce the same
    output under either reading instead of shadowing %I."""
    script = _build_metadata_probe_argv(GUEST_BINARY_PATH)[2]

    assert "for %I in" in script
    assert "for %J in" in script
    assert script.count("for %I in") == 1
    assert script.count("for %J in") == 1
    # Echo suppression, so a nested reading cannot spray command text into
    # the marker stream.
    assert script.startswith("@echo off")


def test_parse_metadata_probe_output_file_exists_with_expected_size():
    parsed = _parse_metadata_probe_output(PROBE_STDOUT_PRESENT.decode())

    assert parsed["exists"] is True
    assert parsed["reported_size"] == 280576
    assert parsed["attributes"] == "--a------"


def test_parse_metadata_probe_output_file_missing():
    parsed = _parse_metadata_probe_output(PROBE_STDOUT_MISSING.decode())

    assert parsed["exists"] is False
    # Empty %~zI must NOT be misread as a real zero-byte file.
    assert parsed["reported_size"] is None
    assert parsed["attributes"] is None


def test_parse_metadata_probe_output_garbled_output_is_inconclusive_not_missing():
    """An empty or unparseable probe result must stay None, never collapse
    into a confident "file is missing" - distinguishing those two is the
    entire reason this probe exists."""
    for text in ("", "The system cannot find the path specified.", "garbage"):
        parsed = _parse_metadata_probe_output(text)
        assert parsed["exists"] is None
        assert parsed["reported_size"] is None
        assert parsed["attributes"] is None


def test_probe_guest_file_metadata_records_exists_and_size(tmp_path):
    session = ProbeScriptedGuestSession(probe_stdout=PROBE_STDOUT_PRESENT)

    probe = _probe_guest_file_metadata(
        session, GUEST_BINARY_PATH, ALKHASER_GUEST_DIR, tmp_path, "post_upload"
    )

    assert probe["checkpoint"] == "post_upload"
    assert probe["exists"] is True
    assert probe["reported_size"] == 280576
    assert probe["exit_code"] == 0
    assert "probe_error" not in probe
    assert probe["timestamp"].endswith("Z")
    # Raw evidence preserved verbatim, not just the parsed view.
    assert _PROBE_SIZE_MARKER in probe["stdout"]

    on_disk = json.loads((tmp_path / "probe_post_upload.json").read_text())
    assert on_disk["exists"] is True
    assert on_disk["reported_size"] == 280576
    assert on_disk["checkpoint"] == "post_upload"


def test_probe_guest_file_metadata_records_missing_file(tmp_path):
    session = ProbeScriptedGuestSession(probe_stdout=PROBE_STDOUT_MISSING)

    probe = _probe_guest_file_metadata(
        session, GUEST_BINARY_PATH, ALKHASER_GUEST_DIR, tmp_path, "pre_run"
    )

    assert probe["checkpoint"] == "pre_run"
    assert probe["exists"] is False
    assert probe["reported_size"] is None
    assert json.loads((tmp_path / "probe_pre_run.json").read_text())["exists"] is False


def test_probe_guest_file_metadata_records_command_failure_without_raising(tmp_path):
    """A probe that cannot run at all must be recorded as an error and must
    never raise - the verifier's own control flow depends on it."""
    session = ProbeScriptedGuestSession(
        probe_error=RuntimeError("Guest session is no longer usable: desync")
    )

    probe = _probe_guest_file_metadata(
        session, GUEST_BINARY_PATH, ALKHASER_GUEST_DIR, tmp_path, "post_upload"
    )

    assert "desync" in probe["probe_error"]
    assert probe["exists"] is None
    assert probe["reported_size"] is None
    on_disk = json.loads((tmp_path / "probe_post_upload.json").read_text())
    assert "desync" in on_disk["probe_error"]


def test_probe_guest_file_metadata_passes_cwd_so_script_is_spliced_verbatim(tmp_path):
    """cwd MUST be passed: it is what makes _build_final_argv() splice the
    script through as a plain str instead of mslex-quoting the list."""
    session = ProbeScriptedGuestSession()

    _probe_guest_file_metadata(
        session, GUEST_BINARY_PATH, ALKHASER_GUEST_DIR, tmp_path, "post_upload"
    )

    _argv, _timeout, cwd = session.probe_runs[0]
    assert cwd == ALKHASER_GUEST_DIR


def test_run_captures_metadata_probe_at_both_checkpoints(tmp_path, alkhaser_binary):
    """Both checkpoints must be captured, in order, strictly before the real
    al-khaser launch - and without disturbing the adapter's own result."""
    log_bytes = b"[Mon Jan 01 00:00:00 2024] [*] TLS process attach callback  -> 0\n"
    session = ProbeScriptedGuestSession(
        run_result=(0, b"", b""),
        files={
            r"C:\Users\Public\alkhaser\log.txt": log_bytes,
            r"C:\Users\Public\alkhaser\stdout.txt": b"unused",
        },
    )
    adapter = AlKhaserAdapter()
    options = {"host_binary_path": str(alkhaser_binary), "checks": ["TLS"]}

    result = adapter.run(session, options, tmp_path, deadline=time.time() + 60)

    assert result.status == ToolStatus.ok
    assert len(result.checks) == 2

    raw_dir = tmp_path / "raw" / "alkhaser"
    post_upload = json.loads((raw_dir / "probe_post_upload.json").read_text())
    pre_run = json.loads((raw_dir / "probe_pre_run.json").read_text())
    assert post_upload["checkpoint"] == "post_upload"
    assert pre_run["checkpoint"] == "pre_run"
    assert post_upload["exists"] is True and pre_run["exists"] is True
    assert post_upload["reported_size"] == pre_run["reported_size"] == 280576

    # Exactly two metadata probes, both before the single al-khaser launch.
    assert len(session.probe_runs) == 2
    launched = [argv for (argv, _t, _c) in session.run_calls]
    assert _PROBE_EXISTS_MARKER in launched[0][2]
    assert _PROBE_EXISTS_MARKER in launched[-2][2]
    assert "--sleep" in launched[-1][2]

    for name in ("probe_post_upload.json", "probe_pre_run.json"):
        assert str((raw_dir / name).relative_to(tmp_path)) in result.raw_artifacts


def test_run_probe_failure_does_not_alter_verifier_result(tmp_path, alkhaser_binary):
    """If the probe itself fails, al-khaser must still run and report its own
    real outcome - the verifier must never fail merely because a diagnostic
    failed."""
    log_bytes = b"[Mon Jan 01 00:00:00 2024] [*] TLS process attach callback  -> 0\n"
    session = ProbeScriptedGuestSession(
        run_result=(0, b"", b""),
        files={
            r"C:\Users\Public\alkhaser\log.txt": log_bytes,
            r"C:\Users\Public\alkhaser\stdout.txt": b"unused",
        },
        probe_error=RuntimeError("probe blew up"),
    )
    adapter = AlKhaserAdapter()
    options = {"host_binary_path": str(alkhaser_binary), "checks": ["TLS"]}

    result = adapter.run(session, options, tmp_path, deadline=time.time() + 60)

    assert result.status == ToolStatus.ok
    assert result.error is None
    assert len(result.checks) == 2
    # al-khaser itself still launched despite both probes failing.
    assert any("--sleep" in argv[2] for (argv, _t, _c) in session.run_calls)

    raw_dir = tmp_path / "raw" / "alkhaser"
    for name in ("probe_post_upload.json", "probe_pre_run.json"):
        assert (
            "probe blew up" in json.loads((raw_dir / name).read_text())["probe_error"]
        )


def test_run_retains_injector_readfile_diagnostics_alongside_the_probe(
    tmp_path, alkhaser_binary
):
    """The probe is additive: the pre-existing Injector.read_file() based
    diag_*.json diagnostics must still be produced, unchanged."""
    log_bytes = b"[Mon Jan 01 00:00:00 2024] [*] TLS process attach callback  -> 0\n"
    session = ProbeScriptedGuestSession(
        run_result=(0, b"", b""),
        files={
            r"C:\Users\Public\alkhaser\log.txt": log_bytes,
            r"C:\Users\Public\alkhaser\stdout.txt": b"unused",
        },
    )
    adapter = AlKhaserAdapter()
    options = {"host_binary_path": str(alkhaser_binary), "checks": ["TLS"]}

    result = adapter.run(session, options, tmp_path, deadline=time.time() + 60)

    raw_dir = tmp_path / "raw" / "alkhaser"
    expected_host_sha256 = hashlib.sha256(alkhaser_binary.read_bytes()).hexdigest()
    for name in ("diag_post_upload.json", "diag_pre_run.json"):
        diag = json.loads((raw_dir / name).read_text())
        # Unchanged read_file()-based schema: host/guest hash comparison.
        assert diag["host_sha256"] == expected_host_sha256
        assert diag["guest_sha256"] == expected_host_sha256
        assert diag["guest_exists"] is True
        assert str((raw_dir / name).relative_to(tmp_path)) in result.raw_artifacts

    # ...and both diagnostics coexist for both checkpoints.
    assert (raw_dir / "probe_post_upload.json").exists()
    assert (raw_dir / "probe_pre_run.json").exists()
    assert _PROBE_ATTR_MARKER  # marker constants are the shared parse contract


# ==========================================================================
# Windows user-mode read/hash probe.
#
# The metadata probe above answers "is the file in the namespace, and what
# size does Windows report?" but by construction never opens the data
# stream. The injector diagnostic opens the data stream, but from DRAKVUF's
# injected context. Neither answers the question that actually matters for
# scan a1e7c574-cbe1-4dfc-8692-d8c0875c9b06 - "can an ORDINARY Windows
# user-mode process open and read this executable?" - which is what this
# probe adds, from a plain powershell.exe started by drakshell: the same
# mechanism that starts al-khaser itself.
# ==========================================================================


def test_build_read_probe_argv_runs_an_uploaded_script_by_path():
    """The probe is invoked as `-File <uploaded .ps1>`, never as an inline
    -EncodedCommand payload."""
    script_path = read_probe_script_guest_path(ALKHASER_GUEST_DIR, "post_upload")
    argv = _build_read_probe_argv(script_path)

    assert argv[0] == "powershell.exe"
    assert "-EncodedCommand" not in argv
    assert "-NoProfile" in argv
    # Windows 10 client default policy is Restricted, which refuses to run a
    # .ps1 from disk at all - without this the probe cannot execute.
    assert argv[argv.index("-ExecutionPolicy") + 1] == "Bypass"
    assert argv[argv.index("-File") + 1] == script_path
    assert argv[-1] == script_path
    # No token needs quoting, so mslex cannot mangle anything.
    assert not any(" " in token or '"' in token or "'" in token for token in argv)


def test_read_probe_invocation_is_comfortably_under_the_drakshell_limit():
    """Regression test for real-Xen scan
    34ae2d08-dcf0-471b-88c8-5bead0cf40eb, where the probe was an inline
    -EncodedCommand payload of 7792 UTF-16LE bytes against drakshell's
    2048-byte ceiling. It was rejected on the host and never reached
    Windows, and because GuestSession poisoned itself on that rejection the
    entire rest of the scan was skipped.

    Measured through encoded_cmdline_size(), i.e. the same mslex-join ->
    UTF-16LE -> +2 computation drakshell itself performs - not an
    approximation of it."""
    for checkpoint in ("post_upload", "pre_run"):
        script_path = read_probe_script_guest_path(ALKHASER_GUEST_DIR, checkpoint)
        argv = _build_read_probe_argv(script_path)
        size = encoded_cmdline_size(argv)

        assert size <= DRAKSHELL_MAX_CMDLINE_BYTES, (checkpoint, size)
        # "Comfortably" below, not merely passing: the invocation must not
        # grow with the diagnostic, so demand a large margin rather than a
        # single spare byte.
        assert size < DRAKSHELL_MAX_CMDLINE_BYTES // 2, (checkpoint, size)

    # ...and the script body itself, which is what actually grew last time,
    # is NOT on the command line at all: it can be far larger than the limit
    # without affecting the invocation.
    body = _build_read_probe_script(GUEST_BINARY_PATH, "a" * 64)
    assert len(body.encode("utf-16le")) > DRAKSHELL_MAX_CMDLINE_BYTES
    assert body not in " ".join(_build_read_probe_argv(script_path))


def test_read_probe_script_path_is_per_checkpoint_and_scoped_to_alkhaser_dir():
    """One path per checkpoint: the injector's writefile opens with
    CREATE_NEW, so re-uploading a shared name for the second checkpoint
    would fail outright."""
    post = read_probe_script_guest_path(ALKHASER_GUEST_DIR, "post_upload")
    pre = read_probe_script_guest_path(ALKHASER_GUEST_DIR, "pre_run")

    assert post != pre
    assert post.startswith(ALKHASER_GUEST_DIR + "\\")
    assert pre.startswith(ALKHASER_GUEST_DIR + "\\")
    assert post.endswith(".ps1") and pre.endswith(".ps1")
    # Never collides with al-khaser's own files in that directory.
    for path in (post, pre):
        assert not path.endswith("log.txt")
        assert not path.endswith("stdout.txt")
        assert "al-khaser_x64.exe" not in path


def test_read_probe_script_embeds_the_expected_host_hash_for_in_guest_comparison():
    expected = "0cd8a40ff7ceef9c1368446d6ead91549681e88fdfa0f9f5a63c03fe38420baf"
    body = _build_read_probe_script(GUEST_BINARY_PATH, expected)

    assert f"$expected = '{expected}'" in body
    assert _READ_HASHMATCH_MARKER in body
    assert _READ_EXPECTED_MARKER in body
    # Unknown host hash must not emit a bogus comparison.
    unknown = _build_read_probe_script(GUEST_BINARY_PATH, None)
    assert "$expected = ''" in unknown


def test_read_probe_script_is_crlf_terminated_and_exits_zero():
    """A .ps1 is consumed by Windows PowerShell, not by this host; and an
    explicit `exit 0` means a non-zero exit code can only mean the probe
    itself broke, never that the file failed to open (which is reported
    in-band via markers)."""
    body = _build_read_probe_script(GUEST_BINARY_PATH, None)

    assert body.endswith("exit 0\r\n")
    assert "\r\n" in body
    assert "\n" not in body.replace("\r\n", "")


def test_read_probe_script_is_read_only_and_never_starts_a_process():
    """Explicit guard on the two constraints the instruction called out: no
    Process.Start()/CreateProcess of any kind, and nothing that could write
    to, move or delete the target."""
    script = _build_read_probe_script(GUEST_BINARY_PATH)

    lowered = script.lower()
    for forbidden in (
        "process.start",
        "start-process",
        "createprocess",
        "invoke-item",
        "remove-item",
        "set-content",
        "move-item",
        "filemode::create",
        "fileaccess::write",
        "fileaccess::readwrite",
    ):
        assert forbidden not in lowered, forbidden

    # The one open it does perform is read-only, with the most permissive
    # share mode so a sharing violation genuinely means "another handle
    # denies read sharing".
    assert "[System.IO.FileAccess]::Read" in script
    assert "[System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete" in (
        script
    )
    assert "[System.IO.FileMode]::Open" in script
    # Windows PowerShell 5.1 surface only - no pwsh/PS7 requirement.
    assert "pwsh" not in lowered
    # Innermost exception, not PowerShell's MethodInvocationException wrapper.
    assert "InnerException" in script


def test_parse_read_probe_output_successful_open_and_hash():
    sha256 = "a" * 64
    parsed = _parse_read_probe_output(_read_probe_stdout_ok(sha256).decode())

    assert parsed["test_path"] is True
    assert parsed["length"] == 280576
    assert parsed["attributes"] == "Archive"
    assert parsed["last_write_utc"] == "2026-09-21T18:00:00.0000000Z"
    assert parsed["open_result"] == "OK"
    assert parsed["read_bytes"] == 280576
    assert parsed["guest_sha256"] == sha256
    assert parsed["exception_type"] is None
    assert parsed["hresult"] is None
    assert parsed["win32_error"] is None


def test_parse_read_probe_output_open_failure_with_hresult_and_win32_code():
    parsed = _parse_read_probe_output(READ_STDOUT_ACCESS_DENIED.decode())

    assert parsed["test_path"] is True
    assert parsed["length"] == 280576
    assert parsed["open_result"] == "FAIL"
    assert parsed["guest_sha256"] is None
    assert parsed["exception_type"] == "System.UnauthorizedAccessException"
    assert parsed["hresult"] == -2147024891
    # 0x80070005 -> Win32 5, ERROR_ACCESS_DENIED, directly comparable with
    # the ErrorCode DRAKVUF's own injector reports.
    assert parsed["win32_error"] == 5
    assert parsed["exception_message"] == "Access to the path is denied."


def test_parse_read_probe_output_sharing_violation_win32_code():
    parsed = _parse_read_probe_output(READ_STDOUT_SHARING_VIOLATION.decode())

    assert parsed["open_result"] == "FAIL"
    assert parsed["exception_type"] == "System.IO.IOException"
    assert parsed["win32_error"] == 32  # ERROR_SHARING_VIOLATION


def test_win32_error_from_hresult_only_decodes_win32_facility_hresults():
    assert _win32_error_from_hresult(-2147024891) == 5  # 0x80070005
    assert _win32_error_from_hresult(-2147024864) == 32  # 0x80070020
    assert _win32_error_from_hresult(-2147024894) == 2  # 0x80070002
    assert (
        _win32_error_from_hresult(-2147467259) is None
    )  # 0x80004005, not FACILITY_WIN32
    assert _win32_error_from_hresult(0) is None
    assert _win32_error_from_hresult(None) is None


def test_parse_read_probe_output_malformed_output_stays_inconclusive():
    """Garbage, truncated or empty PowerShell output must never be readable
    as a definitive answer - the same rule the metadata probe follows."""
    for text in (
        "",
        "powershell.exe is not recognized",
        "CHIMERA_READ_OPEN:MAYBE\r\nCHIMERA_READ_SHA256:not-a-hash\r\n",
        "CHIMERA_READ_TESTPATH:banana\r\nCHIMERA_READ_LENGTH:x\r\n"
        "CHIMERA_READ_HRESULT:not-a-number\r\n",
    ):
        parsed = _parse_read_probe_output(text)
        assert parsed["open_result"] is None
        assert parsed["guest_sha256"] is None
        assert parsed["test_path"] is None
        assert parsed["length"] is None
        assert parsed["hresult"] is None
        assert parsed["win32_error"] is None


def test_probe_guest_file_read_classifies_matching_hash(tmp_path, alkhaser_binary):
    """Outcome C: the file opened, read fully, and its SHA-256 matches the
    host original byte for byte."""
    host_sha256 = hashlib.sha256(alkhaser_binary.read_bytes()).hexdigest()
    session = ProbeScriptedGuestSession(
        read_probe_stdout=_read_probe_stdout_ok(host_sha256)
    )

    probe = _probe_guest_file_read(
        session,
        str(alkhaser_binary),
        GUEST_BINARY_PATH,
        ALKHASER_GUEST_DIR,
        tmp_path,
        "post_upload",
    )

    assert probe["classification"] == READ_PROBE_CLASS_HASH_MATCHES
    assert probe["open_result"] == "OK"
    assert probe["guest_sha256"] == host_sha256
    assert probe["host_sha256"] == host_sha256
    assert probe["checkpoint"] == "post_upload"
    assert probe["exit_code"] == 0
    assert "probe_error" not in probe
    # Raw evidence preserved, not just the parsed view.
    assert _READ_TESTPATH_MARKER in probe["stdout"]
    assert probe["command"].startswith(
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -File "
    )
    assert probe["guest_script_path"].endswith("__chimera_read_probe_post_upload.ps1")
    assert "[System.IO.FileAccess]::Read" in probe["script"]
    # The artifact records that the invocation stayed inside drakshell's
    # ceiling - the exact thing that silently failed in scan 34ae2d08.
    assert probe["cmdline_limit_bytes"] == DRAKSHELL_MAX_CMDLINE_BYTES
    assert probe["cmdline_bytes"] < DRAKSHELL_MAX_CMDLINE_BYTES
    # The probe script was delivered by put_file() before being invoked.
    assert probe["guest_script_path"] in [c[1] for c in session.put_file_calls]
    assert "upload_error" not in probe

    on_disk = json.loads((tmp_path / "read_probe_post_upload.json").read_text())
    assert on_disk["classification"] == READ_PROBE_CLASS_HASH_MATCHES
    assert on_disk["guest_sha256"] == host_sha256


def test_probe_guest_file_read_classifies_hash_mismatch(tmp_path, alkhaser_binary):
    """Outcome D: it opened and read, but the bytes on the guest are not the
    bytes we uploaded."""
    session = ProbeScriptedGuestSession(
        read_probe_stdout=_read_probe_stdout_ok("b" * 64)
    )

    probe = _probe_guest_file_read(
        session,
        str(alkhaser_binary),
        GUEST_BINARY_PATH,
        ALKHASER_GUEST_DIR,
        tmp_path,
        "pre_run",
    )

    assert probe["classification"] == READ_PROBE_CLASS_HASH_DIFFERS
    assert probe["guest_sha256"] != probe["host_sha256"]


def test_probe_guest_file_read_classifies_exists_but_unopenable(
    tmp_path, alkhaser_binary
):
    """Outcome A - the decisive one for this investigation: Windows agrees
    the file is there and can stat it, but an ordinary user-mode process
    cannot open its data stream."""
    session = ProbeScriptedGuestSession(read_probe_stdout=READ_STDOUT_ACCESS_DENIED)

    probe = _probe_guest_file_read(
        session,
        str(alkhaser_binary),
        GUEST_BINARY_PATH,
        ALKHASER_GUEST_DIR,
        tmp_path,
        "pre_run",
    )

    assert probe["classification"] == READ_PROBE_CLASS_UNOPENABLE
    assert probe["test_path"] is True
    assert probe["length"] == 280576
    assert probe["win32_error"] == 5
    assert probe["exception_type"] == "System.UnauthorizedAccessException"
    assert probe["guest_sha256"] is None


def test_probe_guest_file_read_classifies_missing_file(tmp_path, alkhaser_binary):
    session = ProbeScriptedGuestSession(read_probe_stdout=READ_STDOUT_NOT_FOUND)

    probe = _probe_guest_file_read(
        session,
        str(alkhaser_binary),
        GUEST_BINARY_PATH,
        ALKHASER_GUEST_DIR,
        tmp_path,
        "post_upload",
    )

    assert probe["classification"] == READ_PROBE_CLASS_MISSING
    assert probe["test_path"] is False


def test_probe_guest_file_read_records_command_failure_without_raising(
    tmp_path, alkhaser_binary
):
    """A probe that cannot run at all is recorded and classified
    inconclusive - never as one of the substantive verdicts, and never
    raised into the verifier's control flow."""
    session = ProbeScriptedGuestSession(
        read_probe_error=RuntimeError("Guest session is no longer usable: desync")
    )

    probe = _probe_guest_file_read(
        session,
        str(alkhaser_binary),
        GUEST_BINARY_PATH,
        ALKHASER_GUEST_DIR,
        tmp_path,
        "post_upload",
    )

    assert "desync" in probe["probe_error"]
    assert probe["classification"] == READ_PROBE_CLASS_INCONCLUSIVE
    on_disk = json.loads((tmp_path / "read_probe_post_upload.json").read_text())
    assert "desync" in on_disk["probe_error"]
    # Schema is stable even when the probe could not run at all: every
    # parsed field is present and explicitly None, never simply absent.
    for field in (
        "test_path",
        "length",
        "attributes",
        "last_write_utc",
        "open_result",
        "read_bytes",
        "guest_sha256",
        "exception_type",
        "hresult",
        "win32_error",
        "exception_message",
    ):
        assert field in on_disk and on_disk[field] is None, field


def test_probe_guest_file_read_passes_no_cwd(tmp_path, alkhaser_binary):
    """cwd must NOT be passed: without it the argv list goes down the exact
    mslex path _ensure_remote_parent_dir() already proves works on this
    image, instead of gaining a pointless extra cmd.exe wrapper layer."""
    session = ProbeScriptedGuestSession(
        read_probe_stdout=_read_probe_stdout_ok("c" * 64)
    )

    _probe_guest_file_read(
        session,
        str(alkhaser_binary),
        GUEST_BINARY_PATH,
        ALKHASER_GUEST_DIR,
        tmp_path,
        "post_upload",
    )

    _argv, _timeout, cwd = session.read_probe_runs[0]
    assert cwd is None


def test_probe_guest_file_read_records_host_read_error_without_raising(tmp_path):
    session = ProbeScriptedGuestSession(
        read_probe_stdout=_read_probe_stdout_ok("d" * 64)
    )

    probe = _probe_guest_file_read(
        session,
        str(tmp_path / "nope.exe"),
        GUEST_BINARY_PATH,
        ALKHASER_GUEST_DIR,
        tmp_path,
        "pre_run",
    )

    assert "host_error" in probe
    assert probe["host_sha256"] is None
    # The guest opened and read the file; we just cannot compare hashes.
    assert probe["open_result"] == "OK"
    assert probe["classification"] == "B_opened_and_read_but_host_hash_unknown"


# ==========================================================================
# DRAKVUF injector ErrorCode/Error surfacing in diag_<checkpoint>.json.
# ==========================================================================

_INJECTOR_ERROR_LINE = (
    '{"Plugin": "inject", "TimeStamp": "1758134613.123456", '
    '"Method": "readfile", "Status": "Error", "ErrorCode": 5, '
    '"Error": "ERROR_ACCESS_DENIED"}'
)


class _InjectorErrorGuestSession(FakeGuestSession):
    """get_file() fails exactly the way the real GuestSession does - with an
    InjectorReadError carrying DRAKVUF's stdout JSON."""

    def get_file(self, remote_path, local_path):
        self.get_file_calls.append((remote_path, local_path))
        raise InjectorReadError(
            remote_path,
            1,
            _INJECTOR_ERROR_LINE.encode(),
            b"Couldn't open guest file",
        )


def test_diagnose_uploaded_binary_records_injector_error_code(
    tmp_path, alkhaser_binary
):
    """The whole point of the get_file() change: the precise Win32 reason
    CreateFileW failed must land in the artifact, not just DRAKVUF's opaque
    "Couldn't open guest file" string."""
    session = _InjectorErrorGuestSession()

    diagnostic = _diagnose_uploaded_binary(
        session, str(alkhaser_binary), GUEST_BINARY_PATH, tmp_path, "pre_run"
    )

    assert diagnostic["guest_exists"] is False
    assert diagnostic["injector_error_code"] == 5
    assert diagnostic["injector_error_name"] == "ERROR_ACCESS_DENIED"
    assert diagnostic["injector_error_json"]["Method"] == "readfile"
    assert diagnostic["injector_returncode"] == 1
    # Raw output on BOTH streams is preserved - nothing discarded.
    assert _INJECTOR_ERROR_LINE in diagnostic["injector_stdout"]
    assert "Couldn't open guest file" in diagnostic["injector_stderr"]
    # ...and the artifact on disk carries the same, JSON-serializable.
    on_disk = json.loads((tmp_path / "diag_pre_run.json").read_text())
    assert on_disk["injector_error_code"] == 5
    assert on_disk["injector_error_name"] == "ERROR_ACCESS_DENIED"


def test_diagnose_uploaded_binary_without_injector_fields_is_unchanged(
    tmp_path, alkhaser_binary
):
    """A GuestSession implementation that raises something else entirely
    (every unit-test fake raises FileNotFoundError) must still produce the
    pre-existing schema, with no injector_* keys invented."""
    session = FakeGuestSession(files={})

    diagnostic = _diagnose_uploaded_binary(
        session, str(alkhaser_binary), GUEST_BINARY_PATH, tmp_path, "post_upload"
    )

    assert diagnostic["guest_exists"] is False
    assert "guest_error" in diagnostic
    assert "injector_error_code" not in diagnostic
    assert "injector_stdout" not in diagnostic


# ==========================================================================
# Checkpoint ordering across all three diagnostics.
# ==========================================================================


def _diagnostic_order(session):
    """The run()-based guest calls the adapter made, named and in the order
    they actually happened. The injector read-backs use get_file() rather
    than run(), so they are asserted separately via get_file_calls."""
    order = []
    for argv, _t, _c in session.run_calls:
        if len(argv) == 3 and _PROBE_EXISTS_MARKER in argv[2]:
            order.append("metadata")
        elif _is_read_probe_invocation(argv):
            order.append("read_hash")
        elif "--sleep" in " ".join(argv):
            order.append("launch")
    return order


def test_run_executes_all_three_diagnostics_in_the_specified_order(
    tmp_path, alkhaser_binary
):
    """post-upload: put_file -> metadata -> read/hash -> DRAKVUF readfile
    pre-run:     DRAKVUF readfile -> read/hash -> metadata -> al-khaser run

    The two guest-side probes bracket the window (cheapest observation
    closest to each event); the two injector read-backs sit adjacent in the
    middle, where they can least distort what they measure."""
    host_sha256 = hashlib.sha256(alkhaser_binary.read_bytes()).hexdigest()
    log_bytes = b"[Mon Jan 01 00:00:00 2024] [*] TLS process attach callback  -> 0\n"
    session = ProbeScriptedGuestSession(
        run_result=(0, b"", b""),
        files={
            r"C:\Users\Public\alkhaser\log.txt": log_bytes,
            r"C:\Users\Public\alkhaser\stdout.txt": b"unused",
        },
        read_probe_stdout=_read_probe_stdout_ok(host_sha256),
    )
    adapter = AlKhaserAdapter()
    options = {"host_binary_path": str(alkhaser_binary), "checks": ["TLS"]}

    result = adapter.run(session, options, tmp_path, deadline=time.time() + 60)

    assert result.status == ToolStatus.ok

    # run()-based diagnostics, in order, with the launch strictly last.
    assert _diagnostic_order(session) == [
        "metadata",
        "read_hash",
        "read_hash",
        "metadata",
        "launch",
    ]

    # The binary was uploaded exactly once, and first - before any
    # diagnostic. The two probe .ps1 uploads follow it.
    assert session.put_file_calls[0][1] == GUEST_BINARY_PATH
    binary_uploads = [c for c in session.put_file_calls if c[1] == GUEST_BINARY_PATH]
    assert len(binary_uploads) == 1
    script_uploads = [c for c in session.put_file_calls if c[1].endswith(".ps1")]
    assert [c[1] for c in script_uploads] == [
        read_probe_script_guest_path(ALKHASER_GUEST_DIR, "post_upload"),
        read_probe_script_guest_path(ALKHASER_GUEST_DIR, "pre_run"),
    ]

    # The two injector read-backs of the BINARY are the 1st and 2nd
    # get_file() calls; stdout.txt/log.txt collection follows the launch.
    binary_reads = [
        i
        for i, (path, _p) in enumerate(session.get_file_calls)
        if path == GUEST_BINARY_PATH
    ]
    assert binary_reads == [0, 1]

    # al-khaser itself is still launched exactly once.
    assert _diagnostic_order(session).count("launch") == 1


def test_run_writes_all_six_diagnostic_artifacts(tmp_path, alkhaser_binary):
    host_sha256 = hashlib.sha256(alkhaser_binary.read_bytes()).hexdigest()
    log_bytes = b"[Mon Jan 01 00:00:00 2024] [*] TLS process attach callback  -> 0\n"
    session = ProbeScriptedGuestSession(
        run_result=(0, b"", b""),
        files={
            r"C:\Users\Public\alkhaser\log.txt": log_bytes,
            r"C:\Users\Public\alkhaser\stdout.txt": b"unused",
        },
        read_probe_stdout=_read_probe_stdout_ok(host_sha256),
    )
    adapter = AlKhaserAdapter()
    options = {"host_binary_path": str(alkhaser_binary), "checks": ["TLS"]}

    result = adapter.run(session, options, tmp_path, deadline=time.time() + 60)

    raw_dir = tmp_path / "raw" / "alkhaser"
    for name in (
        "probe_post_upload.json",
        "probe_pre_run.json",
        "read_probe_post_upload.json",
        "read_probe_pre_run.json",
        "diag_post_upload.json",
        "diag_pre_run.json",
    ):
        assert (raw_dir / name).exists(), name
        assert str((raw_dir / name).relative_to(tmp_path)) in result.raw_artifacts
        # Every artifact carries enough provenance to stand alone.
        payload = json.loads((raw_dir / name).read_text())
        assert payload["guest_path"] == GUEST_BINARY_PATH
        assert payload["timestamp"].endswith("Z")

    for name in ("read_probe_post_upload.json", "read_probe_pre_run.json"):
        payload = json.loads((raw_dir / name).read_text())
        assert payload["classification"] == READ_PROBE_CLASS_HASH_MATCHES


def test_run_read_probe_failure_does_not_alter_verifier_result(
    tmp_path, alkhaser_binary
):
    """Observational only: a read/hash probe that blows up must be recorded
    and must NOT change al-khaser's own ToolResult."""
    log_bytes = b"[Mon Jan 01 00:00:00 2024] [*] TLS process attach callback  -> 0\n"
    session = ProbeScriptedGuestSession(
        run_result=(0, b"", b""),
        files={
            r"C:\Users\Public\alkhaser\log.txt": log_bytes,
            r"C:\Users\Public\alkhaser\stdout.txt": b"unused",
        },
        read_probe_error=RuntimeError("read probe blew up"),
    )
    adapter = AlKhaserAdapter()
    options = {"host_binary_path": str(alkhaser_binary), "checks": ["TLS"]}

    result = adapter.run(session, options, tmp_path, deadline=time.time() + 60)

    assert result.status == ToolStatus.ok
    assert result.error is None
    assert len(result.checks) == 2
    # al-khaser still launched exactly once.
    assert _diagnostic_order(session).count("launch") == 1

    raw_dir = tmp_path / "raw" / "alkhaser"
    for name in ("read_probe_post_upload.json", "read_probe_pre_run.json"):
        payload = json.loads((raw_dir / name).read_text())
        assert "read probe blew up" in payload["probe_error"]
        assert payload["classification"] == READ_PROBE_CLASS_INCONCLUSIVE


def test_run_all_diagnostics_failing_still_reports_the_real_alkhaser_failure(
    tmp_path, alkhaser_binary
):
    """The control-flow rule in full: with every diagnostic broken AND
    al-khaser producing no parseable output, the reported result must be
    al-khaser's own genuine failure - not a diagnostic's."""
    session = ProbeScriptedGuestSession(
        run_result=(1, b"", b""),
        files={},  # neither log.txt nor stdout.txt retrievable
        probe_error=RuntimeError("metadata probe blew up"),
        read_probe_error=RuntimeError("read probe blew up"),
    )
    adapter = AlKhaserAdapter()
    options = {"host_binary_path": str(alkhaser_binary), "checks": ["TLS"]}

    result = adapter.run(session, options, tmp_path, deadline=time.time() + 60)

    assert result.status == ToolStatus.error
    assert result.error == (
        "Neither log.txt nor stdout could be retrieved from the guest."
    )
    assert result.exit_code == 1
    # ...and every diagnostic's raw evidence is still attached.
    assert len(result.raw_artifacts) == 6


# ==========================================================================
# File-based probe delivery: upload the .ps1, then invoke it by path.
# ==========================================================================


def test_probe_guest_file_read_uploads_script_before_invoking_it(
    tmp_path, alkhaser_binary
):
    """Ordering matters: the script must be on disk in the guest before the
    invocation that runs it by path."""
    host_sha256 = hashlib.sha256(alkhaser_binary.read_bytes()).hexdigest()
    session = ProbeScriptedGuestSession(
        read_probe_stdout=_read_probe_stdout_ok(host_sha256)
    )

    probe = _probe_guest_file_read(
        session,
        str(alkhaser_binary),
        GUEST_BINARY_PATH,
        ALKHASER_GUEST_DIR,
        tmp_path,
        "post_upload",
    )

    (upload,) = session.put_file_calls
    assert upload[1] == probe["guest_script_path"]
    # What was uploaded is exactly the script recorded in the artifact,
    # UTF-8 BOM prefixed for Windows PowerShell 5.1.
    uploaded_bytes = (
        pathlib.Path(upload[0]).read_bytes() if upload[0].exists() else None
    )
    if uploaded_bytes is not None:  # temp dir may already be cleaned up
        assert uploaded_bytes.startswith(b"\xef\xbb\xbf")
    assert session.files[probe["guest_script_path"]].startswith(b"\xef\xbb\xbf")
    assert b"CHIMERA_READ_TESTPATH:" in session.files[probe["guest_script_path"]]
    # ...and the invocation ran that same path.
    argv, _t, _cwd = session.read_probe_runs[0]
    assert argv[-1] == probe["guest_script_path"]


def test_probe_guest_file_read_records_upload_failure_and_skips_invocation(
    tmp_path, alkhaser_binary
):
    """If the probe script cannot be delivered, say so explicitly and do not
    pretend the probe ran - 'could not deliver' and 'ran and found nothing'
    are different facts."""

    class FailingUploadSession(ProbeScriptedGuestSession):
        def put_file(self, local_path, remote_path):
            raise RuntimeError("injector writefile failed (exit 1)")

    session = FailingUploadSession(read_probe_stdout=_read_probe_stdout_ok("a" * 64))

    probe = _probe_guest_file_read(
        session,
        str(alkhaser_binary),
        GUEST_BINARY_PATH,
        ALKHASER_GUEST_DIR,
        tmp_path,
        "pre_run",
    )

    assert "injector writefile failed" in probe["upload_error"]
    assert "probe_error" not in probe
    assert session.read_probe_runs == []
    assert probe["classification"] == READ_PROBE_CLASS_INCONCLUSIVE
    on_disk = json.loads((tmp_path / "read_probe_pre_run.json").read_text())
    assert "injector writefile failed" in on_disk["upload_error"]


def test_probe_records_in_guest_hash_comparison(tmp_path, alkhaser_binary):
    """The guest does its own comparison against the embedded host hash, so
    the artifact states the verdict as Windows computed it."""
    host_sha256 = hashlib.sha256(alkhaser_binary.read_bytes()).hexdigest()
    stdout = (
        _read_probe_stdout_ok(host_sha256)
        + (
            f"CHIMERA_READ_EXPECTED:{host_sha256}\r\n" "CHIMERA_READ_HASHMATCH:True\r\n"
        ).encode()
    )
    session = ProbeScriptedGuestSession(read_probe_stdout=stdout)

    probe = _probe_guest_file_read(
        session,
        str(alkhaser_binary),
        GUEST_BINARY_PATH,
        ALKHASER_GUEST_DIR,
        tmp_path,
        "post_upload",
    )

    assert probe["expected_sha256"] == host_sha256
    assert probe["guest_hash_match"] is True
    # Host-side classification remains the authority and must agree.
    assert probe["classification"] == READ_PROBE_CLASS_HASH_MATCHES


def test_probe_records_in_guest_hash_mismatch(tmp_path, alkhaser_binary):
    host_sha256 = hashlib.sha256(alkhaser_binary.read_bytes()).hexdigest()
    stdout = (
        _read_probe_stdout_ok("b" * 64)
        + (
            f"CHIMERA_READ_EXPECTED:{host_sha256}\r\n"
            "CHIMERA_READ_HASHMATCH:False\r\n"
        ).encode()
    )
    session = ProbeScriptedGuestSession(read_probe_stdout=stdout)

    probe = _probe_guest_file_read(
        session,
        str(alkhaser_binary),
        GUEST_BINARY_PATH,
        ALKHASER_GUEST_DIR,
        tmp_path,
        "pre_run",
    )

    assert probe["guest_hash_match"] is False
    assert probe["classification"] == READ_PROBE_CLASS_HASH_DIFFERS


def test_parse_read_probe_output_ignores_malformed_hash_comparison_markers():
    parsed = _parse_read_probe_output(
        "CHIMERA_READ_EXPECTED:not-a-hash\r\nCHIMERA_READ_HASHMATCH:maybe\r\n"
    )

    assert parsed["expected_sha256"] is None
    assert parsed["guest_hash_match"] is None
