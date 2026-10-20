import base64

from drakrun.analyzer import post_restore


class FakeProcess:
    def __init__(self, exit_code):
        self.exit_code = exit_code

    def join(self):
        return self.exit_code


class FakeDrakshell:
    """Answers run_interactive like drakshell: output goes to stdout.send/stderr.send."""

    def __init__(self, stdout=b"", stderr=b"", exit_code=0, error=None):
        self.out, self.err, self.exit_code, self.error = stdout, stderr, exit_code, error
        self.commands = []

    def run_interactive(self, args, stdin, stdout, stderr):
        self.commands.append(args)
        if self.error:
            raise self.error
        stdout.send(self.out)
        stderr.send(self.err)
        return FakeProcess(self.exit_code)


def decoded_script(command):
    assert command[:2] == ["powershell.exe", "-EncodedCommand"]
    return base64.b64decode(command[2]).decode("utf-16le")


def test_sets_clock_to_host_time_and_reports_offsets(monkeypatch):
    # Host at 1_000_000.000 s when the command is built and 1_000_000.500 s when the
    # answer arrives; the guest was 2 h behind and reads 1_000_000.400 s afterwards.
    times = iter([1_000_000.0, 1_000_000.5])
    monkeypatch.setattr(post_restore.time, "time", lambda: next(times, 1_000_000.5))  # logging calls it too
    shell = FakeDrakshell(stdout=b"992800000 1000000400\r\n")

    result = post_restore.set_guest_clock(shell)

    assert result == {"set": True, "offset_before_s": -7200.0, "offset_after_s": -0.1}
    script = decoded_script(shell.commands[0])
    assert "FromUnixTimeMilliseconds(1000000000)" in script
    assert "HOST_MS" not in script


def test_failed_set_date_is_recorded_not_raised():
    shell = FakeDrakshell(stderr=b"Set-Date : A required privilege is not held", exit_code=1)

    result = post_restore.set_guest_clock(shell)

    assert result["set"] is False
    assert "exit code 1" in result["error"]
    assert "privilege" in result["error"]


def test_drakshell_error_is_recorded_not_raised():
    result = post_restore.set_guest_clock(FakeDrakshell(error=RuntimeError("Drakshell is out of sync")))

    assert result == {"set": False, "error": "Drakshell is out of sync"}


def test_unexpected_output_is_recorded_not_raised():
    result = post_restore.set_guest_clock(FakeDrakshell(stdout=b"garbage"))

    assert result["set"] is False
