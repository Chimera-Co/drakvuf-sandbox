import base64
import datetime
import logging
import time

from drakrun.lib.paths import ETC_DIR, PACKAGE_DATA_PATH

log = logging.getLogger(__name__)

# Sets the guest clock to the host's UTC time (HOST_MS, milliseconds since the epoch, filled in
# when the command is built) and prints the guest's UTC time before and after: "before after".
SET_CLOCK_SCRIPT = """$ErrorActionPreference = 'Stop'
$before = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
Set-Date -Date ([DateTimeOffset]::FromUnixTimeMilliseconds(HOST_MS).LocalDateTime) | Out-Null
"$before $([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())"
"""


def prepare_ps_command(script: str):
    encoded_cmd = base64.b64encode(script.encode("utf-16le")).decode()
    return ["powershell.exe", "-EncodedCommand", encoded_cmd]


def get_post_restore_command(net_enable: bool):
    post_restore_script_path = ETC_DIR / "vm-post-restore.ps1"
    if not post_restore_script_path.exists():
        post_restore_script_path = PACKAGE_DATA_PATH / "vm-post-restore.ps1"
    post_restore_script = post_restore_script_path.read_text()
    current_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    script_substs = {
        "$DRAKVUF_NET_ENABLE": "$true" if net_enable else "$false",
        "$DRAKVUF_DATE": f'"{current_date}"',
    }
    for subst_key, subst_value in script_substs.items():
        post_restore_script = post_restore_script.replace(subst_key, subst_value)
    return prepare_ps_command(post_restore_script)


class _Collector:
    """Collects a drakshell process's output (drakshell calls send() with each chunk)."""

    def __init__(self):
        self.data = b""

    def send(self, data: bytes) -> None:
        self.data += data


def set_guest_clock(drakshell) -> dict:
    """
    Sets the guest clock to the host's UTC time. A restored snapshot otherwise keeps the
    clock it had when it was committed, so every analysis ran on the same, ageing date
    (2 h 11 min behind on the 2026-10-20 scans, and more every day after).

    Never raises: the result is recorded in the analysis metadata instead, with the guest's
    offset from the host before the change (offset_before_s) and after it (offset_after_s,
    which includes the time drakshell takes to report back).
    """
    host_ms = int(time.time() * 1000)
    command = prepare_ps_command(SET_CLOCK_SCRIPT.replace("HOST_MS", str(host_ms)))
    stdout, stderr = _Collector(), _Collector()
    try:
        exit_code = drakshell.run_interactive(command, None, stdout, stderr).join()
        received_ms = int(time.time() * 1000)
        if exit_code != 0:
            raise RuntimeError(
                f"exit code {exit_code}: {stderr.data.decode(errors='replace').strip()[:300]}"
            )
        before_ms, after_ms = (int(v) for v in stdout.data.decode().split())
    except Exception as exc:
        log.warning("Setting the guest clock failed: %s", exc)
        return {"set": False, "error": str(exc)}
    result = {
        "set": True,
        "offset_before_s": round((before_ms - host_ms) / 1000, 3),
        "offset_after_s": round((after_ms - received_ms) / 1000, 3),
    }
    log.info("Guest clock set to host time: %s", result)
    return result
