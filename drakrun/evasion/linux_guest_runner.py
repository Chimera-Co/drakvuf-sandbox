"""Verifier session over the Linux serial agent and Linux injector writefile."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import pathlib
import shlex
import time
import uuid

from drakrun.evasion.verifiers.base import (
    MAX_REPORT_BYTES,
    GuestCommandResult,
    ReportTooLarge,
    VerifierTimeout,
)
from drakrun.lib import cpuid_hide
from drakrun.lib.linux_install import GUEST_AGENT_DIR
from drakrun.lib.linux_install import GUEST_WORK_DIR as WORK_DIR

# 32 KiB becomes <44 KiB base64, below the agent's 64 KiB stdout cap.
READ_CHUNK_BYTES = 32768

# The agent's exec is asynchronous. This child owns the actual command's
# deadline and process group, and publishes completion only after output closes.
_RUNNER = """
import json,os,signal,subprocess,sys
argv,cwd,seconds,base=json.loads(sys.argv[1])
result={"timeout":False}
with open(base+'.out','wb') as out, open(base+'.err','wb') as err:
    try:
        p=subprocess.Popen(argv,cwd=cwd,stdout=out,stderr=err,start_new_session=True)
    except OSError as exc:
        err.write(str(exc).encode())
        result['rc']=127
    else:
        try:
            result['rc']=p.wait(timeout=seconds)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(p.pid,signal.SIGKILL)
            except ProcessLookupError:
                pass
            p.wait()
            result.update(rc=p.returncode,timeout=True)
with open(base+'.done.tmp','w') as f:
    json.dump(result,f)
os.rename(base+'.done.tmp',base+'.done')
"""


class LinuxGuestSession:
    def __init__(
        self, vm_name, kernel_profile, agent, agent_info, uploader=None, hide_cpuid=False
    ):
        self.vm_name = vm_name
        self.kernel_profile = pathlib.Path(kernel_profile)
        self.agent = agent
        self.agent_info = agent_info
        self.uploader = uploader
        self.drakvuf_attached = False
        # Checks run with Xen masked in CPUID, as during analyses (cpuidmon -s).
        # The injector needs the monitor ring, so uploads pause the hider.
        self.hide_cpuid = hide_cpuid and cpuid_hide.available()
        self._hider = None

    def _hide(self):
        if self.hide_cpuid and self._hider is None:
            self._hider = cpuid_hide.attach(self.vm_name)

    def _unhide(self):
        if self._hider is not None:
            hider, self._hider = self._hider, None
            cpuid_hide.detach(hider)

    def close(self):
        try:
            self._unhide()
        finally:
            self.agent.close()

    def _sh(self, cmd, timeout=30):
        try:
            result = self.agent.call(
                "sh",
                {"cmd": cmd, "timeout": max(1, math.ceil(timeout))},
                timeout=max(1, timeout) + 5,
            )
        except TimeoutError as exc:
            raise VerifierTimeout(str(exc)) from exc
        if result["rc"]:
            raise RuntimeError(
                f"Linux guest command failed: {result.get('stderr', '')}"
            )
        return result["stdout"]

    def put_file(self, local_path, remote_path):
        if self.drakvuf_attached:
            raise RuntimeError(
                "Injector transfer is forbidden while DRAKVUF is attached"
            )
        local_path = pathlib.Path(local_path)
        parent = str(pathlib.PurePosixPath(remote_path).parent)
        self._sh("mkdir -p -- " + shlex.quote(parent))
        uploader = self.uploader
        if uploader is None:
            # Reuse the Linux analyzer's existing injector integration.
            from drakrun.analyzer.linux_analyzer import upload_sample

            uploader = upload_sample
        self._unhide()
        uploader(
            self.vm_name,
            self.kernel_profile,
            self.agent_info["pid"],
            local_path,
            remote_path,
        )
        stat = self.agent.call("stat", {"path": remote_path})
        digest = hashlib.sha256(local_path.read_bytes()).hexdigest()
        if stat["size"] != local_path.stat().st_size or stat["sha256"] != digest:
            raise RuntimeError("Linux guest upload size/hash mismatch")

    def put_tree_as_zip(self, local_dir, remote_dir):
        # Only the single checker script is needed today. Keep the protocol
        # method explicit rather than silently using Windows Expand-Archive.
        raise NotImplementedError("Linux verifier uploads individual files")

    def _read_bytes(self, remote_path, limit=MAX_REPORT_BYTES):
        stat = self.agent.call("stat", {"path": remote_path})
        size = stat["size"]
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or size > limit
        ):
            raise ReportTooLarge(
                f"Linux guest file exceeds {limit} bytes: {remote_path}"
            )
        data = bytearray()
        for offset in range(0, size, READ_CHUNK_BYTES):
            count = min(READ_CHUNK_BYTES, size - offset)
            script = (
                "import base64,sys; f=open(sys.argv[1],'rb'); "
                "f.seek(int(sys.argv[2])); "
                "print(base64.b64encode(f.read(int(sys.argv[3]))).decode())"
            )
            cmd = shlex.join(
                ["python3", "-c", script, remote_path, str(offset), str(count)]
            )
            chunk = base64.b64decode(self._sh(cmd).strip(), validate=True)
            if len(chunk) != count:
                raise RuntimeError("Linux guest report chunk was truncated or changed")
            data.extend(chunk)
        if hashlib.sha256(data).hexdigest() != stat["sha256"]:
            raise RuntimeError("Linux guest report hash mismatch")
        return bytes(data)

    def get_file(self, remote_path, local_path):
        data = self._read_bytes(remote_path)
        local_path = pathlib.Path(local_path)
        local_path.parent.mkdir(parents=True, exist_ok=True)
        local_path.write_bytes(data)

    def run(self, argv, timeout, cwd=None):
        if timeout <= 0:
            raise VerifierTimeout("Linux verifier time budget expired")
        self._hide()
        base = f"{GUEST_AGENT_DIR}/evasion-{uuid.uuid4().hex}"
        # The runner kills its child process group at the guest-side deadline.
        deadline = time.monotonic() + timeout
        self.agent.call(
            "exec",
            {
                "argv": [
                    "python3",
                    "-c",
                    _RUNNER,
                    json.dumps([argv, cwd or WORK_DIR, timeout, base]),
                ],
                "cwd": WORK_DIR,
            },
        )
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise VerifierTimeout("Linux verifier exceeded its time budget")
            state = self._sh(
                f"if test -f {shlex.quote(base + '.done')}; then cat -- {shlex.quote(base + '.done')}; fi",
                timeout=min(5, remaining),
            )
            if state.strip():
                result = json.loads(state)
                if result["timeout"]:
                    raise VerifierTimeout(
                        "Linux verifier exceeded its guest-side deadline"
                    )
                stdout = self._read_bytes(base + ".out")
                stderr = self._read_bytes(base + ".err")
                return GuestCommandResult(result["rc"], stdout, stderr)
            time.sleep(min(0.1, remaining))

    def probe_command(self, argv, timeout):
        result = self.run(argv, timeout)
        return result.exit_code == 0, (result.stdout + result.stderr).decode(
            errors="replace"
        )


def connect_linux_guest_session(vm_name, kernel_profile):
    from drakrun.lib.linux_agent import LinuxAgent

    agent = LinuxAgent(f"/var/run/drakrun/{vm_name}.sock")
    try:
        info = agent.wait_ready(60)
        agent.call("prepare")
        return LinuxGuestSession(
            vm_name, kernel_profile, agent, info, hide_cpuid=True
        )
    except BaseException:
        agent.close()
        raise
