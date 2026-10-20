"""Host side of the CHIMERA Linux guest agent (drakrun/data/linux/chimera-agent.py).

The agent listens on the guest's first serial port, which Xen exposes on dom0 as
/var/run/drakrun/vm-N.sock. One request line, one reply line:
    host  -> guest:  @@C> <id> <command> <base64 JSON arguments>
    guest -> host:   @@C< <id> OK|ERR <base64 JSON result>
"""
import base64
import json
import logging
import secrets
import socket
import sys
import time
from typing import Any, Dict, Optional

log = logging.getLogger(__name__)

REQUEST = "@@C> "
REPLY = b"@@C< "


class LinuxAgentError(RuntimeError):
    pass


class LinuxAgent:
    def __init__(self, socket_path: str):
        self.socket_path = socket_path
        self.sock: Optional[socket.socket] = None
        self.buf = b""

    def connect(self, timeout: float = 30.0) -> None:
        deadline = time.monotonic() + timeout
        while True:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                sock.connect(self.socket_path)
                self.sock = sock
                return
            except OSError:
                sock.close()
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.5)

    def close(self) -> None:
        if self.sock is not None:
            self.sock.close()
            self.sock = None
        self.buf = b""

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *exc):
        self.close()

    def call(self, command: str, args: Optional[Dict[str, Any]] = None, timeout: float = 30.0) -> Dict[str, Any]:
        if self.sock is None:
            self.connect()
        req_id = secrets.token_hex(4)
        payload = base64.b64encode(json.dumps(args or {}).encode()).decode()
        self.sock.sendall(f"\n{REQUEST}{req_id} {command} {payload}\n".encode())
        prefix = REPLY + req_id.encode() + b" "
        deadline = time.monotonic() + timeout
        while True:
            while b"\n" in self.buf:
                line, self.buf = self.buf.split(b"\n", 1)
                i = line.find(prefix)
                if i < 0:
                    continue  # console noise or a reply to an earlier, abandoned request
                status, body = line[i + len(prefix):].rstrip(b"\r").split(b" ", 1)
                result = json.loads(base64.b64decode(body))
                if status != b"OK":
                    raise LinuxAgentError(f"{command}: {result.get('error', result)}")
                return result
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"guest agent did not answer {command!r} in {timeout:.0f} s")
            self.sock.settimeout(remaining)
            try:
                data = self.sock.recv(65536)
            except socket.timeout:
                continue
            if not data:
                raise LinuxAgentError("serial socket closed")
            self.buf += data

    def wait_ready(self, timeout: float = 120.0) -> Dict[str, Any]:
        """Ping until the agent answers (after boot or restore)."""
        deadline = time.monotonic() + timeout
        while True:
            try:
                return self.call("ping", timeout=min(2.0, max(0.1, deadline - time.monotonic())))
            except (TimeoutError, OSError, LinuxAgentError):
                if time.monotonic() > deadline:
                    raise
                self.close()
                time.sleep(1)


def set_guest_clock(agent: LinuxAgent) -> Dict[str, Any]:
    """Same report as drakrun.analyzer.post_restore.set_guest_clock, for Linux guests."""
    try:
        host_ms = int(time.time() * 1000)
        result = agent.call("clock", {"host_ms": host_ms})
        received_ms = int(time.time() * 1000)
        return {
            "set": True,
            "offset_before_s": (result["before_ms"] - host_ms) / 1000,
            "offset_after_s": (result["after_ms"] - received_ms) / 1000,
        }
    except Exception as exc:
        return {"set": False, "error": str(exc)}


def wait_for_vm_network(agent: LinuxAgent, vm_id: int, timeout: float = 30) -> Dict[str, Any]:
    """Wait until the guest has its address in this VM's subnet (10.13.<vm_id>.0/24).

    A restored guest keeps the address it had when the snapshot was saved (vm-0's subnet) until
    systemd-networkd notices the carrier change, which does not always happen. If the old address is still
    there after a few seconds, flush it and make networkd ask DHCP again.
    """
    prefix = f"10.13.{vm_id}."
    deadline = time.monotonic() + timeout
    renewed = False
    while True:
        result = agent.call("net", {"timeout": 5}, timeout=20)
        addrs = [a for name, values in result["addr"].items() if name != "lo" for a in values]
        if any(a.startswith(prefix) for a in addrs):
            return {**result, "ready": True, "renewed": renewed}
        if time.monotonic() > deadline:
            return {**result, "ready": False, "renewed": renewed}
        if addrs and not renewed:
            log.info("Guest still has %s, asking DHCP for an address in %s0/24", addrs, prefix)
            agent.call("sh", {
                "cmd": "for i in $(ls /sys/class/net); do [ \"$i\" = lo ] && continue; "
                       "ip -4 addr flush dev \"$i\"; networkctl reconfigure \"$i\"; done",
                "timeout": 10,
            }, timeout=20)
            renewed = True
        time.sleep(0.5)


def main() -> int:
    """python -m drakrun.lib.linux_agent /var/run/drakrun/vm-2.sock ping '{}'"""
    sock_path, command = sys.argv[1], sys.argv[2]
    args = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    with LinuxAgent(sock_path) as agent:
        if command == "wait":
            print(json.dumps(agent.wait_ready(float(args.get("timeout", 120)))))
        else:
            print(json.dumps(agent.call(command, args, timeout=float(args.get("timeout", 30)) + 30)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
