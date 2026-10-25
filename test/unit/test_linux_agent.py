"""Serial protocol exercised over local sockets, without a running guest."""

import base64
import json
import os
import select
import socket
from concurrent.futures import ThreadPoolExecutor

import pytest

from drakrun.lib.linux_agent import LinuxAgent, LinuxAgentError


class SocketpairStream:
    """Use fd I/O on the real socketpair (send/recv are denied by some CI sandboxes)."""

    def __init__(self, sock):
        self.sock = sock
        self.timeout = None

    def sendall(self, data):
        while data:
            written = os.write(self.sock.fileno(), data)
            data = data[written:]

    def recv(self, size):
        readable, _, _ = select.select([self.sock], [], [], self.timeout)
        if not readable:
            raise socket.timeout()
        return os.read(self.sock.fileno(), size)

    def settimeout(self, timeout):
        self.timeout = timeout

    def close(self):
        self.sock.close()


@pytest.fixture
def channel(monkeypatch):
    left, right = socket.socketpair()
    host, guest = SocketpairStream(left), SocketpairStream(right)
    guest.settimeout(2)
    agent = LinuxAgent("unused")
    agent.sock = host
    monkeypatch.setattr(
        "drakrun.lib.linux_agent.secrets.token_hex", lambda _: "1234abcd"
    )
    try:
        yield agent, guest
    finally:
        agent.close()
        guest.close()


def encoded(value):
    return base64.b64encode(json.dumps(value).encode())


def read_request(guest):
    data = b""
    while data.count(b"\n") < 2:
        chunk = guest.recv(65536)
        assert chunk, "host closed before sending a complete request"
        data += chunk
    assert data.startswith(b"\n")
    return data[1:]


def test_agent_request_framing_noise_and_fragmented_reply(channel):
    agent, guest = channel
    args = {"argv": ["/tmp/sample", "two words", "π"], "cwd": "/tmp"}

    def fake_guest():
        request = read_request(guest)
        prefix, reqid, command, payload = request.rstrip(b"\n").split(b" ", 3)
        assert (prefix, reqid, command) == (b"@@C>", b"1234abcd", b"exec")
        assert json.loads(base64.b64decode(payload)) == args
        guest.sendall(
            b"boot noise\n@@C< stale ERR " + encoded({"error": "old"}) + b"\n"
        )
        # Console output can be prefixed to a reply, and recv boundaries need not be lines.
        reply = b"console: @@C< " + reqid + b" OK " + encoded({"pid": 42}) + b"\r\n"
        guest.sendall(reply[:12])
        guest.sendall(reply[12:])

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(fake_guest)
        assert agent.call("exec", args, timeout=1) == {"pid": 42}
        future.result(timeout=2)


def test_agent_empty_args_and_error(channel):
    agent, guest = channel

    def fake_guest():
        assert read_request(guest) == b"@@C> 1234abcd prepare e30=\n"
        guest.sendall(
            b"@@C< 1234abcd ERR " + encoded({"error": "permission denied"}) + b"\n"
        )

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(fake_guest)
        with pytest.raises(LinuxAgentError, match="prepare: permission denied"):
            agent.call("prepare", timeout=1)
        future.result(timeout=2)


def test_agent_timeout(channel):
    agent, guest = channel
    guest.sendall(b"noise only\n@@C< stale OK e30=\n")
    with pytest.raises(TimeoutError, match="guest agent did not answer 'ping'"):
        agent.call("ping", timeout=0.02)


def test_agent_closed_socket(channel):
    agent, guest = channel

    def fake_guest():
        read_request(guest)
        guest.close()

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(fake_guest)
        with pytest.raises(LinuxAgentError, match="serial socket closed"):
            agent.call("ping", timeout=1)
        future.result(timeout=2)


def test_agent_close_clears_partial_reply(channel):
    agent, _ = channel
    agent.buf = b"partial"
    agent.close()
    agent.close()
    assert agent.sock is None
    assert agent.buf == b""


def test_guest_agent_exec_drops_to_the_requested_user(monkeypatch, tmp_path):
    import importlib.util
    from types import SimpleNamespace

    from drakrun.lib.paths import PACKAGE_DATA_PATH

    spec = importlib.util.spec_from_file_location("chimera_agent", PACKAGE_DATA_PATH / "linux/chimera-agent.py")
    agent = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(agent)
    monkeypatch.setattr(agent, "STATE_DIR", str(tmp_path))
    monkeypatch.setattr(agent.pwd, "getpwnam", lambda name: SimpleNamespace(pw_uid=1000, pw_gid=1000))
    monkeypatch.setattr(agent.os, "getgrouplist", lambda name, gid: [1000, 27])
    popens = []
    monkeypatch.setattr(agent.subprocess, "Popen",
                        lambda argv, **kw: popens.append(kw) or SimpleNamespace(pid=7))
    assert agent.cmd_exec({"argv": ["/tmp/s"], "cwd": str(tmp_path), "user": "arjun"}) == {"pid": 7, "uid": 1000}
    assert (popens[0]["user"], popens[0]["group"], popens[0]["extra_groups"]) == (1000, 1000, [1000, 27])
    # Without a user the child keeps the agent's (root's) identity
    agent.cmd_exec({"argv": ["/bin/true"], "cwd": str(tmp_path)})
    assert "user" not in popens[1]
