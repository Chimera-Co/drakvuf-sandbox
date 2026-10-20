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
