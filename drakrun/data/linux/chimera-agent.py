#!/usr/bin/python3
"""CHIMERA Linux guest agent: the Linux counterpart of drakshell.

Installed in the guest as /usr/local/sbin/console-helper (console-helper.service). Answers requests from dom0 on the
first serial port (/dev/ttyS0, a unix socket on the host: /var/run/drakrun/vm-N.sock).

Protocol, one line each way (ASCII):
    host  -> guest:  @@C> <id> <command> <base64 JSON arguments>
    guest -> host:   @@C< <id> OK|ERR <base64 JSON result>
Anything else on the line (stray console output) is ignored by both sides.

The agent stays single-threaded and wakes up every 0.5 s so that the DRAKVUF
injector can hijack it (Linux injection needs a target that makes syscalls).
"""
import base64
import hashlib
import json
import os
import pwd
import select
import subprocess
import sys
import termios
import time
import tty

PORT = "/dev/ttyS0"
# Samples go where a downloaded file would be (GUEST_WORK_DIR in drakrun/lib/linux_install.py); the agent's own
# files go to a root-only directory so nothing next to the sample names the sandbox
WORK_DIR = "/home/arjun/Downloads"
STATE_DIR = "/var/lib/console-helper"
REQUEST = b"@@C> "
REPLY = "@@C< "
MAX_LINE = 1 << 20


def cmd_ping(args):
    return {
        "pid": os.getpid(),
        "time_ms": int(time.time() * 1000),
        "uname": " ".join(os.uname()),
        "uptime_s": float(open("/proc/uptime").read().split()[0]),
    }


def cmd_clock(args):
    host_ms = int(args["host_ms"])
    before_ms = int(time.time() * 1000)
    time.clock_settime(time.CLOCK_REALTIME, host_ms / 1000)
    after_ms = int(time.time() * 1000)
    return {"before_ms": before_ms, "after_ms": after_ms}


def _ipv4_addresses():
    out = subprocess.run(["ip", "-j", "-4", "addr"], capture_output=True, text=True, timeout=10)
    return {i["ifname"]: [a["local"] for a in i.get("addr_info", [])] for i in json.loads(out.stdout or "[]")}


def cmd_net(args):
    # After a restore the NIC loses carrier and systemd-networkd drops the lease, then asks DHCP again:
    # wait until a non-loopback interface has an IPv4 address
    deadline = time.monotonic() + float(args.get("timeout", 30))
    while True:
        addrs = _ipv4_addresses()
        if any(v for k, v in addrs.items() if k != "lo") or time.monotonic() > deadline:
            return {"addr": addrs, "ready": any(v for k, v in addrs.items() if k != "lo")}
        time.sleep(0.5)


def cmd_prepare(args):
    os.makedirs(WORK_DIR, exist_ok=True)
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    return {"work_dir": WORK_DIR}


def cmd_stat(args):
    path = args["path"]
    st = os.stat(path)
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            digest.update(chunk)
    return {"size": st.st_size, "mode": st.st_mode, "uid": st.st_uid, "sha256": digest.hexdigest()}


def cmd_chmod(args):
    os.chmod(args["path"], int(args["mode"]))
    return {}


def user_credentials(name):
    """Popen keyword arguments that run a child as the given account (with its supplementary groups)."""
    pw = pwd.getpwnam(name)
    return {"user": pw.pw_uid, "group": pw.pw_gid, "extra_groups": os.getgrouplist(name, pw.pw_gid)}


def cmd_exec(args):
    argv = [str(a) for a in args["argv"]]
    cwd = args.get("cwd", WORK_DIR)
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    out_base = os.path.join(STATE_DIR, "exec-" + str(int(time.time() * 1000)))
    # A sample runs as the desktop user, like a downloaded file someone opened; the output files stay
    # root's (opened here, before the child drops privileges)
    creds = user_credentials(args["user"]) if args.get("user") else {}
    proc = subprocess.Popen(
        argv,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=open(out_base + ".out", "wb"),
        stderr=open(out_base + ".err", "wb"),
        start_new_session=True,
        env=args.get("env") or {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                                 "HOME": "/root", "LANG": "C.UTF-8"},
        **creds,
    )
    return {"pid": proc.pid, "uid": creds.get("user", os.getuid())}


def cmd_sh(args):
    # Bounded shell command for setup and diagnostics; never used to start a sample
    res = subprocess.run(args["cmd"], shell=True, capture_output=True, timeout=int(args.get("timeout", 30)))
    return {"rc": res.returncode, "stdout": res.stdout[-65536:].decode(errors="replace"),
            "stderr": res.stderr[-65536:].decode(errors="replace")}


COMMANDS = {
    "ping": cmd_ping, "clock": cmd_clock, "net": cmd_net, "prepare": cmd_prepare,
    "stat": cmd_stat, "chmod": cmd_chmod, "exec": cmd_exec, "sh": cmd_sh,
}


def handle(line, write):
    i = line.find(REQUEST)
    if i < 0:
        return
    try:
        req_id, name, payload = line[i + len(REQUEST):].decode("ascii").split(" ", 2)
    except ValueError:
        return
    try:
        result = COMMANDS[name](json.loads(base64.b64decode(payload) or b"{}"))
        status = "OK"
    except Exception as exc:  # report every failure to the host instead of dying
        result, status = {"error": f"{type(exc).__name__}: {exc}"}, "ERR"
    body = base64.b64encode(json.dumps(result).encode()).decode()
    write(f"\n{REPLY}{req_id} {status} {body}\n".encode())


def main():
    fd = os.open(PORT, os.O_RDWR | os.O_NOCTTY)
    tty.setraw(fd)
    attrs = termios.tcgetattr(fd)
    attrs[4] = attrs[5] = termios.B115200
    termios.tcsetattr(fd, termios.TCSANOW, attrs)

    def write(data):
        while data:
            data = data[os.write(fd, data):]

    buf = b""
    while True:
        ready, _, _ = select.select([fd], [], [], 0.5)
        if not ready:
            continue
        buf += os.read(fd, 65536)
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            handle(line.rstrip(b"\r"), write)
        if len(buf) > MAX_LINE:
            buf = b""


if __name__ == "__main__":
    sys.exit(main())
