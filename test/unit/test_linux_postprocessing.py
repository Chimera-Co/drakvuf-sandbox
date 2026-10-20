"""Linux attribution, packet decoding, report production and classifier mapping."""

import gzip
import io
import json
import socket
import struct

import pytest

from drakrun.analyzer.analysis_metadata import AnalysisMetadata
from drakrun.analyzer.analysis_options import AnalysisOptions
from drakrun.analyzer.classifier.features import extract_features
from drakrun.analyzer.postprocessing.plugins.get_linux_behaviour_info import (
    get_linux_behaviour_info,
)
from drakrun.analyzer.postprocessing.plugins.plugin_base import PostprocessContext
from drakrun.analyzer.postprocessing.process_tree import tree_from_log
from drakrun.lib.pcap_summary import summarize_pcap


def event(method, pid=20, uid=0x30, ts=102, **fields):
    return dict(
        Method=method, PID=pid, PPID=10, EventUID=hex(uid), TimeStamp=str(ts), **fields
    )


def tree(*events):
    running = dict(RunningProcess="chimera-agent", PID=10, PPID=1)
    return tree_from_log(
        io.StringIO("\n".join(json.dumps(e) for e in (running, *events)))
    )


def clone(pid=10, child=20, uid=0x20, ts=100, **fields):
    return event("kernel_clone", pid, uid, ts, NewPid=child, **fields)


def execute(pid=20, uid=0x25, ts=101, **fields):
    return event(
        "do_execveat_common",
        pid,
        uid,
        ts,
        ImagePathName="/tmp/sample",
        CommandLine="/tmp/sample --out '/tmp/a b'",
        **fields,
    )


def test_linux_fork_exec_preserves_child_identity_and_order():
    pstree = tree(clone(), execute(), clone(20, 30, 0x40, 104))
    agent, sample, child = pstree.processes
    assert sample.parent is agent
    assert sample.seqid == 1
    assert sample.evtid_from == 0x20
    assert sample.ts_from == 100
    assert sample.procname == "/tmp/sample"
    assert sample.args == ["/tmp/sample", "--out", "/tmp/a b"]
    assert child.parent is sample
    assert child.procname == sample.procname
    assert child.args == sample.args
    assert child.args is not sample.args


def test_linux_vfork_exec_before_clone_does_not_duplicate_child():
    pstree = tree(execute(), clone(uid=0x30, ts=102, Flags="CLONE_VFORK|CLONE_VM"))
    assert len(pstree.processes) == 2
    child = pstree.get_process(20)
    assert child.parent is pstree.get_process(10)
    assert child.evtid_from == 0x25
    assert child.procname == "/tmp/sample"


def test_linux_reexec_is_child_of_previous_image():
    reexec = event(
        "do_execveat_common",
        uid=0x50,
        ts=105,
        ImagePathName="/bin/sh",
        CommandLine="sh -c true",
    )
    pstree = tree(clone(), execute(), reexec)
    old, new = pstree.processes[1:]
    assert new.pid == old.pid == 20
    assert new.parent is old
    assert old.children == [new]
    assert old.ts_to == 105
    assert old.evtid_to == 0x4F
    assert new.args == ["sh", "-c", "true"]
    assert pstree.get_process_for_evtid(20, 0x4F) is old
    assert pstree.get_process_for_evtid(20, 0x50) is new


@pytest.mark.parametrize("fields", [{"Flags": "CLONE_VM|CLONE_THREAD"}, {"NewPid": 0}])
def test_linux_thread_and_failed_clone_ignored(fields):
    entry = clone(20, 30, 0x40, 104)
    entry.update(fields)
    pstree = tree(clone(), execute(), entry)
    assert [p.pid for p in pstree.processes] == [10, 20]


def test_linux_exit_status_and_thread_exit():
    thread_exit = event("do_exit", uid=0x50, ts=105, TID=21, ExitStatus=99)
    leader_exit = event(
        "do_exit", uid=0x60, ts=106, TID=20, ExitStatus=7, ExitStatusStr="7"
    )
    pstree = tree(clone(), execute(), thread_exit)
    assert pstree.get_process(20).ts_to is None
    pstree = tree(clone(), execute(), thread_exit, leader_exit)
    sample = pstree.get_process(20)
    assert (sample.ts_to, sample.exit_code, sample.exit_code_str) == (106, 7, "7")
    # File teardown can still be emitted after do_exit is entered.
    assert pstree.get_process_for_evtid(20, 0x61) is sample


def test_linux_early_child_events_resolve_to_next_birth():
    pstree = tree(clone(), execute(), clone(20, 30, 0x40, 104))
    assert pstree.get_process_for_evtid(30, 0x35) is pstree.get_process(30)
    assert pstree.get_process_for_evtid(999, 0x35) is None


def frame(protocol, source, destination, payload):
    ethernet = b"\x00" * 12 + b"\x08\x00"
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        0,
        0,
        64,
        protocol,
        0,
        socket.inet_aton(source),
        socket.inet_aton(destination),
    )
    return ethernet + ip + payload


def tcp(flags=2):
    return frame(
        6,
        "10.0.0.2",
        "203.0.113.8",
        struct.pack("!HHIIBBHHH", 40000, 443, 0, 0, 0x50, flags, 1024, 0, 0),
    )


def dns():
    query = struct.pack("!HHHHHH", 123, 0x100, 1, 0, 0, 0)
    query += b"\x06sample\x04test\x00" + struct.pack("!HH", 1, 1)
    return frame(
        17,
        "10.0.0.2",
        "8.8.8.8",
        struct.pack("!HHHH", 40001, 53, 8 + len(query), 0) + query,
    )


def write_pcap(path, endian="<", nano=False):
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    header = struct.pack(endian + "IHHIIII", magic, 2, 4, 0, 0, 65535, 1)
    frames = [tcp(), tcp(), tcp(0x12), tcp(0x10), dns()]
    with path.open("wb") as stream:
        stream.write(header)
        for packet in frames:
            fraction = 250_000_000 if nano else 250_000
            stream.write(
                struct.pack(endian + "IIII", 102, fraction, len(packet), len(packet))
            )
            stream.write(packet)


@pytest.mark.parametrize(
    "endian,nano", [("<", False), (">", False), ("<", True), (">", True)]
)
def test_pcap_tcp_syn_and_dns(tmp_path, endian, nano):
    path = tmp_path / "dump.pcap"
    write_pcap(path, endian, nano)
    result = summarize_pcap(path, "10.0.0.2")
    assert result == {
        "connections": [
            dict(
                protocol="tcp",
                local_ip="10.0.0.2",
                local_port=40000,
                remote_ip="203.0.113.8",
                remote_port=443,
                ts=102.25,
            ),
            dict(
                protocol="udp",
                local_ip="10.0.0.2",
                local_port=40001,
                remote_ip="8.8.8.8",
                remote_port=53,
                ts=102.25,
            ),
        ],
        "dns_queries": [
            dict(ts=102.25, domain="sample.test", server="8.8.8.8", local_port=40001)
        ],
    }
    assert summarize_pcap(path, "10.0.0.3") == {"connections": [], "dns_queries": []}


@pytest.mark.parametrize("content", [None, b"", b"bad", b"\xd4\xc3\xb2\xa1"])
def test_pcap_missing_or_incomplete_header(tmp_path, content):
    path = tmp_path / "dump.pcap"
    if content is not None:
        path.write_bytes(content)
    assert summarize_pcap(path) == {"connections": [], "dns_queries": []}


def write_log(directory, name, events):
    (directory / name).write_text("\n".join(json.dumps(e) for e in events) + "\n")


@pytest.fixture
def linux_context(tmp_path, base_config):
    options = AnalysisOptions.with_config_defaults(base_config, guest_os="linux")
    metadata = AnalysisMetadata(id="linux-test", options=options)
    metadata.model_extra["linux"] = {
        "agent": {"pid": 10},
        "network": {"addr": {"ens3": ["10.0.0.2"]}},
    }
    context = PostprocessContext(tmp_path, base_config, metadata)
    context.process_tree = tree(clone(), execute(), clone(20, 30, 0x40, 104))
    write_log(
        tmp_path,
        "filetracer.log",
        [
            event("vfs_write", FileName="/tmp/out"),
            event("vfs_write", FileName="/tmp/out"),  # report deduplicates paths
            event("vfs_mkdir", 30, 0x35, 103, FileName="/tmp/child"),
            event("vfs_unlink", FileName="/tmp/deleted"),
            event("vfs_rename", FileName="/tmp/new", old_name="/tmp/old"),
            event("vfs_symlink", FileName="/tmp/link", oldname="/tmp/out"),
            event("chmod_common", FileName="/tmp/out", Permissions="0755"),
            event("vfs_write", 10, FileName="/tmp/agent"),
            event("vfs_write", FileName="/tmp/.chimera-stdout"),
            event("vfs_write", 999, FileName="/tmp/unattributed"),
        ],
    )
    write_log(
        tmp_path,
        "syscall.log",
        [
            event("connect", addr="203.0.113.8:443"),
            event("sendto", 30, 0x35, 102, dest_addr="8.8.8.8:53"),
            event("connect", addr="[2001:db8::1]:80"),  # attempted, absent from pcap
            event("bind", addr="10.0.0.2:8080"),
            event("connect", addr="unix:/tmp/socket"),
            event("write", 10),
        ],
    )
    write_pcap(tmp_path / "dump.pcap")
    return context


@pytest.mark.parametrize("compressed", [False, True])
def test_linux_behaviour_report_and_attribution(linux_context, compressed):
    if compressed:
        for name in ("filetracer.log", "syscall.log"):
            path = linux_context.analysis_dir / name
            with gzip.open(path.with_name(name + ".gz"), "wb") as stream:
                stream.write(path.read_bytes())
            path.unlink()
    get_linux_behaviour_info(linux_context)
    report = linux_context.report
    modified = {e["filename"]: e["process_seqids"] for e in report["modified_files"]}
    assert modified == {
        "/tmp/child": [2],
        "/tmp/new": [1],
        "/tmp/out": [1],
        "/tmp/unattributed": [-1],
    }
    assert report["deleted_files"] == [
        {"filename": "/tmp/deleted", "process_seqids": [1]},
        {"filename": "/tmp/old", "process_seqids": [1]},
    ]
    assert report["dns_queries"] == [{"domain": "sample.test", "process_seqids": [2]}]
    assert [
        (c["remote_ip"], c["remote_port"], c["process_seqids"])
        for c in report["connections"]
    ] == [
        ("203.0.113.8", 443, [1]),
        ("8.8.8.8", 53, [2]),
        ("2001:db8::1", 80, [1]),
    ]
    assert report["linux"]["links"] == [
        dict(
            link="/tmp/link", target="/tmp/out", method="vfs_symlink", process_seqid=1
        ),
    ]
    assert report["linux"]["permission_changes"] == [
        dict(
            filename="/tmp/out",
            method="chmod_common",
            permissions="0755",
            process_seqid=1,
        ),
    ]
    assert report["linux"]["syscall_counts"] == {
        "1": {"connect": 3, "bind": 1},
        "2": {"sendto": 1},
    }
    assert all(e["seqid"] in (1, 2) for e in report["linux"]["network_syscalls"])
    assert report["linux"]["unix_sockets"] == [
        dict(path="/tmp/socket", method="connect", process_seqids=[1]),
    ]
    assert report["linux"]["fileless_execs"] == []


def test_linux_fileless_exec_is_named_and_reported(linux_context):
    # execve of a memfd: procmon has no image path
    memfd = event("do_execveat_common", 30, 0x45, 105, ImagePathName="(null)",
                  CommandLine="chimera-memfd")
    linux_context.process_tree = tree(clone(), execute(), clone(20, 30, 0x40, 104), memfd)
    child = linux_context.process_tree.processes[2]
    assert child.procname == "[fileless] chimera-memfd"
    get_linux_behaviour_info(linux_context)
    assert linux_context.report["linux"]["fileless_execs"] == [
        dict(process_seqid=2, pid=30, args=["chimera-memfd"]),
    ]


@pytest.mark.parametrize("compressed", [False, True])
def test_linux_classifier_uses_inject_subtree_syscalls_and_report(
    linux_context, compressed
):
    context = linux_context
    directory = context.analysis_dir
    get_linux_behaviour_info(context)
    context.metadata.store_to_file(directory / "metadata.json")
    (directory / "process_tree.json").write_text(
        json.dumps(context.process_tree.as_dict())
    )
    # Linux inject PID takes priority over stale Windows startup data.
    context.report["startup"] = {"pid": 10, "process": 0}
    context.report["connections"].extend(
        [
            {"remote_ip": "192.0.2.1", "remote_port": 80, "process_seqids": [0]},
            {"remote_ip": "192.0.2.2", "remote_port": 80, "process_seqids": []},
        ]
    )
    context.report["dns_queries"].extend(
        [
            {"domain": "background.test", "process_seqids": [0]},
            {"domain": "unattributed.test", "process_seqids": []},
        ]
    )
    (directory / "report.json").write_text(json.dumps(context.report))
    write_log(
        directory,
        "inject.log",
        [dict(Method="AgentExec", Status="Success", InjectedPid=20)],
    )
    write_log(
        directory,
        "syscall.log",
        [
            event("late", ts=105),
            event("child", 30, 0x35, 103),
            event("first", ts=102),
            event("late", ts=106),
            event("agent", 10),
            event("unknown", 999),
            event(None),
            event(""),
        ],
    )
    # Windows artifacts must have no effect on Linux features.
    write_log(directory, "apimon.log", [event("WindowsAPI", Event="api_called")])
    write_log(directory, "regmon.log", [event("NtSetValueKey", Key="Windows")])
    write_log(directory, "socketmon.log", [event("DnsQueryEx", DnsName="windows.test")])
    if compressed:
        path = directory / "syscall.log"
        with gzip.open(directory / "syscall.log.gz", "wb") as stream:
            stream.write(path.read_bytes())
        path.unlink()
    features = extract_features(directory)
    assert features["schema"] == "chimera-features/1"
    assert features["run"]["guest_os"] == "linux"
    assert features["processes"]["count"] == 2
    assert features["processes"]["max_depth"] == 1
    assert features["api_calls"] == {"late": 2, "child": 1, "first": 1}
    assert features["api_sequence"] == ["first", "child", "late", "late"]
    assert features["files"] == dict(
        created=0,
        written=3,
        deleted=2,
        paths=["/tmp/child", "/tmp/new", "/tmp/out", "/tmp/deleted", "/tmp/old"],
    )
    assert features["network"] == dict(
        dns_queries=["sample.test"],
        connections=3,
        remote_endpoints=["203.0.113.8:443", "8.8.8.8:53", "2001:db8::1:80"],
        http_requests=0,
    )
    assert features["registry"] == dict(
        set_value=0, create_key=0, delete=0, keys=[], autorun_touched=False
    )


def test_linux_classifier_sequence_bound_and_pid_reuse(linux_context):
    context = linux_context
    directory = context.analysis_dir
    # Reuse the agent PID outside the sample subtree; it must stay excluded.
    pstree = tree(
        clone(),
        execute(),
        event("do_exit", uid=0x100, ts=110, ExitStatus=0),
        clone(10, 20, 0x200, 120),
    )
    context.metadata.store_to_file(directory / "metadata.json")
    (directory / "process_tree.json").write_text(json.dumps(pstree.as_dict()))
    write_log(directory, "inject.log", [dict(Status="Success", InjectedPid=20)])
    write_log(
        directory,
        "syscall.log",
        [event(f"sys{i}", ts=102 + i / 10000) for i in reversed(range(2100))]
        + [event("reused", uid=0x201, ts=121)],
    )
    features = extract_features(directory)
    assert features["api_sequence"] == [f"sys{i}" for i in range(2000)]
    assert sum(features["api_calls"].values()) == 2100
    assert "reused" not in features["api_calls"]


def test_linux_classifier_without_inject_has_no_attributed_features(linux_context):
    directory = linux_context.analysis_dir
    linux_context.metadata.store_to_file(directory / "metadata.json")
    (directory / "process_tree.json").write_text(
        json.dumps(linux_context.process_tree.as_dict())
    )
    (directory / "report.json").write_text(json.dumps({"startup": {"process": 0}}))
    assert extract_features(directory)["processes"]["count"] == 0
