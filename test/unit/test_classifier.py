"""Classifier contract, attribution, streaming bounds and postprocess integration."""

import json
import time
from types import SimpleNamespace

import pytest

from drakrun.analyzer.analysis_metadata import AnalysisMetadata, FileMetadata
from drakrun.analyzer.analysis_options import AnalysisOptions
from drakrun.analyzer.classifier.features import extract_features
from drakrun.analyzer.classifier.runner import run_classifier
from drakrun.analyzer.postprocessing import postprocess
from drakrun.analyzer.postprocessing.plugins import POSTPROCESS_PLUGINS
from drakrun.analyzer.postprocessing.plugins.classify_sample import classify_sample
from drakrun.analyzer.postprocessing.plugins.generate_report import generate_report
from drakrun.analyzer.postprocessing.plugins.plugin_base import (
    PostprocessContext,
    PostprocessPlugin,
)


def write_json(directory, name, value):
    (directory / name).write_text(json.dumps(value))


def write_log(directory, name, events):
    (directory / name).write_text("\n".join(json.dumps(e) for e in events) + "\n")


def node(seqid, pid, children=None, **extra):
    return {
        "seqid": seqid,
        "pid": pid,
        "ppid": 4,
        "procname": f"p{pid}.exe",
        "args": [f"p{pid}.exe", "--arg"],
        "ts_from": 100,
        "ts_to": None,
        "evtid_from": 0,
        "evtid_to": None,
        "children": children or [],
        **extra,
    }


@pytest.fixture
def analysis(tmp_path):
    child = node(2, 20, ppid=10, evtid_from=10)
    sample = node(1, 10, [child], evtid_to=99, ts_to=110)
    reused = node(3, 10, evtid_from=100, ts_from=111)
    write_json(tmp_path, "process_tree.json", [node(0, 4, [sample]), reused])
    write_json(
        tmp_path,
        "metadata.json",
        {
            "file": {
                "sha256": "abc",
                "name": "sample.exe",
                "type": "PE32",
                "size_bytes": 123,
            },
            "options": {"timeout": 60},
            "telemetry": {"complete": True, "vm_stalled": False, "drakvuf_errors": []},
        },
    )
    write_json(tmp_path, "report.json", {"startup": {"pid": 10, "process": 1}})
    return tmp_path


def event(pid=10, evtid="0x20", **extra):
    return {"PID": pid, "EventUID": evtid, "TimeStamp": "101", **extra}


def test_features_scope_all_sections_and_pid_reuse(analysis):
    write_log(
        analysis,
        "apimon.log",
        [
            event(Event="api_called", Method="Root", TimeStamp="103"),
            event(20, Event="api_called", Method="Child", TimeStamp="102"),
            event(4, Event="api_called", Method="Background"),
            event(evtid="0x101", Event="api_called", Method="Reused"),
            event(Event="dll_loaded", Method="Ignored"),
        ],
    )
    write_log(
        analysis,
        "filetracer.log",
        [
            event(
                Method="NtCreateFile", IoStatusBlock=2, Status="0x0", FileName="created"
            ),
            event(Method="NtCreateFile", IoStatusBlock=1, FileName="opened"),
            event(Method="NtCreateFile", IoStatusBlock=2, Status="0xc0000001"),
            event(20, Method="NtWriteFile", FileName="written"),
            event(
                Method="NtSetInformationFile",
                Operation="FileDispositionInformation",
                FileName="deleted",
            ),
            event(4, Method="NtWriteFile", FileName="background"),
            event(evtid="0x101", Method="NtWriteFile", FileName="reused"),
        ],
    )
    key = r"\REGISTRY\USER\sid\Software\Microsoft\Windows\CurrentVersion\Run"
    write_log(
        analysis,
        "regmon.log",
        [
            event(Method="NtSetValueKey", Key=key),
            event(20, Method="NtCreateKey", Key="child"),
            event(Method="NtDeleteValueKey", Key="deleted"),
            event(4, Method="NtSetValueKey", Key="background"),
        ],
    )
    write_log(
        analysis,
        "socketmon.log",
        [
            event(Method="DnsQueryEx", DnsName="sample.test"),
            event(
                20,
                Method="TcpCreateAndConnectTcbComplete",
                RemoteIp="1.2.3.4",
                RemotePort=443,
            ),
            event(4, Method="DnsQueryEx", DnsName="background.test"),
        ],
    )
    report = json.loads((analysis / "report.json").read_text())
    report.update(
        {
            "http_requests": [{"process_seqid": 2}, {"process_seqid": 0}, {}],
            "ttps": [
                {"name": "child ttp", "att&ck": ["T1234"], "process_seqids": [2]},
                {"name": "background", "process_seqids": [0]},
                {"name": "unattributed"},
            ],
        }
    )
    write_json(analysis, "report.json", report)
    features = extract_features(analysis)
    assert features["schema"] == "chimera-features/1"
    assert features["sample"] == {
        "sha256": "abc",
        "file_name": "sample.exe",
        "file_type": "PE32",
        "size_bytes": 123,
    }
    assert features["run"]["complete"] is True
    assert features["run"]["timeout_s"] == 60
    assert features["processes"] == {
        "count": 2,
        "max_depth": 1,
        "names": ["p10.exe", "p20.exe"],
        "command_lines": ["p10.exe --arg", "p20.exe --arg"],
        "exited_early": True,
    }
    assert features["api_calls"] == {"Root": 1, "Child": 1}
    assert features["api_sequence"] == ["Child", "Root"]
    assert features["files"] == {
        "created": 1,
        "written": 1,
        "deleted": 1,
        "paths": ["created", "opened", "written", "deleted"],
    }
    assert features["registry"] == {
        "set_value": 1,
        "create_key": 1,
        "delete": 1,
        "keys": [key, "child", "deleted"],
        "autorun_touched": True,
    }
    assert features["network"] == {
        "dns_queries": ["sample.test"],
        "connections": 1,
        "remote_endpoints": ["1.2.3.4:443"],
        "http_requests": 1,
    }
    assert features["ttps"] == [{"name": "child ttp", "attack": ["T1234"]}]


def test_inject_fallback_and_jsonl_ttps(analysis):
    (analysis / "report.json").unlink()
    write_json(analysis, "inject.log", {"Status": "Success", "InjectedPid": 10})
    write_log(
        analysis,
        "ttps.json",
        [
            {
                "name": "child",
                "att&ck": ["T1"],
                "occurrences": [{"pid": 20, "ppid": 10}],
            },
            {"name": "host", "occurrences": [{"pid": 4, "ppid": 0}]},
            {"name": "unknown", "occurrences": [{}]},
        ],
    )
    features = extract_features(analysis)
    assert features["processes"]["count"] == 2
    assert features["ttps"] == [{"name": "child", "attack": ["T1"]}]


def test_timestamp_scoping_and_ambiguous_pid(analysis):
    write_log(
        analysis,
        "apimon.log",
        [
            {"PID": 10, "TimeStamp": "105", "Event": "api_called", "Method": "Sample"},
            {"PID": 10, "TimeStamp": "112", "Event": "api_called", "Method": "Reused"},
            {"PID": 10, "Event": "api_called", "Method": "Ambiguous"},
        ],
    )
    assert extract_features(analysis)["api_calls"] == {"Sample": 1}


def test_missing_files_and_unidentified_sample_never_scope_to_host(tmp_path):
    empty = extract_features(tmp_path)
    assert set(empty) == {
        "schema",
        "sample",
        "run",
        "processes",
        "api_calls",
        "api_sequence",
        "files",
        "registry",
        "network",
        "ttps",
    }
    assert empty["processes"]["count"] == 0
    assert empty["run"]["complete"] is False
    assert empty["api_calls"] == {}
    write_json(tmp_path, "process_tree.json", [node(0, 4)])
    write_log(tmp_path, "apimon.log", [event(4, Event="api_called", Method="Host")])
    assert extract_features(tmp_path) == empty


@pytest.mark.parametrize(
    "name", ["report.json", "metadata.json", "process_tree.json", "inject.log"]
)
def test_malformed_documents_are_tolerated(tmp_path, name):
    (tmp_path / name).write_text("{broken")
    assert extract_features(tmp_path)["processes"]["count"] == 0
    write_json(tmp_path, name, [None, 2, "oops"])
    assert extract_features(tmp_path)["processes"]["count"] == 0


def test_malformed_lines_do_not_drop_valid_following_events(analysis):
    bad = 'garbage\n[]\nnull\n42\n{"PID": {}}\n{"PID":10,"Method":[]}\n'
    for name, valid in [
        ("apimon.log", event(Event="api_called", Method="Good")),
        ("regmon.log", event(Method="NtSetValueKey", Key="good")),
        ("filetracer.log", event(Method="NtWriteFile", FileName="good")),
        ("socketmon.log", event(Method="DnsQueryEx", DnsName="good")),
    ]:
        (analysis / name).write_bytes(
            bad.encode() + b"\xff\n" + json.dumps(valid).encode() + b"\n"
        )
    features = extract_features(analysis)
    assert features["api_calls"] == {"Good": 1}
    assert features["registry"]["set_value"] == 1
    assert features["files"]["written"] == 1
    assert features["network"]["dns_queries"] == ["good"]


def test_lists_bounded_and_api_sequence_earliest_not_file_order(analysis):
    write_log(
        analysis,
        "apimon.log",
        [
            event(Event="api_called", Method=f"Api{i}", TimeStamp=str(i))
            for i in reversed(range(2100))
        ],
    )
    write_log(
        analysis,
        "regmon.log",
        [event(Method="NtSetValueKey", Key=f"key{i}") for i in range(120)],
    )
    write_log(
        analysis,
        "filetracer.log",
        [event(Method="NtWriteFile", FileName=f"file{i}") for i in range(120)],
    )
    write_log(
        analysis,
        "socketmon.log",
        [event(Method="DnsQueryEx", DnsName=f"domain{i}") for i in range(120)]
        + [
            event(Method="UdpSendMessages", RemoteIp=f"ip{i}", RemotePort=53)
            for i in range(120)
        ],
    )
    tree = [node(1, 10, [node(i + 2, i + 20, ppid=10) for i in range(60)])]
    write_json(analysis, "process_tree.json", tree)
    features = extract_features(analysis)
    assert features["api_sequence"] == [f"Api{i}" for i in range(2000)]
    assert sum(features["api_calls"].values()) == 2100
    assert features["registry"]["set_value"] == 120
    for values in (
        features["files"]["paths"],
        features["registry"]["keys"],
        features["network"]["dns_queries"],
        features["network"]["remote_endpoints"],
    ):
        assert len(values) == 100
    assert len(features["processes"]["names"]) == 50
    assert len(features["processes"]["command_lines"]) == 50


def test_scoped_report_network_fallback(analysis):
    report = {
        "startup": {"process": 1},
        "connections": [
            {"process_seqids": [2], "remote_ip": "::1", "remote_port": 80},
            {"process_seqids": [0]},
        ],
        "dns_queries": [
            {"process_seqids": [1], "domain": "sample.test"},
            {"domain": "unknown"},
        ],
    }
    write_json(analysis, "report.json", report)
    features = extract_features(analysis)
    assert features["network"]["connections"] == 1
    assert features["network"]["dns_queries"] == ["sample.test"]


GOOD_MODEL = """
def classify(features: dict, analysis_dir: str) -> dict:
    assert features["schema"] == "chimera-features/1"
    assert isinstance(analysis_dir, str)
    print("model diagnostics")
    return {"label": "benign", "score": 0.25, "family": None,
            "model": "test-model", "model_version": "42", "explanation": ["test"]}
"""


def test_runner_good_model(analysis):
    model = analysis / "model.py"
    model.write_text(GOOD_MODEL)
    verdict = run_classifier(extract_features(analysis), analysis, model)
    assert verdict == {
        "schema": "chimera-verdict/1",
        "label": "benign",
        "score": 0.25,
        "family": None,
        "model": "test-model",
        "model_version": "42",
        "explanation": ["test"],
    }


@pytest.mark.parametrize(
    "source,expected",
    [
        (
            'def classify(features, analysis_dir):\n    raise RuntimeError("boom")',
            "RuntimeError: boom",
        ),
        ('raise RuntimeError("import failed")', "RuntimeError: import failed"),
        ("classify = 12", "TypeError"),
        (
            'def classify(features, analysis_dir):\n    return {"label": "evil"}',
            "ValidationError",
        ),
        (GOOD_MODEL.replace("0.25", "1.1"), "ValidationError"),
        (GOOD_MODEL.replace("0.25", 'float("nan")'), "ValidationError"),
        (GOOD_MODEL.replace("0.25", "True"), "ValidationError"),
        (GOOD_MODEL.replace('["test"]', "[1]"), "ValidationError"),
    ],
)
def test_runner_errors_contained(analysis, source, expected):
    model = analysis / "model.py"
    model.write_text(source)
    verdict = run_classifier(extract_features(analysis), analysis, model)
    assert verdict["label"] == "unknown"
    assert expected in verdict["error"]


def test_runner_timeout(analysis):
    model = analysis / "slow.py"
    model.write_text(
        "import time\ndef classify(features, analysis_dir):\n    time.sleep(20)"
    )
    start = time.monotonic()
    verdict = run_classifier(extract_features(analysis), analysis, model, timeout_s=0.2)
    assert verdict["label"] == "unknown"
    assert "timed out" in verdict["error"]
    assert time.monotonic() - start < 3


@pytest.mark.parametrize("model_path", [None, "does-not-exist.py"])
def test_stub_fallback_is_explicit(analysis, model_path):
    verdict = run_classifier(extract_features(analysis), analysis, model_path)
    assert verdict["model"] == "chimera-stub"
    assert any("not a trained model" in line for line in verdict["explanation"])


def context_for(directory, config):
    metadata = AnalysisMetadata(
        id="test", options=AnalysisOptions(plugins=[], net_enable=False, timeout=60)
    )
    return PostprocessContext(directory, config, metadata)


def test_disabled_no_artifacts_and_skipped_outcome(analysis, base_config, monkeypatch):
    context = context_for(analysis, base_config)
    classify_sample(context)
    monkeypatch.setattr(
        postprocess, "POSTPROCESS_PLUGINS", [PostprocessPlugin(classify_sample, [], [])]
    )
    postprocess.run_postprocessing(context)
    assert context.extra_metadata == {"postprocess": {"classify_sample": "skipped"}}
    assert not (analysis / "features.json").exists()
    assert not (analysis / "classification.json").exists()


def test_enabled_artifacts_metadata_and_live_telemetry(
    analysis, config_factory, monkeypatch
):
    config = config_factory("[classifier]\nenabled = true\n")
    context = context_for(analysis, config)
    context.metadata.model_extra["telemetry"] = {
        "complete": False,
        "vm_stalled": True,
        "drakvuf_errors": ["test error"],
    }
    context.report["startup"] = {"process": 1}
    monkeypatch.setattr(
        postprocess,
        "POSTPROCESS_PLUGINS",
        [
            PostprocessPlugin(generate_report, [], []),
            PostprocessPlugin(classify_sample, [], []),
        ],
    )
    postprocess.run_postprocessing(context)
    verdict = json.loads((analysis / "classification.json").read_text())
    assert verdict == context.extra_metadata["classification"]
    features = json.loads((analysis / "features.json").read_text())
    assert features["run"]["vm_stalled"] is True
    assert features["run"]["complete"] is False
    assert features["run"]["drakvuf_errors"] == ["test error"]
    assert context.extra_metadata["postprocess"]["classify_sample"] == "ok"
    # Reprocessing must restore extra metadata even when artifacts already exist.
    context.extra_metadata.clear()
    postprocess.run_postprocessing(context)
    assert context.extra_metadata["classification"]["model"] == "chimera-stub"


def test_model_error_does_not_fail_postprocessing(
    analysis, config_factory, monkeypatch
):
    config = config_factory("[classifier]\nenabled = true\n")
    model = analysis / "model.py"
    model.write_text(
        'def classify(features, analysis_dir):\n    raise ValueError("bad model")'
    )
    config.classifier.model_path = model
    context = context_for(analysis, config)
    monkeypatch.setattr(
        postprocess, "POSTPROCESS_PLUGINS", [PostprocessPlugin(classify_sample, [], [])]
    )
    postprocess.run_postprocessing(context)
    assert context.extra_metadata["classification"]["label"] == "unknown"
    assert context.extra_metadata["postprocess"]["classify_sample"] == "ok"


def test_classifier_registration_follows_producers():
    names = [plugin.function.__name__ for plugin in POSTPROCESS_PLUGINS]
    assert all(
        names.index(producer) < names.index("classify_sample")
        for producer in (
            "build_process_tree",
            "capa_analysis",
            "get_ttps_info",
            "generate_report",
        )
    )


def test_sample_size_captured_at_upload(tmp_path, monkeypatch):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ-test")
    monkeypatch.setattr(
        "drakrun.analyzer.analysis_metadata.magic.from_file", lambda _: "PE32"
    )
    assert FileMetadata.evaluate(sample).size_bytes == 7


def test_large_logs_are_consumed_only_by_line(analysis, monkeypatch):
    write_log(analysis, "apimon.log", [event(Event="api_called", Method="Good")])
    write_log(analysis, "regmon.log", [event(Method="NtSetValueKey", Key="good")])
    write_log(
        analysis, "filetracer.log", [event(Method="NtWriteFile", FileName="good")]
    )
    write_log(analysis, "socketmon.log", [event(Method="DnsQueryEx", DnsName="good")])
    original_open = type(analysis).open
    streamed = set()

    class LinesOnly:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()

        def __iter__(self):
            return iter(self.stream)

        def read(self, *args):
            raise AssertionError("bulk log reads are forbidden")

        def readlines(self, *args):
            raise AssertionError("bulk log reads are forbidden")

    def guarded_open(path, *args, **kwargs):
        stream = original_open(path, *args, **kwargs)
        if path.name in {"apimon.log", "regmon.log", "filetracer.log", "socketmon.log"}:
            streamed.add(path.name)
            return LinesOnly(stream)
        return stream

    monkeypatch.setattr(type(analysis), "open", guarded_open)
    assert extract_features(analysis)["api_calls"] == {"Good": 1}
    assert streamed == {"apimon.log", "regmon.log", "filetracer.log", "socketmon.log"}


def _dns_pcap(path, names, dst="10.99.0.2"):
    import socket
    import struct

    out = [struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)]
    for index, name in enumerate(names):
        query = struct.pack("!HHHHHH", index, 0x100, 1, 0, 0, 0)
        query += b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
        query += struct.pack("!HH", 1, 1)
        udp = struct.pack("!HHHH", 40000 + index, 53, 8 + len(query), 0) + query
        ip = struct.pack(
            "!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
            socket.inet_aton("10.99.0.3"), socket.inet_aton(dst),
        )
        packet = b"\x00" * 12 + b"\x08\x00" + ip + udp
        out.append(struct.pack("<IIII", 100 + index, 0, len(packet), len(packet)) + packet)
    path.write_bytes(b"".join(out))


def _udp53(local_port, remote="10.99.0.2", **extra):
    return event(
        Method="UdpSendMessages", RemoteIp=remote, RemotePort=53, LocalPort=local_port, **extra
    )


def test_windows_dns_from_pcap_only_for_sample_flows(analysis):
    # Query i is sent from port 40000+i; only ports 40000 and 40002 belong to the sample.
    names = ["Elevated-Yes.probe.example", "fs.microsoft.com", "elevated-yes.probe.example", "hooked.test"]
    _dns_pcap(analysis / "dump.pcap", names)
    write_log(
        analysis,
        "socketmon.log",
        [
            event(Method="DnsQueryEx", DnsName="hooked.TEST"),
            _udp53(40000),
            _udp53(40002),
            _udp53(40001, PID=999),  # another process: not attributed
            _udp53(40003, remote="10.99.0.9"),  # same port, different server
        ],
    )
    assert extract_features(analysis)["network"]["dns_queries"] == [
        "hooked.TEST",
        "elevated-yes.probe.example",
    ]


def test_windows_dns_pcap_cap_and_missing_ports(analysis):
    _dns_pcap(analysis / "dump.pcap", [f"h{i}.example" for i in range(150)])
    write_log(analysis, "socketmon.log", [_udp53(40000 + i) for i in range(150)])
    assert len(extract_features(analysis)["network"]["dns_queries"]) == 100
    # No local port recorded, or no socketmon.log: capture names cannot be attributed.
    write_log(analysis, "socketmon.log", [event(Method="UdpSendMessages", RemoteIp="10.99.0.2", RemotePort=53)])
    assert extract_features(analysis)["network"]["dns_queries"] == []
    (analysis / "socketmon.log").unlink()
    assert extract_features(analysis)["network"]["dns_queries"] == []


def test_windows_dns_bad_pcap(analysis):
    write_log(analysis, "socketmon.log", [_udp53(40000)])
    (analysis / "dump.pcap").write_bytes(b"garbage")
    assert extract_features(analysis)["network"]["dns_queries"] == []
