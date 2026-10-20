"""Process cores need no Xen guest for command, log, and archive checks."""

import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from drakrun.analyzer.analysis_metadata import AnalysisMetadata
from drakrun.analyzer.analysis_options import AnalysisOptions
from drakrun.analyzer.linux_analyzer import linux_drakvuf_cmdline, linux_plugins
from drakrun.analyzer.postprocessing.plugins.plugin_base import PostprocessContext
from drakrun.analyzer.postprocessing.plugins.process_dumps import (
    parse_linux_procdump,
    process_dumps,
    process_linux_dumps,
)
from drakrun.analyzer.postprocessing.process_tree import ProcessTree
from drakrun.analyzer.telemetry import summarize_telemetry


def test_linux_dump_command(tmp_path):
    plugins = linux_plugins(["memdump", "procdump2", "cpuidmon"])
    assert plugins.count("procdump2") == 1
    assert "procdump2" in linux_plugins([])
    assert "memdump" not in plugins
    command = linux_drakvuf_cmdline("vm-1", Path("kernel.json"), plugins, 60, tmp_path)
    assert command[command.index("--procdump-dir") + 1] == str(tmp_path / "dumps")
    assert (tmp_path / "dumps").is_dir()
    assert "--procdump-use-maple-tree" in command
    assert "--procdump-new-processes-on-finish" in command
    assert command[command.index("--procdump-timeout") + 1] == "10"
    assert "--compress-procdumps" not in command
    other = tmp_path / "without-plugin"
    other.mkdir()
    command = linux_drakvuf_cmdline("vm-1", Path("kernel.json"), ["procmon"], 60, other)
    assert not any(arg.startswith("--procdump") for arg in command)
    assert not (other / "dumps").exists()


def success(sn=0, pid=20, timestamp=102, size=64, reason="TerminateProcess"):
    # linux.cpp print_dump_info uses synthetic EventUID=0, numeric size/SN,
    # and does not emit a filename or useful Method.
    return dict(
        Plugin="procdump",
        EventUID="0x0",
        TimeStamp=str(timestamp),
        PID=pid,
        TargetPID=pid,
        TargetName="/tmp/sample",
        DumpReason=reason,
        DumpSize=size,
        SN=sn,
        Status="Success",
    )


@pytest.mark.parametrize("reason", ["TerminateProcess", "FinishAnalysis"])
def test_linux_success_parser(reason):
    parsed = parse_linux_procdump(success(reason=reason))
    assert parsed == dict(
        index=0,
        filename="procdump.0",
        pid=20,
        process_name="/tmp/sample",
        dump_reason=reason,
        size=64,
        timestamp=102.0,
    )
    assert (
        parse_linux_procdump({"Plugin": "procdump_fail", "Message": "Timeout"}) is None
    )
    assert parse_linux_procdump({"Status": "Error"}) is None
    with pytest.raises(ValueError):
        parse_linux_procdump(success(sn=-1))


@pytest.fixture
def dump_context(tmp_path, base_config):
    context = PostprocessContext(
        tmp_path,
        base_config,
        AnalysisMetadata(
            id="linux-dumps",
            options=AnalysisOptions.with_config_defaults(base_config, guest_os="linux"),
        ),
    )
    tree = ProcessTree()
    agent = tree.add_process(10, 1, 0, 0, "agent", None)
    old = tree.add_process(20, 1, 0, 0, "old-process", None)
    old.ts_to, old.evtid_to = 90, 5
    sample = tree.add_process(20, 10, 10, 100, "/tmp/sample", agent)
    child = tree.add_process(30, 20, 20, 101, "/tmp/child", sample)
    sample.ts_to, sample.evtid_to = 101.5, 30
    child.ts_to, child.evtid_to = 102, 31
    # PID reuse after the sample died must not receive the sample's core.
    tree.add_process(20, 1, 40, 110, "background", None)
    context.process_tree = tree
    (tmp_path / "dumps").mkdir()
    (tmp_path / "process_tree.json").write_text(json.dumps(tree.as_dict()))
    (tmp_path / "inject.log").write_text(
        json.dumps(dict(Status="Success", InjectedPid=20)) + "\n"
    )
    context.config.memdump.min_single_dump_size = 1
    return context


def write_dumps(context, events, log_name="procdump.log"):
    path = context.analysis_dir
    for event in events:
        (path / "dumps" / f"procdump.{event['SN']}").write_bytes(
            b"\x7fELF" + b"x" * (event["DumpSize"] - 4)
        )
    (path / log_name).write_text("\n".join(json.dumps(e) for e in events) + "\n")


def test_linux_zip_metadata_and_pid_reuse(dump_context, caplog):
    context = dump_context
    write_dumps(
        context,
        [
            success(),
            success(1, 30, 103, reason="FinishAnalysis"),
            success(2, 10),
            success(3, 20, 111),
            success(4, 999),
        ],
    )
    log = context.analysis_dir / "procdump.log"
    with log.open("a") as stream:
        stream.write('bad json\n{"Status":"Success"}\n')
        stream.write(json.dumps(success()) + "\n")  # duplicate success
        stream.write(json.dumps(success(99)) + "\n")  # missing file
    original = (context.analysis_dir / "dumps/procdump.0").read_bytes()
    process_linux_dumps(context)
    metadata = context.extra_metadata["dumps_metadata"]
    assert [m["filename"] for m in metadata] == ["dumps/procdump.0", "dumps/procdump.1"]
    assert [(m["pid"], m["process_seqid"]) for m in metadata] == [(20, 2), (30, 3)]
    assert metadata[0]["process_name"] == "/tmp/sample"
    assert metadata[0]["size"] == len(original)
    assert metadata[0]["sha256"] == hashlib.sha256(original).hexdigest()
    assert [m["dump_reason"] for m in metadata] == [
        "TerminateProcess",
        "FinishAnalysis",
    ]
    with zipfile.ZipFile(context.analysis_dir / "dumps.zip") as archive:
        assert archive.namelist() == [m["filename"] for m in metadata]
        assert archive.read(metadata[0]["filename"]) == original
    assert [p["process_seqid"] for p in context.report["memdumps"]] == [2, 3]
    assert not (context.analysis_dir / "dumps").exists()
    assert "Failed to parse line" in caplog.text
    assert "Linux dump missing" in caplog.text


def test_linux_strict_size_caps_and_partial_files(dump_context):
    context = dump_context
    context.config.memdump.min_single_dump_size = 8
    context.config.memdump.max_single_dump_size = 64
    context.config.memdump.max_total_dumps_size = 96
    write_dumps(
        context,
        [
            success(0, size=4),
            success(1, size=65),
            success(2, size=64),
            success(3, size=64),
            success(4, size=32),
            success(5, size=16),
        ],
    )
    # A Success line alone must not make a truncated file acceptable.
    (context.analysis_dir / "dumps/procdump.5").write_bytes(b"partial")
    process_linux_dumps(context)
    metadata = context.extra_metadata["dumps_metadata"]
    assert [m["index"] for m in metadata] == [2, 4]
    assert sum(m["size"] for m in metadata) == 96


@pytest.mark.parametrize("log_name", ["procdump.log", "procdump2.log"])
def test_linux_unknown_sample_tree_retains_unmatched_dumps(
    dump_context, log_name, caplog
):
    context = dump_context
    (context.analysis_dir / "inject.log").unlink()
    write_dumps(context, [success(pid=999)], log_name)
    process_linux_dumps(context)
    assert context.extra_metadata["dumps_metadata"][0]["process_seqid"] is None
    assert context.report["memdumps"][0]["process_seqid"] == -1
    assert "sample tree unavailable" in caplog.text


@pytest.mark.parametrize("empty_log", [False, True])
def test_linux_no_successful_dumps(dump_context, empty_log):
    context = dump_context
    if empty_log:
        (context.analysis_dir / "procdump.log").write_text("")
    process_linux_dumps(context)
    assert context.extra_metadata["dumps_metadata"] == []
    assert context.report["memdumps"] == []
    with zipfile.ZipFile(context.analysis_dir / "dumps.zip") as archive:
        assert archive.namelist() == ["dumps/"]


def test_linux_dump_pipeline_and_telemetry(dump_context, monkeypatch):
    import drakrun.analyzer.postprocessing.postprocess as pipeline

    context = dump_context
    write_dumps(context, [success()])
    monkeypatch.setattr(
        pipeline,
        "POSTPROCESS_PLUGINS",
        [
            p
            for p in pipeline.POSTPROCESS_PLUGINS
            if p.function.__name__
            in ("process_dumps", "process_linux_dumps", "capa_analysis")
        ],
    )
    pipeline.run_postprocessing(context)
    assert context.extra_metadata["postprocess"] == {
        "capa_analysis": "skipped",
        "process_dumps": "skipped",
        "process_linux_dumps": "ok",
    }
    summary = summarize_telemetry(context.analysis_dir, ["procdump2"], 0, False)
    assert summary["plugins"]["procdump2"]["status"] == "produced"
    assert summary["plugins"]["procdump2"]["dumps.zip"] == "produced"


def test_windows_dump_output_unchanged(dump_context):
    context = dump_context
    context.options.guest_os = "windows"
    contents = b"windows-region"
    (context.analysis_dir / "dumps/memdump.000001").write_bytes(contents)
    (context.analysis_dir / "dumps/memdump.000001.metadata").write_text("{}")
    (context.analysis_dir / "memdump.log").write_text(
        json.dumps(
            dict(
                PID=20,
                EventUID="0xa",
                DumpsCount=1,
                DumpReason="test",
                Method="NtWriteVirtualMemory",
                DumpAddr="0x1000",
                DumpSize=hex(len(contents)),
                DumpFilename="memdump.000001",
            )
        )
        + "\n"
    )
    process_dumps(context)
    assert context.extra_metadata["dumps_metadata"] == [
        {"filename": "dumps/memdump.000001", "base_address": "0x1000"},
    ]
    with zipfile.ZipFile(context.analysis_dir / "dumps.zip") as archive:
        assert archive.read("dumps/memdump.000001") == contents
    assert context.report["memdumps"][0]["process_seqid"] == 2
