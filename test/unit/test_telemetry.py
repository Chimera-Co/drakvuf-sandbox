from types import SimpleNamespace

from drakrun.analyzer import telemetry
from drakrun.analyzer.postprocessing import postprocess
from drakrun.analyzer.postprocessing.plugins.plugin_base import PostprocessContext, PostprocessPlugin


def test_summarize_telemetry_classifies_plugin_outputs(tmp_path):
    (tmp_path / "procmon.log").write_text("{}\n")
    (tmp_path / "regmon.log").write_text("")
    (tmp_path / "memdump.log").write_text("{}\n")
    (tmp_path / "screenshots").mkdir()
    (tmp_path / "screenshots" / "screenshot_1.png").write_bytes(b"png")

    summary = telemetry.summarize_telemetry(
        tmp_path, ["procmon", "regmon", "socketmon", "memdump"], 0, False
    )

    assert summary["plugins"]["procmon"]["status"] == "produced"
    assert summary["plugins"]["regmon"]["status"] == "empty"
    assert summary["plugins"]["socketmon"]["status"] == "missing"
    assert summary["plugins"]["memdump"]["status"] == "produced"
    assert summary["plugins"]["memdump"]["dumps.zip"] == "missing"
    assert summary["missing_plugins"] == ["regmon", "socketmon"]
    assert summary["pcap"]["status"] == "missing"
    assert summary["screenshots"] == 1
    assert summary["drakvuf_returncode"] == 0
    assert summary["drakvuf_hard_timeout"] is False


def test_hard_timeout_and_unknown_returncode_are_recorded(tmp_path):
    (tmp_path / "procmon.log").write_text("x")
    summary = telemetry.summarize_telemetry(tmp_path, ["procmon", "regmon"], None, True)
    assert summary["missing_plugins"] == ["regmon"]
    assert summary["drakvuf_hard_timeout"] is True
    assert summary["drakvuf_returncode"] is None


def test_postprocess_records_ok_skipped_and_failed(monkeypatch, tmp_path):
    def ok_step(context):
        pass

    def broken_step(context):
        raise ValueError("boom")

    def needs_missing_file(context):
        raise AssertionError("must not run")

    monkeypatch.setattr(
        postprocess,
        "POSTPROCESS_PLUGINS",
        [
            PostprocessPlugin(function=ok_step, requires=[], generates=[]),
            PostprocessPlugin(function=broken_step, requires=[], generates=[]),
            PostprocessPlugin(function=needs_missing_file, requires=["nope.log"], generates=[]),
        ],
    )
    context = PostprocessContext(
        analysis_dir=tmp_path, config=None, metadata=SimpleNamespace(options=None)
    )
    postprocess.run_postprocessing(context)
    assert context.extra_metadata["postprocess"] == {
        "ok_step": "ok",
        "broken_step": "failed: ValueError",
        "needs_missing_file": "skipped",
    }
