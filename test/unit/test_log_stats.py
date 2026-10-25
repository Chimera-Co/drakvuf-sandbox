import io
import json

import pytest

from drakrun.lib import log_stats as core
from drakrun.web import log_stats


def stream(events):
    return io.BytesIO(b"\n".join(json.dumps(event).encode() for event in events))


def test_counts_malformed_and_histogram():
    data = stream(
        [
            {"TimeStamp": "10", "Method": "Write", "PID": 3, "FileName": "x"},
            {"TimeStamp": "11", "Method": "Write", "PID": 3, "FileName": "x"},
            {"TimeStamp": "12", "Method": "Read", "PID": 4},
        ]
    ).getvalue()
    result = log_stats.compute_stats(
        io.BytesIO(data + b"\ninvalid\n[]\n"), "filetracer"
    )
    assert result["total"] == 3
    assert result["parse_errors"] == 2
    assert result["methods"][0] == ["Write", 2]
    assert result["top_values"]["files"] == [["x", 2]]
    assert result["first_ts"] == 10
    assert result["last_ts"] == 12
    assert sum(result["histogram"]["counts"]) == 3
    assert len(result["histogram"]["counts"]) <= 120


def test_empty_and_invalid_timestamps():
    result = log_stats.compute_stats(stream([{"TimeStamp": "NaN"}, {}]), "regmon")
    assert result["first_ts"] is None
    assert result["histogram"]["counts"] == []
    assert result["total"] == 2
    assert log_stats.compute_stats(io.BytesIO(), "apimon")["total"] == 0


def test_bounded_values_and_oversized_line():
    result = log_stats.compute_stats(stream([{"Key": "x" * 10000}]), "regmon")
    assert len(result["top_values"]["keys"][0][0]) == 512
    result = log_stats.compute_stats(
        io.BytesIO(b"x" * (core.MAX_LINE + 1) + b"\n{}"), "regmon"
    )
    assert result["parse_errors"] == 1
    assert result["total"] == 1


def test_cache_invalidates_and_missing_file(tmp_path, monkeypatch):
    monkeypatch.setattr(log_stats.storage, "ANALYSES_DIR", tmp_path)
    monkeypatch.setattr(log_stats, "is_s3_enabled", lambda config: False)
    monkeypatch.setattr(log_stats.storage, "is_s3_enabled", lambda config: False)
    task = tmp_path / "task"
    task.mkdir()
    log = task / "regmon.log"
    log.write_text('{"Method":"Write","TimeStamp":1}\n')
    assert log_stats.get_stats("task", "regmon", None)["total"] == 1
    assert (task / "log_stats" / "regmon.json").exists()
    log.write_text(log.read_text() * 2)
    assert log_stats.get_stats("task", "regmon", None)["total"] == 2
    for name in ("missing", "../regmon", "a\\regmon"):
        with pytest.raises(FileNotFoundError):
            log_stats.get_stats("task", name, None)


def test_combined_histogram_preserves_totals():
    results = {
        "a": log_stats.compute_stats(stream([{"TimeStamp": 1}, {"TimeStamp": 9}]), "a"),
        "b": log_stats.compute_stats(stream([{"TimeStamp": 5}]), "b"),
    }
    result = log_stats.combine(results)
    assert result["logs"] == {"a": 2, "b": 1}
    assert sum(result["histogram"]["counts"]) == 3
    assert result["first_ts"] == 1


def test_plain_text_is_not_a_parse_error():
    result = log_stats.compute_stats(io.BytesIO(b"INFO ready\nWARN done\n"), "drakrun")
    assert result["total"] == 2
    assert result["parse_errors"] == 0


def test_s3_stream_and_unwritable_cache(monkeypatch, tmp_path):
    from contextlib import contextmanager

    @contextmanager
    def opened(*args):
        yield stream([{"Method": "NtSetValueKey", "Key": "x", "TimeStamp": 2}])

    monkeypatch.setattr(
        log_stats.storage, "list_analysis_logs", lambda *args: ["regmon.log"]
    )
    monkeypatch.setattr(log_stats.storage, "open_seekable_stream", opened)
    monkeypatch.setattr(log_stats, "is_s3_enabled", lambda config: True)
    result = log_stats.get_stats("task", "regmon", object())
    assert result["registry_writes"] == 1
    assert result["total"] == 1


def test_high_cardinality_keeps_exact_counts():
    records = [{"Method": f"method-{i}"} for i in range(5000)]
    records.extend({"Method": "frequent"} for _ in range(60))
    result = log_stats.compute_stats(stream(records), "apimon")
    assert len(result["methods"]) == 50
    assert result["methods"][0] == ["frequent", 60]


def test_unwritable_cache_still_computes(tmp_path, monkeypatch):
    monkeypatch.setattr(log_stats.storage, "ANALYSES_DIR", tmp_path)
    monkeypatch.setattr(log_stats, "is_s3_enabled", lambda config: False)
    monkeypatch.setattr(log_stats.storage, "is_s3_enabled", lambda config: False)
    task = tmp_path / "task"
    task.mkdir()
    (task / "regmon.log").write_text('{"Method":"NtSetValueKey"}\n')

    def denied(*args):
        raise PermissionError("read-only storage")

    monkeypatch.setattr(core.os, "replace", denied)
    assert log_stats.get_stats("task", "regmon", None)["total"] == 1
    assert not list(task.glob("log_stats/.tmp-*"))


def test_counter_pruning_marks_result_approximate(monkeypatch):
    monkeypatch.setattr(core, "MAX_DISTINCT", 100)
    monkeypatch.setattr(core, "PRUNE_TO", 20)
    records = [{"Method": "hot"} for _ in range(50)] + [{"Method": f"m{i}"} for i in range(300)]
    result = log_stats.compute_stats(stream(records), "apimon")
    assert result["approximate"] is True
    assert result["methods"][0] == ["hot", 50]


def test_precompute_writes_every_log(tmp_path):
    (tmp_path / "regmon.log").write_text('{"Method":"NtSetValueKey","TimeStamp":1}\n')
    (tmp_path / "drakrun.log").write_text("INFO a\nINFO b\n")
    assert core.precompute(tmp_path) == {"drakrun": 2, "regmon": 1}
    assert core.read_cache(tmp_path, "regmon")["registry_writes"] == 1
