"""Log summaries for the analysis page (computation and cache: drakrun/lib/log_stats.py)."""

import tempfile

from drakrun.lib import log_stats as core
from drakrun.lib.log_stats import compute_stats
from drakrun.lib.s3_storage import is_s3_enabled
from drakrun.web import storage


def get_stats(task_uid, log_type, s3_config):
    if (
        not log_type
        or "/" in log_type
        or "\\" in log_type
        or f"{log_type}.log" not in storage.list_analysis_logs(task_uid, s3_config)
    ):
        raise FileNotFoundError(log_type)
    if is_s3_enabled(s3_config):
        with storage.open_seekable_stream(
            task_uid, f"{log_type}.log", s3_config
        ) as stream:
            return compute_stats(stream, log_type)
    base = storage.ANALYSES_DIR / task_uid
    storage.check_path(base / f"{log_type}.log", base)
    cached = core.read_cache(base, log_type)
    if cached is not None:
        return cached
    with (base / f"{log_type}.log").open("rb") as stream:
        result = compute_stats(stream, log_type)
    try:
        core.write_cache(base, log_type, result)
    except OSError:
        pass
    return result


def combined_stats(task_uid, s3_config):
    logs = {
        name[:-4]: get_stats(task_uid, name[:-4], s3_config)
        for name in storage.list_analysis_logs(task_uid, s3_config)
    }
    return combine(logs)


def combine(logs):
    timed = [value for value in logs.values() if value["first_ts"] is not None]
    first = min((value["first_ts"] for value in timed), default=None)
    last = max((value["last_ts"] for value in timed), default=None)
    bucket = max((last - first) / 119, 0.001) if timed else 1
    size = min(120, int((last - first) / bucket) + 1) if timed else 0
    series = {}
    for name, value in logs.items():
        counts = [0] * size
        if value["first_ts"] is not None:
            for index, count in enumerate(value["histogram"]["counts"]):
                offset = (
                    value["first_ts"] + index * value["histogram"]["bucket_s"] - first
                )
                counts[min(size - 1, max(0, int(offset / bucket)))] += count
        series[name] = counts
    return dict(
        logs={name: value["total"] for name, value in logs.items()},
        registry_writes=sum(value.get("registry_writes", 0) for value in logs.values()),
        first_ts=first,
        last_ts=last,
        histogram=dict(
            bucket_s=bucket,
            counts=[
                sum(values[index] for values in series.values())
                for index in range(size)
            ],
            series=series,
        ),
    )


def process_stats(task_uid, seqid, s3_config):
    from drakrun.analyzer.postprocessing.indexer import get_log_index_for_process

    logs = {}
    values = {"files": {}, "keys": {}, "remote": {}}
    for name in storage.list_analysis_logs(task_uid, s3_config):
        plugin = name[:-4]
        with storage.open_seekable_stream(task_uid, "log_index", s3_config) as index:
            entry = get_log_index_for_process(index, seqid, plugin)
        if not entry:
            continue
        with tempfile.TemporaryFile() as selected:
            with storage.open_seekable_stream(task_uid, name, s3_config) as source:
                for start, end in entry["blocks"]:
                    source.seek(start)
                    remaining = end - start
                    while remaining:
                        chunk = source.read(min(65536, remaining))
                        if not chunk:
                            break
                        selected.write(chunk)
                        remaining -= len(chunk)
            selected.seek(0)
            result = compute_stats(selected, plugin)
        logs[plugin] = result
        for kind, items in result["top_values"].items():
            for value, count in items:
                values[kind][value] = values[kind].get(value, 0) + count
    combined = combine(logs)
    combined["top_values"] = {
        kind: sorted(items.items(), key=lambda item: -item[1])[:50]
        for kind, items in values.items()
    }
    return combined
