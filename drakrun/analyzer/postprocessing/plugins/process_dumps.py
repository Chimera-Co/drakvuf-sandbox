import hashlib
import logging
import os
import shutil
import zipfile
from collections import defaultdict
from typing import Any, Dict, Optional

from drakrun.lib.paths import DUMPS_DIR, DUMPS_ZIP

from .parse_utils import parse_log
from .plugin_base import PostprocessContext

logger = logging.getLogger(__name__)


def parse_linux_procdump(data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Linux success events use SN for the on-disk procdump.<SN> filename."""
    if data.get("Status") != "Success":
        return None
    index = int(data["SN"])
    if index < 0:
        raise ValueError("Negative procdump sequence number")
    return {
        "index": index,
        "filename": f"procdump.{index}",
        "pid": int(data["TargetPID"]),
        "process_name": data["TargetName"],
        "dump_reason": data["DumpReason"],
        "size": int(data["DumpSize"]),
        "timestamp": float(data["TimeStamp"]),
    }


def process_linux_dumps(context: PostprocessContext) -> None:
    """Package ELF cores separately from Windows region dumps and their metadata."""
    analysis_dir = context.analysis_dir
    dumps_path = analysis_dir / DUMPS_DIR
    config = context.config.memdump
    tree = context.process_tree

    # AgentExec records a PID, not an EventUID. Select its first newly observed
    # instance; the initial process enumeration has ts_from == 0.
    root = None
    inject_path = analysis_dir / "inject.log"
    if inject_path.exists():
        for event in parse_log(inject_path, lambda data: data):
            if event.get("Status") == "Success":
                candidates = [
                    p for p in tree.processes if p.pid == event.get("InjectedPid")
                ]
                root = next(
                    (p for p in candidates if p.ts_from > 0),
                    next(iter(candidates), None),
                )
                break
    sample_seqids = set()
    if root is not None:
        pending = [root]
        while pending:
            process = pending.pop()
            if process.seqid not in sample_seqids:
                sample_seqids.add(process.seqid)
                pending.extend(process.children)
    else:
        logger.warning(
            "Linux dump sample tree unavailable; retaining all process dumps within size limits"
        )

    # Upstream emits Plugin=procdump, not procdump2. Accept the latter for builds
    # that use the plugin's command-line name in their JSON output.
    log_path = analysis_dir / "procdump.log"
    if not log_path.exists():
        log_path = analysis_dir / "procdump2.log"
    events = parse_log(log_path, parse_linux_procdump) if log_path.exists() else []
    dumps_metadata = []
    per_process = defaultdict(list)
    seen = set()
    total_size = 0
    filtered = 0
    with zipfile.ZipFile(analysis_dir / DUMPS_ZIP, "w", zipfile.ZIP_DEFLATED) as zipf:
        for dump in events:
            if dump["filename"] in seen:
                continue
            # print_dump_info constructs a fresh trap info with EventUID=0.
            # Its timestamp is after the copy, possibly after procmon's exit
            # event, so use the latest instance started by that timestamp.
            candidates = [
                p
                for p in tree.processes
                if p.pid == dump["pid"] and p.ts_from <= dump["timestamp"]
            ]
            process = max(candidates, key=lambda p: p.ts_from) if candidates else None
            seqid = process.seqid if process else None
            if root is not None and seqid not in sample_seqids:
                filtered += 1
                continue
            path = dumps_path / dump["filename"]
            if path.is_symlink() or not path.is_file():
                logger.warning("Linux dump missing or unsafe: %s", path)
                continue
            size = path.stat().st_size
            if size != dump["size"]:
                logger.warning(
                    "Linux dump size mismatch: %s (log=%d, file=%d)",
                    path,
                    dump["size"],
                    size,
                )
                continue
            if not config.min_single_dump_size <= size <= config.max_single_dump_size:
                filtered += 1
                continue
            if total_size + size > config.max_total_dumps_size:
                filtered += 1
                continue
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            zip_name = f"{DUMPS_DIR}/{dump['filename']}"
            metadata = {
                **dump,
                "filename": zip_name,
                "process_seqid": seqid,
                "sha256": digest.hexdigest(),
            }
            dumps_metadata.append(metadata)
            per_process[seqid if seqid is not None else -1].append(
                {
                    **metadata,
                    "filename": dump["filename"],
                    "method": "procdump2",
                }
            )
            zipf.write(path, zip_name)
            seen.add(dump["filename"])
            total_size += size
        if not dumps_metadata:
            zipf.writestr(zipfile.ZipInfo(f"{DUMPS_DIR}/"), "")

    shutil.rmtree(dumps_path)
    context.update_metadata({"dumps_metadata": dumps_metadata})
    context.update_report(
        {
            "memdumps": [
                {"process_seqid": seqid, "dumps": dumps}
                for seqid, dumps in sorted(per_process.items())
            ]
        }
    )
    logger.info(
        "Linux dumps: packed %d files (%d bytes), filtered %d",
        len(dumps_metadata),
        total_size,
        filtered,
    )


def process_dumps(context: PostprocessContext) -> None:
    analysis_dir = context.analysis_dir
    process_tree = context.process_tree
    memdump_config = context.config.memdump

    def parse_memdump(data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        event_uid = int(data["EventUID"], 16)
        pid = data["PID"]
        process = process_tree.get_process_for_evtid(pid, event_uid)
        memdump_data = {
            "index": data["DumpsCount"],
            "dump_reason": data["DumpReason"],
            "method": data["Method"],
            "process": process,
            "address": data["DumpAddr"],
            "size": int(data["DumpSize"], 16),
            "filename": data["DumpFilename"],
        }
        if "TargetPID" in data and "WriteAddr" in data:
            target_pid = data["TargetPID"]
            target_process = process_tree.get_process_for_evtid(target_pid, event_uid)
            memdump_data["target_process"] = target_process.seqid
            memdump_data["target_addr"] = data["WriteAddr"]
        return memdump_data

    memdump_log = parse_log(analysis_dir / "memdump.log", parse_memdump)

    dumps_path = analysis_dir / DUMPS_DIR
    target_zip = analysis_dir / DUMPS_ZIP

    occurrence_index = defaultdict(int)
    filtered_dumps = []
    filtered_out_count = 0

    # First, we're pre-filtering single dumps
    for idx, entry in enumerate(memdump_log):
        dump_file = dumps_path / entry["filename"]
        metadata_file = (
            dumps_path / f"memdump.{str(entry['index']).rjust(6, '0')}.metadata"
        )
        if not dump_file.exists():
            logger.warning(f"{dump_file} does not exist")
            continue
        if not metadata_file.exists():
            logger.warning(f"{metadata_file} does not exist")
            continue
        if memdump_config.filter_out_system_pid and entry["process"].pid == 4:
            filtered_out_count += 1
            continue
        dump_size = entry["size"]
        if not (
            memdump_config.min_single_dump_size
            <= dump_size
            <= memdump_config.max_single_dump_size
        ):
            filtered_out_count += 1
            continue
        region = (entry["process"].pid, entry["address"])
        # Add occurrence counter: it counts the index of
        # current (PID,address) region dump
        occurrence_index[region] += 1
        filtered_dumps.append(
            {
                **entry,
                "dump_file": dump_file,
                "occurrence_index": occurrence_index[region],
            }
        )

    logger.info("Filtered out %d dumps.", filtered_out_count)

    # Sort dumps starting from first occurrences of a region
    # If region was dumped n>1 times, first dumps will be prioritized
    # in case if size threshold was exceeded
    filtered_dumps = sorted(
        filtered_dumps,
        key=lambda x: (
            x["occurrence_index"],
            x["index"],
        ),
    )
    current_size = 0
    dump_name_visited = set()
    dumps_to_pack = []

    for idx, dump in enumerate(filtered_dumps):
        if current_size > memdump_config.max_total_dumps_size:
            logger.warning(
                "%d dumps were deleted, because the configured size threshold was exceeded. "
                "Regions with the most copies have been removed.",
                len(filtered_dumps) - idx,
            )
            break
        dump_filename = dump["filename"]
        if dump_filename not in dump_name_visited:
            # Count each dump file only once
            current_size += dump["size"]
        dump_name_visited.add(dump_filename)
        dumps_to_pack.append(dump)

    dumps_to_pack = sorted(dumps_to_pack, key=lambda x: x["index"])
    dump_name_visited = set()
    dumps_metadata = []
    dumps_per_process = defaultdict(list)
    with zipfile.ZipFile(target_zip, "w", zipfile.ZIP_DEFLATED) as zipf:
        for dump in dumps_to_pack:
            dump_file = dump["dump_file"]
            dump_zip_name = os.path.join(DUMPS_DIR, dump["filename"])
            dumps_per_process[dump["process"].seqid].append(dump)
            if dump["filename"] not in dump_name_visited:
                dumps_metadata.append(
                    {
                        "filename": dump_zip_name,
                        "base_address": dump["address"],
                    }
                )
                zipf.write(dump_file, dump_zip_name)
                dump_name_visited.add(dump["filename"])

        # No dumps, force empty directory
        if not dumps_metadata:
            zipf.writestr(zipfile.ZipInfo(f"{DUMPS_DIR}/"), "")

    shutil.rmtree(dumps_path)
    context.update_metadata({"dumps_metadata": dumps_metadata})
    context.update_report(
        {
            "memdumps": [
                {
                    "process_seqid": process_seqid,
                    "dumps": [
                        {
                            k: v
                            for k, v in dump.items()
                            if k not in ["process", "dump_file", "occurrence_index"]
                        }
                        for dump in dumps_per_process[process_seqid]
                    ],
                }
                for process_seqid in sorted(dumps_per_process.keys())
            ]
        }
    )
