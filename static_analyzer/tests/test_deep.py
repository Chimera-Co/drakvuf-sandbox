"""Deep pass (capa + FLOSS): runs per format, records versions, and keeps going when one tool fails."""

import json
import time
from pathlib import Path

from chimera_static import deep

HERE = Path(__file__).resolve().parent
PE = HERE / "fixtures" / "test.exe"
ELF = HERE / "fixtures" / "linux-x86_64.so"


def test_pe_gets_capa_and_floss(tmp_path):
    r = deep.run_deep(str(PE), str(tmp_path), file_name="test.exe", timeout_s=240)
    assert r["schema"] == "chimera-deep/1" and r["format"] == "pe" and not r["errors"], r["errors"]
    names = {x["name"] for x in r["capa"]["rules"]}
    assert "contain a thread local storage (.tls) section" in names
    assert not any(x["namespace"] and x["namespace"].startswith("internal") for x in r["capa"]["rules"])
    assert r["capa"]["version"] and r["capa"]["library_signatures"] is False
    assert set(r["floss"]) >= {"version", "stack", "tight", "decoded"}
    assert json.loads((tmp_path / "deep.json").read_text())["format"] == "pe"


def test_elf_gets_capa_only(tmp_path):
    r = deep.run_deep(str(ELF), None, file_name="lib.so", timeout_s=240)
    assert r["format"] == "elf" and r["floss"] is None
    assert r["capa"] is not None or any(e["stage"] == "capa" for e in r["errors"])


def test_other_formats_and_budget(tmp_path):
    p = tmp_path / "doc.pdf"
    p.write_bytes(b"%PDF-1.4\n%%EOF\n")
    r = deep.run_deep(str(p), None, timeout_s=240)
    assert r["capa"] is None and r["floss"] is None and not r["errors"]
    r = deep.run_deep(str(PE), None, timeout_s=1)
    assert {e["stage"] for e in r["errors"]} == {"capa", "floss"}


def test_timeout_gets_past_a_tool_that_swallows_it(tmp_path, monkeypatch):
    def stubborn(path, *args):  # like capa and FLOSS: swallows the timeout, keeps going
        while True:
            try:
                time.sleep(0.01)
            except BaseException:
                pass
            time.sleep(0.01)

    monkeypatch.setattr(deep, "_capa", stubborn)
    seen = {}

    def floss(path):
        seen["partial"] = json.loads((tmp_path / "deep.json").read_text())
        return {"version": "x"}

    monkeypatch.setattr(deep, "_floss", floss)
    t0 = time.monotonic()
    r = deep.run_deep(str(PE), str(tmp_path), timeout_s=20)
    assert time.monotonic() - t0 < 25  # capa gets 60% of 20 s, then FLOSS returns at once
    assert r["errors"][0]["stage"] == "capa" and "timed out" in r["errors"][0]["error"]
    assert r["floss"] == {"version": "x"}
    # deep.json is written after each tool, so the capa outcome is on disk before FLOSS starts
    assert seen["partial"]["errors"][0]["stage"] == "capa"


def test_one_tool_failing_keeps_the_other(tmp_path, monkeypatch):
    def broken(path, fmt):
        raise RuntimeError("boom")

    monkeypatch.setattr(deep, "_capa", broken)
    r = deep.run_deep(str(PE), None, timeout_s=240)
    assert r["errors"] == [{"stage": "capa", "error": "RuntimeError: boom"}]
    assert r["floss"] is not None
