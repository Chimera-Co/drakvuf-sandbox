import csv
import datetime
import hashlib
import importlib.util
import json
import pathlib

ROOT = pathlib.Path(__file__).parents[2]
spec = importlib.util.spec_from_file_location("m5_samples", ROOT / "scripts/chimera/bench/m5_samples.py")
m5 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m5)

TODAY = datetime.date.today()


def entry(family, n, days_ago=10, file_type="exe", tags=()):
    return {"sha256_hash": hashlib.sha256(f"{family}{n}".encode()).hexdigest(), "signature": family, "file_type": file_type,
            "first_seen": (TODAY - datetime.timedelta(days=days_ago)).isoformat() + " 00:00:00",
            "tags": list(tags), "file_name": f"{family}{n}.exe"}


def test_cohort_caps_families_excludes_stage1_and_ineligible():
    data = {
        "AgentTesla": [entry("AgentTesla", i, days_ago=i) for i in range(30)],
        "GuLoader": [entry("GuLoader", i) for i in range(2)] + [entry("GuLoader", 9, file_type="dll")],
        "WannaCry": [entry("WannaCry", 1)],
        "Vidar": [entry("Vidar", 1, tags=["worm"]), entry("Vidar", 2, days_ago=900)],
    }
    stage1 = {data["AgentTesla"][0]["sha256_hash"]}
    rows = m5.cohort(lambda f: data.get(f, []), list(data), 100, 4, (TODAY - datetime.timedelta(days=365)).isoformat(),
                     stage1)
    fams = [r["family"] for r in rows]
    assert fams.count("AgentTesla") == 4 and fams.count("GuLoader") == 2
    assert "WannaCry" not in fams and "Vidar" not in fams  # excluded family, worm tag, too old
    assert not {r["sha256"] for r in rows} & stage1
    assert all(r["role"] == "calibration" for r in rows)


def test_cohort_trims_largest_families_first():
    data = {f: [entry(f, i) for i in range(10)] for f in ("AgentTesla", "Formbook", "Amadey")}
    data["Stealc"] = [entry("Stealc", 1)]
    rows = m5.cohort(lambda f: data.get(f, []), list(data), 7, 4, "2000-01-01", set())
    counts = {f: [r["family"] for r in rows].count(f) for f in data}
    assert len(rows) == 7 and counts["Stealc"] == 1 and max(counts.values()) - min(counts.values()) <= 1


def test_cmd_cohort_uses_cache_without_key_and_writes_manifest(tmp_path, monkeypatch):
    meta = tmp_path / "metadata"
    meta.mkdir()
    for family in m5.VM_AWARE_FAMILIES + m5.CONTROL_FAMILIES:
        (meta / f"{family.lower()}.json").write_text(json.dumps([entry(family, i) for i in range(3)]))
    with (tmp_path / "register.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["sha256", "family"])
        w.writeheader()
        w.writerow({"sha256": entry("AgentTesla", 0)["sha256_hash"], "family": "AgentTesla"})
    monkeypatch.setattr(m5, "auth_key", lambda: (_ for _ in ()).throw(AssertionError("key read")))
    m5.main(["cohort", "--out", str(tmp_path)])
    manifest = json.loads((tmp_path / "cohort-manifest.json").read_text())
    assert manifest["new_queries"] == 0 and manifest["stage1_hashes_excluded"] == 1
    assert "AgentTesla" in manifest["families_shared_with_stage1"]
    with (tmp_path / "cohort.csv").open(newline="") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == manifest["samples"] <= 100
    assert entry("AgentTesla", 0)["sha256_hash"] not in {r["sha256"] for r in rows}
