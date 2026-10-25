"""Build-time YARA gate: compile every rule under a folder into one file, or fail the image build.

    python -I -m chimera_static.rules_build /opt/chimera-static/rules /opt/chimera-static/rules.yarc

Exit 1 on zero rules or any compile error, so an image never ships without working rules. Writes
<out>.json beside the compiled file with the rule count and each ruleset's pin (its SOURCE.json), which
static.json then reports, so "no YARA matches" always says which rules were looked for.
"""

from __future__ import annotations

import json
import os
import sys


def collect(rules_dir: str) -> dict[str, str]:
    files = {}
    for root, dirs, names in os.walk(rules_dir):
        dirs.sort()
        for n in sorted(names):
            if n.endswith((".yar", ".yara")):
                path = os.path.join(root, n)
                files[os.path.relpath(path, rules_dir)] = path
    return files


def sources(rules_dir: str) -> list[dict]:
    out = []
    for name in sorted(os.listdir(rules_dir)):
        pin = os.path.join(rules_dir, name, "SOURCE.json")
        if os.path.isfile(pin):
            with open(pin, encoding="utf-8") as fh:
                meta = json.load(fh)
            out.append({k: meta.get(k) for k in ("name", "source", "commit", "licence")} | {"folder": name})
    return out


def build(rules_dir: str, out_path: str) -> dict:
    import yara

    files = collect(rules_dir)
    if not files:
        raise SystemExit(f"rules_build: no .yar/.yara files under {rules_dir}")
    try:
        rules = yara.compile(filepaths=files)
    except yara.Error as exc:
        raise SystemExit(f"rules_build: compile failed: {exc}") from exc
    count = sum(1 for _ in rules)
    if count == 0:
        raise SystemExit("rules_build: the rule files define no rules")
    rules.save(out_path)
    info = {"rules": count, "files": len(files), "warnings": len(getattr(rules, "warnings", []) or []),
            "yara": yara.__version__, "sources": sources(rules_dir)}
    with open(f"{out_path}.json", "w", encoding="utf-8") as fh:
        json.dump(info, fh, indent=1)
    return info


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    info = build(sys.argv[1], sys.argv[2])
    print(f"rules_build: {info['rules']} rules from {info['files']} files, {info['warnings']} warnings")
