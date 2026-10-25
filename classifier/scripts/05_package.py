"""Build the deploy/ folder Shreyas copies to /etc/drakrun/classifier/.

    .venv/bin/python scripts/05_package.py --model models/v0 --out deploy

Copies model.py, featurize.py, hooks.txt, model.txt, meta.json (and family.txt), writes a
manifest with SHA-256s, then runs the model on the fixture through CHIMERA's own runner.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", type=Path, default=ROOT / "models" / "v0")
    ap.add_argument("--out", type=Path, default=ROOT / "deploy")
    ap.add_argument("--static-model", type=Path, default=ROOT / "models" / "static_v0",
                    help="folder with static_meta.json and pe/elf/pdf.txt (skipped if missing)")
    ap.add_argument("--fixture", type=Path, default=ROOT / "fixtures" / "bginfo-96f7ee81-features.json")
    a = ap.parse_args()
    if a.out.exists():
        shutil.rmtree(a.out)
    a.out.mkdir(parents=True)
    copies = {"model.py": ROOT / "chimera_clf" / "deploy_model.py", "featurize.py": ROOT / "chimera_clf" / "featurize.py",
              "hooks.txt": ROOT / "chimera_clf" / "hooks.txt", "model.txt": a.model / "model.txt",
              "meta.json": a.model / "meta.json", "family.txt": a.model / "family.txt"}
    smeta = a.static_model / "static_meta.json"
    if smeta.exists():
        copies["static_meta.json"] = smeta
        for name in json.loads(smeta.read_text())["models"]:
            copies[f"static_{name}.txt"] = a.static_model / f"{name}.txt"
    for dst, src in copies.items():
        if src.exists():
            shutil.copy2(src, a.out / dst)
    meta = json.loads((a.out / "meta.json").read_text())
    manifest = {"model": meta["model"], "model_version": meta["model_version"], "packaged": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "requires": meta["versions"], "files": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                                         for p in sorted(a.out.iterdir())}}
    (a.out / "MANIFEST.json").write_text(json.dumps(manifest, indent=1))

    from chimera_runner import run_classifier  # CHIMERA's real runner (vendored from sprint/final)
    features = json.loads(a.fixture.read_text())
    t = time.time()
    verdict = run_classifier(features, str(a.fixture.parent), str(a.out / "model.py"), timeout_s=60)
    print(json.dumps(verdict, indent=1))
    print(f"runner round trip {time.time() - t:.2f}s")
    if verdict.get("error"):
        raise SystemExit(f"model failed under CHIMERA's runner: {verdict['error']}")
    print(f"packaged {sorted(manifest['files'])} -> {a.out}")


if __name__ == "__main__":
    main()
