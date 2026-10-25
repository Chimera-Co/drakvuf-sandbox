"""Download an EMBER2024 subset (features + labels, no binaries) from Hugging Face.

    .venv/bin/python scripts/06_download_ember.py            # the ~10 GB starter set
    .venv/bin/python scripts/06_download_ember.py Win32_train  # more later

thrember.download_dataset() leaves every zip in the Hugging Face cache as well, doubling the disk
use; this downloads each zip into a temporary folder, extracts it, and deletes it. Resumable:
zips whose extraction finished (marker file) are skipped.
"""

import os
import shutil
import sys
import time
import zipfile
from pathlib import Path

os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
from huggingface_hub import hf_hub_download  # noqa: E402

REPO = "joyce8/EMBER2024"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from chimera_clf.paths import EMBER_DATA as OUT  # noqa: E402
STARTER = ["Win32_test", "Win64_test", "Dot_Net_train", "Dot_Net_test", "ELF_train", "ELF_test",
           "PDF_train", "PDF_test", "challenge"]


def fetch(name: str):
    marker = OUT / f".done_{name}"
    if marker.exists():
        print(f"{name}: already done", flush=True)
        return
    tmp = OUT / ".tmp"
    tmp.mkdir(parents=True, exist_ok=True)
    t = time.time()
    path = Path(hf_hub_download(repo_id=REPO, filename=f"{name}.zip", repo_type="dataset", local_dir=tmp))
    size = path.stat().st_size
    print(f"{name}: downloaded {size / 1e9:.2f} GB in {time.time() - t:.0f}s, extracting", flush=True)
    with zipfile.ZipFile(path) as z:  # zipfile drops absolute and '..' components
        z.extractall(OUT)
    path.unlink()
    marker.write_text(f"{size}\n")
    print(f"{name}: done", flush=True)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    names = sys.argv[1:] or STARTER
    for name in names:
        fetch(name)
    shutil.rmtree(OUT / ".tmp", ignore_errors=True)
    files = [p for p in OUT.iterdir() if p.suffix == ".jsonl"]
    print(f"all done: {len(files)} feature files in {OUT}")


if __name__ == "__main__":
    main()
