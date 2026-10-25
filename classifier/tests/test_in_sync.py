"""Copies must not drift from their originals in this repository."""

from pathlib import Path

import pytest

CLF = Path(__file__).resolve().parents[1]
REPO = CLF.parent


def body(path: Path, skip_comment_header=True) -> list[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    while skip_comment_header and lines and lines[0].startswith("# Vendored"):
        lines = lines[1:]
    while skip_comment_header and lines and lines[0].startswith("# Only change"):
        lines = lines[1:]
    return lines


def test_runner_matches_drakrun():
    assert body(CLF / "tests" / "chimera_runner.py") == body(REPO / "drakrun/analyzer/classifier/runner.py")


def test_feature_extractor_matches_drakrun():
    ours = body(CLF / "chimera_clf/vendor/chimera_features.py")
    theirs = [line.replace("from drakrun.lib.pcap_summary import", "from .pcap_summary import")
              for line in body(REPO / "drakrun/analyzer/classifier/features.py")]
    assert ours == theirs


def test_pcap_summary_matches_drakrun():
    assert body(CLF / "chimera_clf/vendor/pcap_summary.py") == body(REPO / "drakrun/lib/pcap_summary.py")


def test_hooks_match_drakrun():
    assert (CLF / "chimera_clf/hooks.txt").read_bytes() == (REPO / "drakrun/data/hooks.txt").read_bytes()


@pytest.mark.parametrize("deployed,source", [("model.py", "chimera_clf/deploy_model.py"),
                                             ("featurize.py", "chimera_clf/featurize.py"),
                                             ("hooks.txt", "chimera_clf/hooks.txt")])
def test_deploy_is_packaged_from_current_sources(deployed, source):
    assert (CLF / "deploy" / deployed).read_bytes() == (CLF / source).read_bytes(), \
        "deploy/ is stale: run scripts/05_package.py"


def test_static_analyzer_uses_the_same_thrember():
    vendored = REPO / "static_analyzer/chimera_static/vendor/thrember/features.py"
    thrember = pytest.importorskip("thrember.features")
    assert vendored.read_bytes() == Path(thrember.__file__).read_bytes()
