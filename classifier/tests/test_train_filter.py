"""The training filter counts usable calls (inside the API vocabulary), like the deployed gate."""

import importlib.util
import json
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _stub_sklearn():
    """The loaders under test do not use scikit-learn; stub it where only the runtime venv is installed."""
    try:
        import sklearn  # noqa: F401
    except ImportError:
        names = {"sklearn": [], "sklearn.isotonic": ["IsotonicRegression"],
                 "sklearn.metrics": ["average_precision_score", "f1_score", "roc_auc_score"],
                 "sklearn.model_selection": ["StratifiedGroupKFold", "StratifiedKFold"]}
        for name, attrs in names.items():
            mod = types.ModuleType(name)
            for attr in attrs:
                setattr(mod, attr, object)
            sys.modules[name] = mod


def load_trainer():
    _stub_sklearn()
    spec = importlib.util.spec_from_file_location("train", ROOT / "scripts" / "03_train.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run(api_calls):
    return {"id": "r", "group": "prog:x", "split": "train", "label": {"malicious": 0},
            "aux": {"program": "x", "arm": "a"},
            "features": {"run": {"guest_os": "windows"}, "api_calls": api_calls}}


def test_runs_outside_the_vocabulary_count_zero_usable_calls(tmp_path):
    train = load_trainer()
    hooked = sorted(train.fz._HOOKED)
    inside, outside = hooked[0], hooked[1]
    path = tmp_path / "chimera.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in (run({outside: 200}), run({inside: 12, outside: 5}))))
    _, meta = train.load_chimera(path, allowed=[inside])
    assert meta["calls"] == [0, 12]  # raw counts would be 200 and 17
    _, meta_all = train.load_chimera(path, allowed=None)
    assert meta_all["calls"] == [200, 17]
