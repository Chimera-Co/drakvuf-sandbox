"""Run a trusted Python model in a separate, time-limited interpreter.

Model files define classify(features: dict, analysis_dir: str) -> dict. This is
process isolation for crashes/timeouts, not a security sandbox for untrusted code.
"""

import importlib.util
import json
import os
import signal
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Verdict(BaseModel):
    # Lenient on purpose: numpy floats and extra keys from a real model are accepted (extras dropped)
    model_config = ConfigDict(extra="ignore")
    schema_: Literal["chimera-verdict/1"] = Field(
        default="chimera-verdict/1", alias="schema"
    )
    label: Literal["malicious", "suspicious", "benign", "unknown"]
    score: float = Field(ge=0, le=1, allow_inf_nan=False)
    family: Optional[str]
    model: str
    model_version: str
    explanation: list[str]

    @field_validator("score", mode="before")
    @classmethod
    def _score_not_bool(cls, value):
        if isinstance(value, bool):
            raise ValueError("score must be a number, not a bool")
        return value


def unknown_verdict(error: str) -> dict:
    return {"schema": "chimera-verdict/1", "label": "unknown", "error": error[:2000]}


def run_classifier(features: dict, analysis_dir, model_path=None, timeout_s=60) -> dict:
    """Use the labelled stub when unset/missing; contain all model failures."""
    try:
        model = (
            Path(model_path)
            if model_path
            else Path(__file__).with_name("stub_model.py")
        )
        if not model.exists():
            model = Path(__file__).with_name("stub_model.py")
        with tempfile.TemporaryDirectory(prefix="chimera-classifier-") as temporary:
            request = Path(temporary) / "features.json"
            response = Path(temporary) / "verdict.json"
            request.write_text(json.dumps(features, allow_nan=False), encoding="utf-8")
            command = [
                sys.executable,
                str(Path(__file__).resolve()),
                str(model.resolve()),
                str(request),
                str(response),
                str(Path(analysis_dir).resolve()),
            ]
            with subprocess.Popen(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            ) as process:
                try:
                    process.wait(timeout=timeout_s)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                    return unknown_verdict(f"Classifier timed out after {timeout_s}s")
                if process.returncode != 0:
                    return unknown_verdict(
                        f"Classifier process exited with code {process.returncode}"
                    )
            result = json.loads(response.read_text(encoding="utf-8"))
            if isinstance(result, dict) and "error" in result:
                return unknown_verdict(str(result["error"]))
            return Verdict.model_validate(result).model_dump(by_alias=True)
    except Exception as error:
        return unknown_verdict(f"{type(error).__name__}: {error}")


def _worker(model_path, request_path, response_path, analysis_dir):
    try:
        # Allow a deployed model to import sibling helpers.
        sys.path.insert(0, str(Path(model_path).parent))
        spec = importlib.util.spec_from_file_location(
            "chimera_classifier_model", model_path
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        features = json.loads(Path(request_path).read_text(encoding="utf-8"))
        result = Verdict.model_validate(
            module.classify(features, analysis_dir)
        ).model_dump(by_alias=True)
        encoded = json.dumps(result, allow_nan=False)
    except BaseException as error:
        encoded = json.dumps(unknown_verdict(f"{type(error).__name__}: {error}"))
    Path(response_path).write_text(encoded, encoding="utf-8")


if __name__ == "__main__":
    _worker(*sys.argv[1:])
