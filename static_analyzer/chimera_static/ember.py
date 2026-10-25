"""EMBER2024 feature vector (thrember feature version 3) for the static ML models."""

from __future__ import annotations

import math

from .vendor.thrember.features import PEFeatureExtractor

THREMBER_COMMIT = "0ef753e"
_extractor = None


def ember_vector(data: bytes) -> dict:
    global _extractor
    if _extractor is None:
        _extractor = PEFeatureExtractor()
    vec = _extractor.feature_vector(data)
    values = [float(v) if math.isfinite(float(v)) else 0.0 for v in vec.tolist()]
    return {"version": f"thrember@{THREMBER_COMMIT}", "dim": len(values), "vector": values}
