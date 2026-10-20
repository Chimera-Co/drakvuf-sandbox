"""Demonstration heuristic only. Replace through [classifier].model_path."""


def classify(features: dict, analysis_dir: str) -> dict:
    explanation = [
        "Placeholder heuristic, not a trained model; score is not a probability."
    ]
    score = 0.0
    ttp_count = len(features["ttps"])
    if ttp_count:
        score += min(0.4, 0.1 * ttp_count)
        explanation.append(f"{ttp_count} sample-scoped TTPs observed.")
    if features["registry"]["autorun_touched"]:
        score += 0.3
        explanation.append("An autorun registry key was accessed.")
    if any(
        features["api_calls"].get(name, 0)
        for name in (
            "WriteProcessMemory",
            "NtWriteVirtualMemory",
            "CreateRemoteThread",
            "NtCreateThreadEx",
        )
    ):
        score += 0.2
        explanation.append("API calls associated with process injection were observed.")
    if features["processes"]["count"] > 1:
        score += 0.1
        explanation.append("The sample launched descendant processes.")
    score = round(min(score, 1.0), 2)
    if not features["run"]["complete"]:
        explanation.append(
            "Telemetry is incomplete; absence of indicators is inconclusive."
        )
    return {
        "schema": "chimera-verdict/1",
        "label": (
            "malicious" if score >= 0.7 else "suspicious" if score >= 0.3 else "unknown"
        ),
        "score": score,
        "family": None,
        "model": "chimera-stub",
        "model_version": "1",
        "explanation": explanation,
    }
