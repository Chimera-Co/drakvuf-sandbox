import json

from drakrun.analyzer.classifier.features import extract_features
from drakrun.analyzer.classifier.runner import run_classifier, unknown_verdict

from .plugin_base import PostprocessContext


def classify_sample(context: PostprocessContext) -> None:
    settings = context.config.classifier
    if not settings.enabled:
        return
    try:
        features = extract_features(context.analysis_dir)
        (context.analysis_dir / "features.json").write_text(
            json.dumps(features, indent=2, allow_nan=False), encoding="utf-8"
        )
        verdict = run_classifier(
            features, context.analysis_dir, settings.model_path, settings.timeout_s
        )
    except Exception as error:
        verdict = unknown_verdict(f"{type(error).__name__}: {error}")
    context.update_metadata({"classification": verdict})
    (context.analysis_dir / "classification.json").write_text(
        json.dumps(verdict, indent=2, allow_nan=False), encoding="utf-8"
    )
