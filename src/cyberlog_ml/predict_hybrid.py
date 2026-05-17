from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd
from joblib import load


SPECIALIST_CATEGORY_MODELS = {
    "firewall": "specialist_firewall_attack_category_detector.joblib",
    "ssh": "specialist_ssh_attack_category_detector.joblib",
    "web": "specialist_web_attack_category_detector.joblib",
}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Score normalized logs with the recommended hybrid strategy."
    )
    parser.add_argument("--input", required=True, type=Path, help="CSV containing normalized feature columns.")
    parser.add_argument("--output", required=True, type=Path, help="Where to write scored CSV output.")
    parser.add_argument("--models-dir", default=Path("models"), type=Path)
    args = parser.parse_args()

    df = pd.read_csv(args.input)
    binary_artifact = load(args.models_dir / "multisource_binary_detector.joblib")
    fallback_category_artifact = load(args.models_dir / "multisource_attack_category_detector.joblib")
    specialist_artifacts = load_specialists(args.models_dir)

    scored = df.copy()
    scored["predicted_binary_label"] = predict_with_artifact(binary_artifact, df)
    scored["category_model_used"] = "not_run_binary_normal"
    scored["predicted_attack_category"] = "normal"

    attack_mask = scored["predicted_binary_label"].astype(str).eq("attack")
    scored.loc[attack_mask, "predicted_attack_category"] = predict_categories_by_source(
        fallback_category_artifact,
        specialist_artifacts,
        df.loc[attack_mask],
    )
    scored.loc[attack_mask, "category_model_used"] = category_model_used_by_source(
        specialist_artifacts,
        df.loc[attack_mask],
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    scored.to_csv(args.output, index=False)
    print(f"Wrote hybrid predictions to {args.output}")


def load_specialists(models_dir: Path) -> dict[str, dict[str, object]]:
    artifacts = {}
    for source, filename in SPECIALIST_CATEGORY_MODELS.items():
        path = models_dir / filename
        if path.exists():
            artifacts[source] = load(path)
    return artifacts


def predict_categories_by_source(
    fallback_artifact: dict[str, object],
    specialist_artifacts: dict[str, dict[str, object]],
    df: pd.DataFrame,
) -> pd.Series:
    predictions = pd.Series(index=df.index, dtype=object)
    if "log_source" not in df.columns:
        predictions.loc[:] = predict_with_artifact(fallback_artifact, df)
        return predictions

    for source, source_df in df.groupby(df["log_source"].astype(str)):
        artifact = specialist_artifacts.get(source, fallback_artifact)
        predictions.loc[source_df.index] = predict_with_artifact(artifact, source_df)
    return predictions


def category_model_used_by_source(
    specialist_artifacts: dict[str, dict[str, object]],
    df: pd.DataFrame,
) -> pd.Series:
    model_used = pd.Series(index=df.index, dtype=object)
    if "log_source" not in df.columns:
        model_used.loc[:] = "multisource_attack_category_detector"
        return model_used

    for source, source_df in df.groupby(df["log_source"].astype(str)):
        if source in specialist_artifacts:
            model_used.loc[source_df.index] = f"specialist_{source}_attack_category_detector"
        else:
            model_used.loc[source_df.index] = "multisource_attack_category_detector"
    return model_used


def predict_with_artifact(artifact: dict[str, object], df: pd.DataFrame):
    feature_columns = artifact["feature_columns"]
    missing_cols = [col for col in feature_columns if col not in df.columns]
    if missing_cols:
        raise ValueError(f"Input is missing required feature columns: {missing_cols}")
    return artifact["pipeline"].predict(df[feature_columns])


if __name__ == "__main__":
    main()
