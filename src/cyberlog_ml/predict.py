from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd
from joblib import load


def main() -> None:
    parser = argparse.ArgumentParser(description="Batch-score security logs with a trained detector.")
    parser.add_argument("--model", required=True, type=Path, help="Path to a .joblib model artifact.")
    parser.add_argument("--input", required=True, type=Path, help="CSV containing feature columns.")
    parser.add_argument("--output", required=True, type=Path, help="Where to write scored CSV output.")
    args = parser.parse_args()

    artifact = load(args.model)
    pipeline = artifact["pipeline"]
    feature_columns = artifact["feature_columns"]
    target = artifact["target"]

    df = pd.read_csv(args.input)
    missing_cols = [col for col in feature_columns if col not in df.columns]
    if missing_cols:
        raise ValueError(f"Input is missing required feature columns: {missing_cols}")

    scored = df.copy()
    scored[f"predicted_{target}"] = pipeline.predict(df[feature_columns])

    if hasattr(pipeline, "predict_proba"):
        probabilities = pipeline.predict_proba(df[feature_columns])
        classes = pipeline.named_steps["classifier"].classes_
        for idx, class_name in enumerate(classes):
            scored[f"probability_{target}_{class_name}"] = probabilities[:, idx]

    args.output.parent.mkdir(parents=True, exist_ok=True)
    scored.to_csv(args.output, index=False)
    print(f"Wrote predictions to {args.output}")


if __name__ == "__main__":
    main()
