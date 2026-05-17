from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from joblib import dump, load
from sklearn.compose import ColumnTransformer
from sklearn.dummy import DummyClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler


EXCLUDED_FEATURE_COLUMNS = {
    "label",
    "label_clean",
    "binary_label",
    "attack_category",
    "source_dataset",
    "timestamp",
    "src_ip",
    "dst_ip",
    "username",
    "url_path",
    "user_agent",
    "raw_message",
}


@dataclass(frozen=True)
class TrainingResult:
    target: str
    model_path: str
    metrics_path: str
    report_path: str
    confusion_matrix_path: str
    metrics: dict[str, float | int | str]
    baseline_metrics: dict[str, float | int | str]


def train_and_evaluate(
    df: pd.DataFrame,
    target_col: str,
    model_name: str,
    models_dir: Path,
    metrics_dir: Path,
    figures_dir: Path,
    random_state: int = 42,
) -> TrainingResult:
    models_dir.mkdir(parents=True, exist_ok=True)
    metrics_dir.mkdir(parents=True, exist_ok=True)
    figures_dir.mkdir(parents=True, exist_ok=True)

    train_df, test_df = make_train_test_split(
        df,
        target_col=target_col,
        random_state=random_state,
    )
    return train_and_evaluate_on_split(
        train_df=train_df,
        test_df=test_df,
        target_col=target_col,
        model_name=model_name,
        models_dir=models_dir,
        metrics_dir=metrics_dir,
        figures_dir=figures_dir,
        random_state=random_state,
    )


def train_and_evaluate_on_split(
    train_df: pd.DataFrame,
    test_df: pd.DataFrame,
    target_col: str,
    model_name: str,
    models_dir: Path,
    metrics_dir: Path,
    figures_dir: Path,
    random_state: int = 42,
    metadata: dict[str, object] | None = None,
) -> TrainingResult:
    models_dir.mkdir(parents=True, exist_ok=True)
    metrics_dir.mkdir(parents=True, exist_ok=True)
    figures_dir.mkdir(parents=True, exist_ok=True)

    X_train, y_train = split_features_target(train_df, target_col)
    X_test, y_test = split_features_target(test_df, target_col)

    baseline = DummyClassifier(strategy="most_frequent")
    baseline.fit(X_train, y_train)
    baseline_predictions = baseline.predict(X_test)
    baseline_metrics = compute_metrics(y_test, baseline_predictions, model_name=f"{model_name}_baseline")

    pipeline = build_pipeline(X_train, random_state=random_state)
    pipeline.fit(X_train, y_train)
    predictions = pipeline.predict(X_test)
    metrics = compute_metrics(y_test, predictions, model_name=model_name)

    model_path = models_dir / f"{model_name}.joblib"
    dump(
        {
            "pipeline": pipeline,
            "target": target_col,
            "feature_columns": X_train.columns.tolist(),
            "classes": sorted(pd.concat([y_train, y_test]).unique().tolist()),
            "metadata": metadata or {},
        },
        model_path,
    )

    metrics_payload = {
        "target": target_col,
        "model": model_name,
        "rows_train": int(len(X_train)),
        "rows_test": int(len(X_test)),
        "classes": sorted(pd.concat([y_train, y_test]).unique().tolist()),
        "metadata": metadata or {},
        "main_model": metrics,
        "baseline": baseline_metrics,
    }
    metrics_path = metrics_dir / f"{model_name}_metrics.json"
    metrics_path.write_text(json.dumps(metrics_payload, indent=2), encoding="utf-8")

    report = classification_report(y_test, predictions, output_dict=True, zero_division=0)
    report_path = metrics_dir / f"{model_name}_classification_report.csv"
    pd.DataFrame(report).T.to_csv(report_path)

    cm_path = figures_dir / f"{model_name}_confusion_matrix.png"
    save_confusion_matrix(y_test, predictions, cm_path, title=f"{target_col} confusion matrix")

    save_model_coefficients(pipeline, model_name, metrics_dir)

    return TrainingResult(
        target=target_col,
        model_path=str(model_path),
        metrics_path=str(metrics_path),
        report_path=str(report_path),
        confusion_matrix_path=str(cm_path),
        metrics=metrics,
        baseline_metrics=baseline_metrics,
    )


def make_train_test_split(
    df: pd.DataFrame,
    target_col: str,
    random_state: int,
    test_size: float = 0.2,
    stratify_source: bool = True,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    if target_col not in df.columns:
        raise KeyError(f"Target column not found: {target_col}")

    stratify = None
    if stratify_source and "log_source" in df.columns:
        stratify_key = df["log_source"].astype(str) + "__" + df[target_col].astype(str)
        if stratify_key.value_counts().min() >= 2:
            stratify = stratify_key
    if stratify is None:
        target = df[target_col].astype(str)
        if target.value_counts().min() >= 2:
            stratify = target

    train_df, test_df = train_test_split(
        df,
        test_size=test_size,
        random_state=random_state,
        stratify=stratify,
    )
    return train_df.reset_index(drop=True), test_df.reset_index(drop=True)


def evaluate_model_artifact(
    model_path: Path | str,
    df: pd.DataFrame,
    target_col: str | None = None,
    model_name: str | None = None,
) -> dict[str, float | int | str]:
    artifact = load(model_path)
    target = target_col or artifact["target"]
    feature_columns = artifact["feature_columns"]
    missing_cols = [col for col in feature_columns if col not in df.columns]
    if missing_cols:
        raise ValueError(f"Evaluation data is missing required feature columns: {missing_cols}")

    y_true = df[target].astype(str)
    y_pred = artifact["pipeline"].predict(df[feature_columns])
    return compute_metrics(y_true, y_pred, model_name=model_name or Path(model_path).stem)


def split_features_target(df: pd.DataFrame, target_col: str) -> tuple[pd.DataFrame, pd.Series]:
    if target_col not in df.columns:
        raise KeyError(f"Target column not found: {target_col}")
    feature_cols = [col for col in df.columns if col not in EXCLUDED_FEATURE_COLUMNS]
    X = df[feature_cols].copy()
    y = df[target_col].astype(str)
    return X, y


def build_pipeline(X: pd.DataFrame, random_state: int) -> Pipeline:
    numeric_cols = X.select_dtypes(include=np.number).columns.tolist()
    categorical_cols = [col for col in X.columns if col not in numeric_cols]

    numeric_pipeline = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
        ]
    )
    categorical_pipeline = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="most_frequent")),
            ("onehot", make_one_hot_encoder()),
        ]
    )

    preprocessor = ColumnTransformer(
        transformers=[
            ("numeric", numeric_pipeline, numeric_cols),
            ("categorical", categorical_pipeline, categorical_cols),
        ],
        remainder="drop",
    )

    classifier = SGDClassifier(
        loss="log_loss",
        penalty="elasticnet",
        alpha=0.0005,
        l1_ratio=0.05,
        max_iter=2000,
        tol=1e-3,
        class_weight="balanced",
        early_stopping=True,
        validation_fraction=0.1,
        n_iter_no_change=8,
        n_jobs=-1,
        random_state=random_state,
    )

    return Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            ("classifier", classifier),
        ]
    )


def make_one_hot_encoder() -> OneHotEncoder:
    try:
        return OneHotEncoder(handle_unknown="ignore", sparse_output=True)
    except TypeError:
        return OneHotEncoder(handle_unknown="ignore", sparse=True)


def compute_metrics(y_true: pd.Series, y_pred: np.ndarray, model_name: str) -> dict[str, float | int | str]:
    return {
        "model_name": model_name,
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
        "support": int(len(y_true)),
    }


def save_confusion_matrix(y_true: pd.Series, y_pred: np.ndarray, path: Path, title: str) -> None:
    labels = sorted(pd.Series(y_true).unique().tolist())
    matrix = confusion_matrix(y_true, y_pred, labels=labels)

    fig_width = max(6, len(labels) * 1.4)
    fig, ax = plt.subplots(figsize=(fig_width, fig_width * 0.78))
    image = ax.imshow(matrix, cmap="Blues")
    ax.set_title(title)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=35, ha="right")
    ax.set_yticks(range(len(labels)))
    ax.set_yticklabels(labels)

    max_value = matrix.max() if matrix.size else 0
    for row_idx in range(matrix.shape[0]):
        for col_idx in range(matrix.shape[1]):
            value = matrix[row_idx, col_idx]
            color = "white" if max_value and value > max_value / 2 else "black"
            ax.text(col_idx, row_idx, f"{value:,}", ha="center", va="center", color=color, fontsize=8)

    fig.colorbar(image, ax=ax, fraction=0.046, pad=0.04)
    fig.tight_layout()
    fig.savefig(path, dpi=160)
    plt.close(fig)


def save_model_coefficients(pipeline: Pipeline, model_name: str, metrics_dir: Path) -> None:
    classifier = pipeline.named_steps["classifier"]
    if not hasattr(classifier, "coef_"):
        return

    try:
        feature_names = pipeline.named_steps["preprocessor"].get_feature_names_out()
    except Exception:
        return

    coef = classifier.coef_
    classes = classifier.classes_
    rows = []

    if coef.shape[0] == 1 and len(classes) == 2:
        class_name = classes[1]
        values = coef[0]
        top_indices = np.argsort(np.abs(values))[-40:][::-1]
        for idx in top_indices:
            rows.append(
                {
                    "class": class_name,
                    "feature": feature_names[idx],
                    "coefficient": float(values[idx]),
                    "absolute_coefficient": float(abs(values[idx])),
                }
            )
    else:
        for class_idx, class_name in enumerate(classes):
            values = coef[class_idx]
            top_indices = np.argsort(np.abs(values))[-20:][::-1]
            for idx in top_indices:
                rows.append(
                    {
                        "class": class_name,
                        "feature": feature_names[idx],
                        "coefficient": float(values[idx]),
                        "absolute_coefficient": float(abs(values[idx])),
                    }
                )

    if rows:
        pd.DataFrame(rows).to_csv(metrics_dir / f"{model_name}_top_coefficients.csv", index=False)
