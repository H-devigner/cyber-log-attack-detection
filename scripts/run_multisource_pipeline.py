from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CACHE_DIR = PROJECT_ROOT / ".cache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("MPLCONFIGDIR", str(CACHE_DIR / "matplotlib"))
os.environ.setdefault("XDG_CACHE_HOME", str(CACHE_DIR))

SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from cyberlog_ml.eda import run_eda
from cyberlog_ml.modeling import (
    TrainingResult,
    evaluate_model_artifact,
    make_train_test_split,
    train_and_evaluate_on_split,
)
from cyberlog_ml.multisource_data import acquire_multisource_dataset


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the SSH/web/firewall multi-source log pipeline.")
    parser.add_argument(
        "--source",
        choices=["auto", "synthetic"],
        default="auto",
        help="auto tries public real datasets and always adds synthetic SSH/web/firewall rows.",
    )
    parser.add_argument("--synthetic-rows-per-source", type=int, default=12_000)
    parser.add_argument("--real-firewall-limit", type=int, default=15_000)
    parser.add_argument("--real-web-limit", type=int, default=8_000)
    parser.add_argument("--real-ssh-limit", type=int, default=8_000)
    parser.add_argument("--random-state", type=int, default=42)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    raw_dir = PROJECT_ROOT / "data" / "raw" / "multisource"
    processed_dir = PROJECT_ROOT / "data" / "processed" / "multisource"
    reports_dir = PROJECT_ROOT / "reports" / "multisource"
    figures_dir = reports_dir / "figures"
    metrics_dir = reports_dir / "metrics"
    models_dir = PROJECT_ROOT / "models"

    df, dataset_info = acquire_multisource_dataset(
        raw_dir=raw_dir,
        processed_dir=processed_dir,
        source=args.source,
        rows_per_synthetic_source=args.synthetic_rows_per_source,
        real_firewall_limit=args.real_firewall_limit,
        real_web_limit=args.real_web_limit,
        real_ssh_limit=args.real_ssh_limit,
        random_state=args.random_state,
    )

    scoring_sample_path = processed_dir / "sample_multisource_for_scoring.csv"
    df.drop(
        columns=["binary_label", "attack_category", "timestamp", "src_ip", "dst_ip", "username", "url_path", "user_agent", "raw_message"],
        errors="ignore",
    ).head(40).to_csv(scoring_sample_path, index=False)

    run_eda(df, reports_dir=reports_dir, figures_dir=figures_dir)

    binary_train_df, binary_test_df = make_train_test_split(
        df,
        target_col="binary_label",
        random_state=args.random_state,
    )
    category_train_df, category_test_df = make_train_test_split(
        df,
        target_col="attack_category",
        random_state=args.random_state,
    )

    binary_result = train_and_evaluate_on_split(
        train_df=binary_train_df,
        test_df=binary_test_df,
        target_col="binary_label",
        model_name="multisource_binary_detector",
        models_dir=models_dir,
        metrics_dir=metrics_dir,
        figures_dir=figures_dir,
        random_state=args.random_state,
        metadata={"scope": "unified", "log_source": "all"},
    )
    category_result = train_and_evaluate_on_split(
        train_df=category_train_df,
        test_df=category_test_df,
        target_col="attack_category",
        model_name="multisource_attack_category_detector",
        models_dir=models_dir,
        metrics_dir=metrics_dir,
        figures_dir=figures_dir,
        random_state=args.random_state,
        metadata={"scope": "unified", "log_source": "all"},
    )

    comparison_df, specialist_results = train_specialists_and_compare(
        binary_unified_result=binary_result,
        category_unified_result=category_result,
        binary_train_df=binary_train_df,
        binary_test_df=binary_test_df,
        category_train_df=category_train_df,
        category_test_df=category_test_df,
        models_dir=models_dir,
        metrics_dir=metrics_dir,
        figures_dir=figures_dir,
        random_state=args.random_state,
    )
    comparison_path = metrics_dir / "unified_vs_specialist_comparison.csv"
    comparison_df.to_csv(comparison_path, index=False)
    decision = choose_final_model_strategy(comparison_df)
    decision_report_path = reports_dir / "model_strategy_decision.md"
    write_model_strategy_report(decision_report_path, comparison_df, specialist_results, decision)

    summary_path = reports_dir / "multisource_pipeline_summary.md"
    write_multisource_summary(
        summary_path,
        dataset_info.to_dict(),
        binary_result,
        category_result,
        specialist_results,
        comparison_path,
        decision_report_path,
        decision,
        scoring_sample_path,
    )

    print(
        json.dumps(
            {
                "dataset": dataset_info.to_dict(),
                "summary": str(summary_path),
                "comparison": str(comparison_path),
                "decision": decision["strategy"],
            },
            indent=2,
        )
    )


def write_multisource_summary(
    path: Path,
    dataset_info: dict[str, object],
    binary_result: TrainingResult,
    category_result: TrainingResult,
    specialist_results: list[TrainingResult],
    comparison_path: Path,
    decision_report_path: Path,
    decision: dict[str, object],
    scoring_sample_path: Path,
) -> None:
    lines = [
        "# Multi-Source Pipeline Summary",
        "",
        "## Dataset",
        "",
        f"- Source: `{dataset_info['source']}`",
        f"- Rows: `{dataset_info['rows']}`",
        f"- Columns: `{dataset_info['columns']}`",
        f"- Processed path: `{dataset_info['path']}`",
        "",
        "## Source Loading",
        "",
    ]

    for report in dataset_info.get("source_reports", []):
        detail = f" - {report['detail']}" if report.get("detail") else ""
        lines.append(f"- `{report['source']}`: {report['status']}, rows `{report['rows']}`{detail}")

    lines.extend(
        [
            "",
            "## Binary Detector",
            "",
            metrics_line(binary_result.metrics),
            metrics_line(binary_result.baseline_metrics, prefix="Baseline"),
            f"- Model artifact: `{binary_result.model_path}`",
            f"- Metrics JSON: `{binary_result.metrics_path}`",
            f"- Classification report: `{binary_result.report_path}`",
            f"- Confusion matrix: `{binary_result.confusion_matrix_path}`",
            "",
            "## Attack Category Detector",
            "",
            metrics_line(category_result.metrics),
            metrics_line(category_result.baseline_metrics, prefix="Baseline"),
            f"- Model artifact: `{category_result.model_path}`",
            f"- Metrics JSON: `{category_result.metrics_path}`",
            f"- Classification report: `{category_result.report_path}`",
            f"- Confusion matrix: `{category_result.confusion_matrix_path}`",
            "",
            "## Specialist Models",
            "",
            f"- Specialist models trained: `{len(specialist_results)}`",
            f"- Unified-vs-specialist comparison CSV: `{comparison_path}`",
            f"- Model strategy decision report: `{decision_report_path}`",
            f"- Final strategy: `{decision['strategy']}`",
            f"- Decision summary: {decision['summary']}",
            "",
            "## Scoring Sample",
            "",
            f"- Feature-only sample CSV: `{scoring_sample_path}`",
        ]
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def train_specialists_and_compare(
    binary_unified_result: TrainingResult,
    category_unified_result: TrainingResult,
    binary_train_df,
    binary_test_df,
    category_train_df,
    category_test_df,
    models_dir: Path,
    metrics_dir: Path,
    figures_dir: Path,
    random_state: int,
) -> tuple:
    comparison_rows = []
    specialist_results: list[TrainingResult] = []
    sources = sorted(set(binary_train_df["log_source"].astype(str)) | set(category_train_df["log_source"].astype(str)))

    target_specs = [
        {
            "target_col": "binary_label",
            "target_name": "binary",
            "unified_result": binary_unified_result,
            "train_df": binary_train_df,
            "test_df": binary_test_df,
        },
        {
            "target_col": "attack_category",
            "target_name": "attack_category",
            "unified_result": category_unified_result,
            "train_df": category_train_df,
            "test_df": category_test_df,
        },
    ]

    for spec in target_specs:
        target_col = spec["target_col"]
        target_name = spec["target_name"]
        unified_result = spec["unified_result"]
        train_df = spec["train_df"]
        test_df = spec["test_df"]

        for source in sources:
            source_train = train_df[train_df["log_source"].astype(str).eq(source)].reset_index(drop=True)
            source_test = test_df[test_df["log_source"].astype(str).eq(source)].reset_index(drop=True)
            if len(source_train) == 0 or len(source_test) == 0 or source_train[target_col].nunique() < 2:
                continue

            specialist_name = f"specialist_{source}_{target_name}_detector"
            specialist_result = train_and_evaluate_on_split(
                train_df=source_train,
                test_df=source_test,
                target_col=target_col,
                model_name=specialist_name,
                models_dir=models_dir,
                metrics_dir=metrics_dir,
                figures_dir=figures_dir,
                random_state=random_state,
                metadata={"scope": "specialist", "log_source": source},
            )
            specialist_results.append(specialist_result)

            unified_metrics = evaluate_model_artifact(
                unified_result.model_path,
                source_test,
                target_col=target_col,
                model_name=f"unified_on_{source}_{target_name}",
            )
            specialist_metrics = specialist_result.metrics
            comparison_rows.append(
                {
                    "target": target_col,
                    "log_source": source,
                    "test_rows": int(len(source_test)),
                    "classes": "|".join(sorted(source_test[target_col].astype(str).unique())),
                    "unified_accuracy": unified_metrics["accuracy"],
                    "specialist_accuracy": specialist_metrics["accuracy"],
                    "delta_accuracy_specialist_minus_unified": specialist_metrics["accuracy"] - unified_metrics["accuracy"],
                    "unified_balanced_accuracy": unified_metrics["balanced_accuracy"],
                    "specialist_balanced_accuracy": specialist_metrics["balanced_accuracy"],
                    "delta_balanced_accuracy_specialist_minus_unified": specialist_metrics["balanced_accuracy"]
                    - unified_metrics["balanced_accuracy"],
                    "unified_macro_f1": unified_metrics["macro_f1"],
                    "specialist_macro_f1": specialist_metrics["macro_f1"],
                    "delta_macro_f1_specialist_minus_unified": specialist_metrics["macro_f1"] - unified_metrics["macro_f1"],
                    "unified_weighted_f1": unified_metrics["weighted_f1"],
                    "specialist_weighted_f1": specialist_metrics["weighted_f1"],
                    "delta_weighted_f1_specialist_minus_unified": specialist_metrics["weighted_f1"]
                    - unified_metrics["weighted_f1"],
                    "unified_model_path": unified_result.model_path,
                    "specialist_model_path": specialist_result.model_path,
                }
            )

    import pandas as pd

    comparison_df = pd.DataFrame(comparison_rows)
    return comparison_df.sort_values(["target", "log_source"]).reset_index(drop=True), specialist_results


def choose_final_model_strategy(comparison_df) -> dict[str, object]:
    binary = comparison_df[comparison_df["target"].eq("binary_label")]
    category = comparison_df[comparison_df["target"].eq("attack_category")]
    binary_delta = float(binary["delta_macro_f1_specialist_minus_unified"].mean()) if len(binary) else 0.0
    category_delta = float(category["delta_macro_f1_specialist_minus_unified"].mean()) if len(category) else 0.0
    category_wins = int((category["delta_macro_f1_specialist_minus_unified"] > 0.01).sum()) if len(category) else 0
    binary_wins = int((binary["delta_macro_f1_specialist_minus_unified"] > 0.01).sum()) if len(binary) else 0

    if category_delta > 0.01 or category_wins >= 2:
        strategy = "hybrid_unified_binary_plus_specialist_categories"
        summary = (
            "Use the unified binary detector for first-pass triage, then route SSH/web/firewall rows "
            "to specialist category detectors for source-specific diagnosis."
        )
    elif binary_delta > 0.01 and binary_wins >= 2:
        strategy = "specialists_for_binary_and_category"
        summary = "Use specialist models for both binary detection and attack-category routing."
    else:
        strategy = "unified_models_with_specialists_as_optional_checks"
        summary = (
            "Keep the unified binary and category models as the default because specialists did not "
            "show a consistent enough gain on the current data."
        )

    return {
        "strategy": strategy,
        "summary": summary,
        "average_binary_macro_f1_delta": binary_delta,
        "average_category_macro_f1_delta": category_delta,
        "binary_sources_with_material_specialist_gain": binary_wins,
        "category_sources_with_material_specialist_gain": category_wins,
    }


def write_model_strategy_report(
    path: Path,
    comparison_df,
    specialist_results: list[TrainingResult],
    decision: dict[str, object],
) -> None:
    lines = [
        "# Model Strategy Decision",
        "",
        "## Final Decision",
        "",
        f"- Strategy: `{decision['strategy']}`",
        f"- Summary: {decision['summary']}",
        f"- Average binary macro-F1 specialist delta: `{decision['average_binary_macro_f1_delta']:.4f}`",
        f"- Average category macro-F1 specialist delta: `{decision['average_category_macro_f1_delta']:.4f}`",
        "",
        "## Unified Vs Specialist Comparison",
        "",
        comparison_table(comparison_df),
        "",
        "## Specialist Model Artifacts",
        "",
    ]
    for result in specialist_results:
        lines.append(f"- `{Path(result.model_path).name}`: {metrics_inline(result.metrics)}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def comparison_table(comparison_df) -> str:
    if comparison_df.empty:
        return "No specialist comparison rows were generated."
    columns = [
        "target",
        "log_source",
        "test_rows",
        "unified_macro_f1",
        "specialist_macro_f1",
        "delta_macro_f1_specialist_minus_unified",
        "unified_weighted_f1",
        "specialist_weighted_f1",
    ]
    header = "| " + " | ".join(columns) + " |"
    divider = "| " + " | ".join(["---"] * len(columns)) + " |"
    rows = []
    for _, row in comparison_df[columns].iterrows():
        values = []
        for col in columns:
            value = row[col]
            if isinstance(value, float):
                values.append(f"{value:.4f}")
            else:
                values.append(str(value))
        rows.append("| " + " | ".join(values) + " |")
    return "\n".join([header, divider, *rows])


def metrics_inline(metrics: dict[str, float | int | str]) -> str:
    return (
        f"accuracy `{metrics['accuracy']:.4f}`, "
        f"balanced accuracy `{metrics['balanced_accuracy']:.4f}`, "
        f"macro F1 `{metrics['macro_f1']:.4f}`, "
        f"weighted F1 `{metrics['weighted_f1']:.4f}`"
    )


def metrics_line(metrics: dict[str, float | int | str], prefix: str = "Model") -> str:
    return (
        f"- {prefix}: accuracy `{metrics['accuracy']:.4f}`, "
        f"balanced accuracy `{metrics['balanced_accuracy']:.4f}`, "
        f"macro F1 `{metrics['macro_f1']:.4f}`, "
        f"weighted F1 `{metrics['weighted_f1']:.4f}`"
    )


if __name__ == "__main__":
    main()
