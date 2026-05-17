from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


def run_eda(df: pd.DataFrame, reports_dir: Path, figures_dir: Path) -> None:
    reports_dir.mkdir(parents=True, exist_ok=True)
    figures_dir.mkdir(parents=True, exist_ok=True)

    save_tables(df, reports_dir)
    plot_label_distribution(df, figures_dir)
    plot_attack_category_distribution(df, figures_dir)
    plot_source_distribution(df, figures_dir)
    plot_attack_by_source(df, figures_dir)
    plot_protocol_by_label(df, figures_dir)
    plot_service_attack_rate(df, figures_dir)
    plot_numeric_correlation(df, figures_dir)


def save_tables(df: pd.DataFrame, reports_dir: Path) -> None:
    summary = pd.DataFrame(
        [
            {
                "rows": len(df),
                "columns": len(df.columns),
                "duplicate_rows": int(df.duplicated().sum()),
                "source_dataset": ", ".join(sorted(df["source_dataset"].astype(str).unique()))
                if "source_dataset" in df
                else "unknown",
            }
        ]
    )
    summary.to_csv(reports_dir / "dataset_summary.csv", index=False)

    profile_rows = []
    for col in df.columns:
        non_null = df[col].dropna()
        example = non_null.iloc[0] if len(non_null) else ""
        profile_rows.append(
            {
                "column": col,
                "dtype": str(df[col].dtype),
                "missing_count": int(df[col].isna().sum()),
                "missing_pct": float(df[col].isna().mean()),
                "unique_values": int(df[col].nunique(dropna=True)),
                "example": example,
            }
        )
    pd.DataFrame(profile_rows).to_csv(reports_dir / "column_profile.csv", index=False)

    df.isna().sum().sort_values(ascending=False).rename("missing_count").to_csv(
        reports_dir / "missing_values.csv"
    )

    numeric = df.select_dtypes(include=np.number)
    if not numeric.empty:
        numeric.describe(percentiles=[0.01, 0.05, 0.5, 0.95, 0.99]).T.to_csv(
            reports_dir / "numeric_summary.csv"
        )

    if "binary_label" in df:
        df["binary_label"].value_counts().rename_axis("binary_label").rename("rows").to_csv(
            reports_dir / "binary_label_distribution.csv"
        )
    if "attack_category" in df:
        df["attack_category"].value_counts().rename_axis("attack_category").rename("rows").to_csv(
            reports_dir / "attack_category_distribution.csv"
        )
    if "log_source" in df:
        df["log_source"].value_counts().rename_axis("log_source").rename("rows").to_csv(
            reports_dir / "log_source_distribution.csv"
        )


def plot_label_distribution(df: pd.DataFrame, figures_dir: Path) -> None:
    if "binary_label" not in df:
        return
    counts = df["binary_label"].value_counts().sort_values(ascending=True)
    fig, ax = plt.subplots(figsize=(7, 4))
    counts.plot(kind="barh", ax=ax, color=["#3a7ca5", "#d1495b"][: len(counts)])
    ax.set_title("Binary label distribution")
    ax.set_xlabel("Rows")
    ax.set_ylabel("")
    annotate_bars(ax)
    fig.tight_layout()
    fig.savefig(figures_dir / "binary_label_distribution.png", dpi=160)
    plt.close(fig)


def plot_attack_category_distribution(df: pd.DataFrame, figures_dir: Path) -> None:
    if "attack_category" not in df:
        return
    counts = df["attack_category"].value_counts().sort_values(ascending=True)
    fig, ax = plt.subplots(figsize=(8, 4.8))
    counts.plot(kind="barh", ax=ax, color="#4f7cac")
    ax.set_title("Attack category distribution")
    ax.set_xlabel("Rows")
    ax.set_ylabel("")
    annotate_bars(ax)
    fig.tight_layout()
    fig.savefig(figures_dir / "attack_category_distribution.png", dpi=160)
    plt.close(fig)


def plot_protocol_by_label(df: pd.DataFrame, figures_dir: Path) -> None:
    required = {"protocol_type", "binary_label"}
    if not required.issubset(df.columns):
        return
    table = pd.crosstab(df["protocol_type"], df["binary_label"], normalize="index")
    fig, ax = plt.subplots(figsize=(7, 4.5))
    table.plot(kind="bar", stacked=True, ax=ax, color=["#d1495b", "#3a7ca5"])
    ax.set_title("Binary label mix by protocol")
    ax.set_xlabel("Protocol")
    ax.set_ylabel("Share of protocol traffic")
    ax.legend(title="Label")
    fig.tight_layout()
    fig.savefig(figures_dir / "protocol_by_binary_label.png", dpi=160)
    plt.close(fig)


def plot_source_distribution(df: pd.DataFrame, figures_dir: Path) -> None:
    if "log_source" not in df:
        return
    counts = df["log_source"].value_counts().sort_values(ascending=True)
    fig, ax = plt.subplots(figsize=(7, 4))
    counts.plot(kind="barh", ax=ax, color="#3a7ca5")
    ax.set_title("Rows by log source")
    ax.set_xlabel("Rows")
    ax.set_ylabel("")
    annotate_bars(ax)
    fig.tight_layout()
    fig.savefig(figures_dir / "log_source_distribution.png", dpi=160)
    plt.close(fig)


def plot_attack_by_source(df: pd.DataFrame, figures_dir: Path) -> None:
    required = {"log_source", "binary_label"}
    if not required.issubset(df.columns):
        return
    table = pd.crosstab(df["log_source"], df["binary_label"], normalize="index")
    fig, ax = plt.subplots(figsize=(7, 4.5))
    table.plot(kind="bar", stacked=True, ax=ax, color=["#d1495b", "#3a7ca5"])
    ax.set_title("Binary label mix by log source")
    ax.set_xlabel("Log source")
    ax.set_ylabel("Share of source rows")
    ax.legend(title="Label")
    fig.tight_layout()
    fig.savefig(figures_dir / "attack_mix_by_log_source.png", dpi=160)
    plt.close(fig)


def plot_service_attack_rate(df: pd.DataFrame, figures_dir: Path) -> None:
    required = {"service", "binary_label"}
    if not required.issubset(df.columns):
        return

    work = df[["service", "binary_label"]].copy()
    work["attack_flag"] = work["binary_label"].eq("attack").astype(int)
    grouped = work.groupby("service").agg(rows=("attack_flag", "size"), attack_rate=("attack_flag", "mean"))
    grouped = grouped[grouped["rows"] >= max(25, int(len(df) * 0.001))]
    top = grouped.sort_values(["attack_rate", "rows"], ascending=[False, False]).head(15)
    if top.empty:
        return

    fig, ax = plt.subplots(figsize=(9, 5))
    top.sort_values("attack_rate").plot(kind="barh", y="attack_rate", ax=ax, legend=False, color="#e07a5f")
    ax.set_title("Services with highest attack rate")
    ax.set_xlabel("Attack rate")
    ax.set_ylabel("")
    ax.set_xlim(0, 1)
    fig.tight_layout()
    fig.savefig(figures_dir / "top_services_by_attack_rate.png", dpi=160)
    plt.close(fig)


def plot_numeric_correlation(df: pd.DataFrame, figures_dir: Path) -> None:
    numeric = df.select_dtypes(include=np.number).copy()
    if "binary_label" in df:
        numeric["attack_flag"] = df["binary_label"].eq("attack").astype(int)
    numeric = numeric.loc[:, numeric.nunique(dropna=True) > 1]
    if numeric.shape[1] < 2:
        return

    if "attack_flag" in numeric:
        corr_to_target = numeric.corr(numeric_only=True)["attack_flag"].abs().sort_values(ascending=False)
        selected = corr_to_target.head(14).index.tolist()
    else:
        selected = numeric.var().sort_values(ascending=False).head(14).index.tolist()

    corr = numeric[selected].corr(numeric_only=True).fillna(0.0)
    fig, ax = plt.subplots(figsize=(10, 8))
    image = ax.imshow(corr, cmap="coolwarm", vmin=-1, vmax=1)
    ax.set_xticks(range(len(corr.columns)))
    ax.set_xticklabels(corr.columns, rotation=45, ha="right", fontsize=8)
    ax.set_yticks(range(len(corr.index)))
    ax.set_yticklabels(corr.index, fontsize=8)
    ax.set_title("Correlation among target-relevant numeric features")
    fig.colorbar(image, ax=ax, fraction=0.046, pad=0.04)
    fig.tight_layout()
    fig.savefig(figures_dir / "numeric_correlation_heatmap.png", dpi=160)
    plt.close(fig)


def annotate_bars(ax: plt.Axes) -> None:
    for patch in ax.patches:
        width = patch.get_width()
        ax.text(
            width,
            patch.get_y() + patch.get_height() / 2,
            f" {int(width):,}",
            va="center",
            fontsize=9,
        )
