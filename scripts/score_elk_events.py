"""Score Elasticsearch cyberlog events with the hybrid ML detector."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CACHE_DIR = PROJECT_ROOT / ".cache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("MPLCONFIGDIR", str(CACHE_DIR / "matplotlib"))
os.environ.setdefault("XDG_CACHE_HOME", str(CACHE_DIR))

SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import numpy as np
import pandas as pd
from joblib import load

from cyberlog_ml.modeling import make_train_test_split, train_and_evaluate_on_split
from cyberlog_ml.multisource_data import (
    CATEGORICAL_COLUMNS,
    NUMERIC_COLUMNS,
    RAW_CONTEXT_COLUMNS,
    acquire_multisource_dataset,
    make_record,
    make_web_record,
    port_to_service,
    username_type,
)
from cyberlog_ml.predict_hybrid import (
    SPECIALIST_CATEGORY_MODELS,
    category_model_used_by_source,
    predict_categories_by_source,
    predict_with_artifact,
)


REQUIRED_MODEL_FILES = [
    "multisource_binary_detector.joblib",
    "multisource_attack_category_detector.joblib",
    *SPECIALIST_CATEGORY_MODELS.values(),
]


def es_request(
    base_url: str,
    path: str,
    method: str = "GET",
    payload: dict[str, Any] | list[Any] | str | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 30,
) -> Any:
    url = urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    data: bytes | None = None
    request_headers = headers or {}
    if payload is not None:
        if isinstance(payload, str):
            data = payload.encode("utf-8")
        else:
            data = json.dumps(payload).encode("utf-8")
        request_headers.setdefault("Content-Type", "application/json")
    request = urllib.request.Request(url, data=data, headers=request_headers, method=method)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read().decode("utf-8")
        if not body:
            return {}
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return body


def kibana_request(
    kibana_url: str,
    path: str,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
    timeout: int = 30,
) -> Any:
    url = urllib.parse.urljoin(kibana_url.rstrip("/") + "/", path.lstrip("/"))
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "kbn-xsrf": "true"},
        method=method,
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read().decode("utf-8")
        return json.loads(body) if body else {}


def fetch_elk_events(base_url: str, index: str, limit: int, since_minutes: int | None = None) -> list[dict[str, Any]]:
    query: dict[str, Any] = {"match_all": {}}
    if since_minutes:
        query = {"range": {"@timestamp": {"gte": f"now-{since_minutes}m"}}}
    payload = {
        "size": limit,
        "sort": [{"@timestamp": {"order": "asc", "unmapped_type": "date"}}],
        "query": query,
    }
    response = es_request(base_url, f"{index}/_search", method="POST", payload=payload)
    return response.get("hits", {}).get("hits", [])


def dotted_get(document: dict[str, Any], dotted_path: str, default: Any = "") -> Any:
    current: Any = document
    for part in dotted_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def safe_int(value: Any, default: int = 0) -> int:
    try:
        if value in ("", None) or pd.isna(value):
            return default
        return int(float(value))
    except Exception:
        return default


def attack_category_from_elk(source: dict[str, Any]) -> str:
    category = str(dotted_get(source, "labels.attack_category", "normal") or "normal")
    if category == "firewall_blocked":
        return "firewall_block"
    return category


def binary_label_from_category(category: str) -> str:
    return "normal" if category == "normal" else "attack"


def normalize_elk_events_for_model(hits: list[dict[str, Any]]) -> tuple[pd.DataFrame, pd.DataFrame]:
    source_counts = Counter(
        (
            str(dotted_get(hit.get("_source", {}), "log_source", "unknown")),
            str(dotted_get(hit.get("_source", {}), "source_ip", "")),
        )
        for hit in hits
    )
    ssh_failed_counts = Counter(
        (
            str(dotted_get(hit.get("_source", {}), "source_ip", "")),
            str(dotted_get(hit.get("_source", {}), "user_name", "")),
        )
        for hit in hits
        if str(dotted_get(hit.get("_source", {}), "log_source", "")) == "ssh"
        and str(dotted_get(hit.get("_source", {}), "event.action", "")) == "ssh_failed_password"
    )

    records: list[dict[str, Any]] = []
    metadata_rows: list[dict[str, Any]] = []

    for hit in hits:
        source = hit.get("_source", {})
        log_source = str(dotted_get(source, "log_source", "unknown") or "unknown")
        event_action = str(dotted_get(source, "event.action", "unknown") or "unknown")
        category = attack_category_from_elk(source)
        binary_label = binary_label_from_category(category)
        timestamp = str(source.get("@timestamp", ""))
        source_ip = str(dotted_get(source, "source_ip", ""))
        src_event_count = source_counts[(log_source, source_ip)]
        raw_message = str(dotted_get(source, "raw_message", source.get("message", "")))

        metadata_rows.append(
            {
                "elk_index": hit.get("_index", ""),
                "elk_id": hit.get("_id", ""),
                "elk_timestamp": timestamp,
                "rule_attack_category": category,
            }
        )

        if log_source == "web":
            record = make_web_record(
                source_dataset="elk_cyberlog_events",
                timestamp=timestamp,
                src_ip=source_ip,
                method=str(dotted_get(source, "http_method", "UNKNOWN") or "UNKNOWN"),
                path=str(dotted_get(source, "url_original", "/") or "/"),
                status=safe_int(dotted_get(source, "http_status", 0)),
                response_bytes=float(safe_int(dotted_get(source, "http_bytes", 0))),
                user_agent=str(dotted_get(source, "user_agent_original", "unknown") or "unknown"),
                binary_label=binary_label,
                attack_category=category,
                raw_message=raw_message,
            )
            record["src_event_count"] = src_event_count
        elif log_source == "ssh":
            username = str(dotted_get(source, "user_name", ""))
            failed_count = ssh_failed_counts[(source_ip, username)]
            auth_result = "unknown"
            if event_action == "ssh_failed_password":
                auth_result = "failed"
            elif event_action in {"ssh_success", "ssh_session_opened"}:
                auth_result = "accepted"
            record = make_record(
                log_source="ssh",
                source_dataset="elk_cyberlog_events",
                binary_label=binary_label,
                attack_category=category,
                event_type=event_action,
                protocol="tcp",
                service="ssh",
                timestamp=timestamp,
                src_ip=source_ip,
                src_port=safe_int(dotted_get(source, "source_port", 0)),
                dst_port=22,
                username=username,
                username_type=username_type(username),
                ssh_auth_result=auth_result,
                ssh_failed_logins_10m=failed_count,
                ssh_invalid_user=int("invalid user" in raw_message.lower()),
                ssh_privileged_username=int(username.lower() in {"root", "admin", "administrator"}),
                ssh_success_after_failures=int(auth_result == "accepted" and failed_count > 0),
                src_event_count=src_event_count,
                raw_message=raw_message,
            )
        elif log_source == "firewall":
            dst_port = safe_int(dotted_get(source, "destination_port", 0))
            action = str(dotted_get(source, "firewall.action", "") or event_action).lower()
            blocked = int("deny" in action or "drop" in action or "block" in action or "blocked" in event_action)
            record = make_record(
                log_source="firewall",
                source_dataset="elk_cyberlog_events",
                binary_label=binary_label,
                attack_category=category,
                event_type=event_action,
                protocol="network",
                service=port_to_service(dst_port),
                timestamp=timestamp,
                src_ip=source_ip,
                dst_ip=str(dotted_get(source, "destination_ip", "")),
                src_port=safe_int(dotted_get(source, "source_port", 0)),
                dst_port=dst_port,
                firewall_action=action or "unknown",
                firewall_is_allowed=int(not blocked),
                firewall_is_blocked=blocked,
                denied_admin_port=int(blocked and dst_port in {22, 23, 445, 3389, 5900}),
                src_event_count=src_event_count,
                raw_message=raw_message,
            )
        else:
            record = make_record(
                log_source=log_source,
                source_dataset="elk_cyberlog_events",
                binary_label=binary_label,
                attack_category=category,
                event_type=event_action,
                timestamp=timestamp,
                src_ip=source_ip,
                src_event_count=src_event_count,
                raw_message=raw_message,
            )
        records.append(record)

    return prepare_model_frame(records), pd.DataFrame(metadata_rows)


def prepare_model_frame(records: list[dict[str, Any]]) -> pd.DataFrame:
    df = pd.DataFrame(records)
    required_columns = [*NUMERIC_COLUMNS, *CATEGORICAL_COLUMNS, *RAW_CONTEXT_COLUMNS, "binary_label", "attack_category"]
    for col in required_columns:
        if col not in df.columns:
            df[col] = 0 if col in NUMERIC_COLUMNS else ""

    timestamps = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    fallback_time = pd.Timestamp.now(tz="UTC")
    timestamps = timestamps.fillna(fallback_time)
    df["timestamp"] = timestamps.dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    df["hour"] = timestamps.dt.hour.astype(int)
    df["day_of_week"] = timestamps.dt.dayofweek.astype(int)
    df["is_weekend"] = timestamps.dt.dayofweek.isin([5, 6]).astype(int)

    for col in NUMERIC_COLUMNS:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    src_ip = df["src_ip"].replace("", np.nan)
    counts = df.assign(_src_ip=src_ip).groupby(["log_source", "_src_ip"], dropna=True)["log_source"].transform("size")
    df["src_event_count"] = np.maximum(df["src_event_count"], counts.fillna(1).astype(float))
    df["dst_port"] = df["dst_port"].astype(int)
    unknown_service = df["service"].isin(["", "unknown"])
    df.loc[unknown_service, "service"] = df.loc[unknown_service, "dst_port"].map(port_to_service)

    for col in CATEGORICAL_COLUMNS:
        df[col] = df[col].astype(str).fillna("unknown").replace("", "unknown")
    for col in RAW_CONTEXT_COLUMNS:
        df[col] = df[col].astype(str).fillna("")

    ordered_cols = [
        "binary_label",
        "attack_category",
        *CATEGORICAL_COLUMNS,
        *NUMERIC_COLUMNS,
        *RAW_CONTEXT_COLUMNS,
    ]
    return df[ordered_cols].reset_index(drop=True)


def missing_models(models_dir: Path) -> list[str]:
    return [filename for filename in REQUIRED_MODEL_FILES if not (models_dir / filename).exists()]


def train_demo_models(models_dir: Path, rows_per_source: int, random_state: int) -> None:
    tmp_root = Path("/private/tmp/cyberlog_elk_demo_training")
    raw_dir = tmp_root / "raw"
    processed_dir = tmp_root / "processed"
    metrics_dir = tmp_root / "metrics"
    figures_dir = tmp_root / "figures"
    models_dir.mkdir(parents=True, exist_ok=True)

    df, _ = acquire_multisource_dataset(
        raw_dir=raw_dir,
        processed_dir=processed_dir,
        source="synthetic",
        rows_per_synthetic_source=rows_per_source,
        random_state=random_state,
    )

    binary_train, binary_test = make_train_test_split(df, "binary_label", random_state=random_state)
    category_train, category_test = make_train_test_split(df, "attack_category", random_state=random_state)

    train_and_evaluate_on_split(
        train_df=binary_train,
        test_df=binary_test,
        target_col="binary_label",
        model_name="multisource_binary_detector",
        models_dir=models_dir,
        metrics_dir=metrics_dir,
        figures_dir=figures_dir,
        random_state=random_state,
        metadata={"scope": "unified", "log_source": "all", "training_mode": "local_elk_demo"},
    )
    train_and_evaluate_on_split(
        train_df=category_train,
        test_df=category_test,
        target_col="attack_category",
        model_name="multisource_attack_category_detector",
        models_dir=models_dir,
        metrics_dir=metrics_dir,
        figures_dir=figures_dir,
        random_state=random_state,
        metadata={"scope": "unified", "log_source": "all", "training_mode": "local_elk_demo"},
    )

    for source in sorted(category_train["log_source"].astype(str).unique()):
        source_train = category_train[category_train["log_source"].astype(str).eq(source)].reset_index(drop=True)
        source_test = category_test[category_test["log_source"].astype(str).eq(source)].reset_index(drop=True)
        if len(source_train) == 0 or len(source_test) == 0 or source_train["attack_category"].nunique() < 2:
            continue
        train_and_evaluate_on_split(
            train_df=source_train,
            test_df=source_test,
            target_col="attack_category",
            model_name=f"specialist_{source}_attack_category_detector",
            models_dir=models_dir,
            metrics_dir=metrics_dir,
            figures_dir=figures_dir,
            random_state=random_state,
            metadata={"scope": "specialist", "log_source": source, "training_mode": "local_elk_demo"},
        )


def load_hybrid_artifacts(models_dir: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, dict[str, Any]]]:
    binary_artifact = load(models_dir / "multisource_binary_detector.joblib")
    fallback_category_artifact = load(models_dir / "multisource_attack_category_detector.joblib")
    specialist_artifacts = {}
    for source, filename in SPECIALIST_CATEGORY_MODELS.items():
        path = models_dir / filename
        if path.exists():
            specialist_artifacts[source] = load(path)
    return binary_artifact, fallback_category_artifact, specialist_artifacts


def prediction_confidence(artifact: dict[str, Any], df: pd.DataFrame, positive_class: str | None = None) -> np.ndarray:
    pipeline = artifact["pipeline"]
    feature_columns = artifact["feature_columns"]
    if not hasattr(pipeline, "predict_proba"):
        return np.full(len(df), np.nan)
    probabilities = pipeline.predict_proba(df[feature_columns])
    classes = list(pipeline.classes_)
    if positive_class and positive_class in classes:
        return probabilities[:, classes.index(positive_class)]
    return probabilities.max(axis=1)


def score_events(models_dir: Path, features_df: pd.DataFrame, metadata_df: pd.DataFrame) -> pd.DataFrame:
    binary_artifact, fallback_category_artifact, specialist_artifacts = load_hybrid_artifacts(models_dir)

    scored = pd.concat([metadata_df.reset_index(drop=True), features_df.reset_index(drop=True)], axis=1)
    scored["source_ip"] = scored["src_ip"]
    scored["predicted_binary_label"] = predict_with_artifact(binary_artifact, features_df)
    scored["binary_attack_probability"] = prediction_confidence(binary_artifact, features_df, positive_class="attack")
    scored["category_model_used"] = "not_run_binary_normal"
    scored["predicted_attack_category"] = "normal"
    scored["category_confidence"] = np.nan

    attack_mask = scored["predicted_binary_label"].astype(str).eq("attack")
    if attack_mask.any():
        attack_features = features_df.loc[attack_mask].copy()
        scored.loc[attack_mask, "predicted_attack_category"] = predict_categories_by_source(
            fallback_category_artifact,
            specialist_artifacts,
            attack_features,
        )
        scored.loc[attack_mask, "category_model_used"] = category_model_used_by_source(
            specialist_artifacts,
            attack_features,
        )
        scored.loc[attack_mask, "category_confidence"] = category_confidence_by_source(
            fallback_category_artifact,
            specialist_artifacts,
            attack_features,
        )

    scored["ml_scored_at"] = datetime.now(timezone.utc).isoformat()
    return scored


def category_confidence_by_source(
    fallback_artifact: dict[str, Any],
    specialist_artifacts: dict[str, dict[str, Any]],
    df: pd.DataFrame,
) -> pd.Series:
    confidences = pd.Series(index=df.index, dtype=float)
    if "log_source" not in df.columns:
        confidences.loc[:] = prediction_confidence(fallback_artifact, df)
        return confidences
    for source, source_df in df.groupby(df["log_source"].astype(str)):
        artifact = specialist_artifacts.get(source, fallback_artifact)
        confidences.loc[source_df.index] = prediction_confidence(artifact, source_df)
    return confidences


def write_predictions_csv(scored: pd.DataFrame, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    selected = [
        "elk_timestamp",
        "log_source",
        "source_ip",
        "rule_attack_category",
        "predicted_binary_label",
        "binary_attack_probability",
        "predicted_attack_category",
        "category_confidence",
        "category_model_used",
        "raw_message",
    ]
    scored[selected].to_csv(output_path, index=False)


def write_predictions_to_elasticsearch(base_url: str, scored: pd.DataFrame, index_prefix: str) -> tuple[str, int]:
    index = f"{index_prefix}-{datetime.now(timezone.utc):%Y.%m.%d}"
    lines: list[str] = []
    for _, row in scored.iterrows():
        doc_id = f"{row['elk_index']}__{row['elk_id']}"
        doc = {
            "@timestamp": row["ml_scored_at"],
            "original_event": {
                "index": row["elk_index"],
                "id": row["elk_id"],
                "timestamp": row["elk_timestamp"],
            },
            "log_source": row["log_source"],
            "source_ip": row["source_ip"],
            "rule_attack_category": row["rule_attack_category"],
            "ml": {
                "predicted_binary_label": row["predicted_binary_label"],
                "binary_attack_probability": none_if_nan(row["binary_attack_probability"]),
                "predicted_attack_category": row["predicted_attack_category"],
                "category_confidence": none_if_nan(row["category_confidence"]),
                "category_model_used": row["category_model_used"],
            },
            "raw_message": row["raw_message"],
        }
        lines.append(json.dumps({"index": {"_index": index, "_id": doc_id}}))
        lines.append(json.dumps(doc))
    payload = "\n".join(lines) + "\n"
    response = es_request(base_url, "_bulk?refresh=true", method="POST", payload=payload)
    if response.get("errors"):
        raise RuntimeError(f"Elasticsearch bulk write had errors: {json.dumps(response)[:1000]}")
    return index, len(scored)


def none_if_nan(value: Any) -> Any:
    try:
        if pd.isna(value):
            return None
    except Exception:
        pass
    return float(value) if isinstance(value, (np.floating, float)) else value


def create_kibana_data_view(kibana_url: str, title: str, name: str) -> None:
    payload = {"data_view": {"title": title, "name": name, "timeFieldName": "@timestamp"}}
    try:
        kibana_request(kibana_url, "/api/data_views/data_view", method="POST", payload=payload)
    except urllib.error.HTTPError as exc:
        if exc.code not in {400, 409}:
            raise


def run_once(args: argparse.Namespace) -> pd.DataFrame:
    missing = missing_models(args.models_dir)
    if missing and args.train_demo_models_if_missing:
        print(f"missing models: {', '.join(missing)}")
        print("training local synthetic demo models for ELK scoring...")
        train_demo_models(args.models_dir, args.demo_rows_per_source, args.random_state)
        missing = missing_models(args.models_dir)
    if missing:
        raise SystemExit(
            "Missing model artifacts: "
            + ", ".join(missing)
            + ". Run the ML pipeline first or add --train-demo-models-if-missing."
        )

    hits = fetch_elk_events(args.elasticsearch_url, args.source_index, args.limit, args.since_minutes)
    if not hits:
        print("No ELK events found to score.")
        return pd.DataFrame()

    features_df, metadata_df = normalize_elk_events_for_model(hits)
    scored = score_events(args.models_dir, features_df, metadata_df)
    write_predictions_csv(scored, args.output)
    print(f"scored {len(scored)} ELK events and wrote {args.output}")

    if args.write_back:
        index, count = write_predictions_to_elasticsearch(args.elasticsearch_url, scored, args.predictions_index_prefix)
        print(f"wrote {count} prediction docs to {index}")
        if args.create_kibana_data_view:
            create_kibana_data_view(args.kibana_url, f"{args.predictions_index_prefix}-*", "Cyber Log ML Predictions")
            print(f"created or reused Kibana data view {args.predictions_index_prefix}-*")

    return scored


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elasticsearch-url", default="http://localhost:9200")
    parser.add_argument("--kibana-url", default="http://localhost:5601")
    parser.add_argument("--source-index", default="cyberlog-events-*")
    parser.add_argument("--predictions-index-prefix", default="cyberlog-ml-predictions")
    parser.add_argument("--models-dir", type=Path, default=PROJECT_ROOT / "models")
    parser.add_argument("--limit", type=int, default=500)
    parser.add_argument("--since-minutes", type=int)
    parser.add_argument("--output", type=Path, default=PROJECT_ROOT / "data" / "scenarios" / "elk_ml_scored_events.csv")
    parser.add_argument("--write-back", action="store_true")
    parser.add_argument("--create-kibana-data-view", action="store_true")
    parser.add_argument("--train-demo-models-if-missing", action="store_true")
    parser.add_argument("--demo-rows-per-source", type=int, default=3000)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--watch", action="store_true")
    parser.add_argument("--interval-seconds", type=int, default=30)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if not args.watch:
        run_once(args)
        return

    while True:
        run_once(args)
        time.sleep(args.interval_seconds)


if __name__ == "__main__":
    main()
