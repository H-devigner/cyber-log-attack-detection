"""Export normalized events from Elasticsearch for ML experiments."""

from __future__ import annotations

import argparse
import csv
import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


DEFAULT_FIELDS = [
    "@timestamp",
    "log_source",
    "event.action",
    "labels.attack_category",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "user_name",
    "http_method",
    "url_original",
    "http_status",
    "http_bytes",
    "network_protocol",
    "raw_message",
]


def dotted_get(document: dict[str, Any], dotted_path: str) -> Any:
    current: Any = document
    for part in dotted_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return ""
        current = current[part]
    return current


def fetch_events(base_url: str, index: str, limit: int) -> list[dict[str, Any]]:
    query = {
        "size": limit,
        "sort": [{"@timestamp": {"order": "asc", "unmapped_type": "date"}}],
        "query": {"match_all": {}},
    }
    url = urllib.parse.urljoin(base_url.rstrip("/") + "/", f"{index}/_search")
    request = urllib.request.Request(
        url,
        data=json.dumps(query).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        payload = json.loads(response.read().decode("utf-8"))
    return [hit.get("_source", {}) for hit in payload.get("hits", {}).get("hits", [])]


def write_csv(rows: list[dict[str, Any]], output_path: Path, fields: list[str]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: dotted_get(row, field) for field in fields})


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://localhost:9200")
    parser.add_argument("--index", default="cyberlog-events-*")
    parser.add_argument("--limit", type=int, default=500)
    parser.add_argument("--output", type=Path, default=Path("data/scenarios/elk_exported_events.csv"))
    parser.add_argument("--fields", nargs="*", default=DEFAULT_FIELDS)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        rows = fetch_events(args.base_url, args.index, args.limit)
    except urllib.error.URLError as exc:
        raise SystemExit(f"Could not reach Elasticsearch at {args.base_url}: {exc}") from exc

    write_csv(rows, args.output, args.fields)
    print(f"exported {len(rows)} events to {args.output}")


if __name__ == "__main__":
    main()
