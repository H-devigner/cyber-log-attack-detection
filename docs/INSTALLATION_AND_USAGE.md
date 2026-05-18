# Installation And Usage Guide

This guide explains how to install and run the project after cloning the repository. It covers the Python ML pipeline, the optional ELK stack, and the ELK-to-ML scoring bridge.

The project is designed to work on macOS, Linux, and Windows. For Windows, the recommended path is WSL2 with Ubuntu because the project uses shell scripts, Python tooling, and Linux containers.

## 1. What You Are Installing

There are two parts:

| Part | Required? | Purpose |
| --- | --- | --- |
| Python ML pipeline | Yes | Data collection, EDA, preprocessing, model training, batch scoring |
| ELK stack | Optional | Log ingestion, search, Kibana exploration, ML prediction write-back |

High-level flow:

```text
Python ML pipeline:
public/synthetic logs -> normalized table -> EDA -> models -> predictions

ELK demo:
elk/sample-logs/*.log -> Logstash -> Elasticsearch -> Kibana
                                  -> ML scoring bridge -> Elasticsearch predictions -> Kibana
```

## 2. Prerequisites

Minimum tools:

- Git
- Python 3.11 or newer
- `pip`

Optional ELK tools:

- Podman plus `podman-compose`, or Docker with Docker Compose
- At least 4 GB memory available to the container runtime

Official installation references:

- Python virtual environments: <https://docs.python.org/3/library/venv.html>
- Docker Desktop: <https://docs.docker.com/desktop/>
- Podman installation: <https://podman.io/docs/installation>

Recommended container choice:

| OS | Recommended runtime | Notes |
| --- | --- | --- |
| macOS | Podman or Docker Desktop | Podman uses a VM called a Podman machine |
| Linux | Docker Engine/Compose or Podman | Linux runs containers natively |
| Windows | Docker Desktop with WSL2, or Podman Desktop | Clone and run Python commands inside WSL2 Ubuntu when possible |

## 3. Clone The Repository

```bash
git clone https://github.com/H-devigner/cyber-log-attack-detection.git
cd cyber-log-attack-detection
git switch feature/elk-log-ingestion
```

Use `main` if you only want the ML project without the ELK integration. Use `feature/elk-log-ingestion` for the full version with Podman/Docker Compose and Kibana.

## 4. Python Environment Setup

### macOS / Linux / WSL2

```bash
python3 -m venv .venv
./.venv/bin/python -m pip install --upgrade pip
./.venv/bin/pip install -r requirements.txt
```

Optional presentation dependencies:

```bash
./.venv/bin/pip install -r requirements-presentation.txt
```

### Windows PowerShell

If you are not using WSL2:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python -m pip install --upgrade pip
.\.venv\Scripts\pip install -r requirements.txt
```

Optional presentation dependencies:

```powershell
.\.venv\Scripts\pip install -r requirements-presentation.txt
```

## 5. Run The ML Pipeline

### Option A: Full Auto Mode

This tries public datasets and also adds synthetic data for SSH, web, and firewall logs.

```bash
./.venv/bin/python scripts/run_multisource_pipeline.py --source auto
```

Generated outputs:

```text
data/raw/multisource/
data/processed/multisource/
reports/multisource/
models/
```

These outputs are ignored by Git because they can be regenerated.

### Option B: Offline Synthetic Mode

Use this when you do not want public downloads or do not have internet access:

```bash
./.venv/bin/python scripts/run_multisource_pipeline.py --source synthetic
```

### Run Scenario Demo

```bash
./.venv/bin/python scripts/run_scenario_demo.py
```

This creates and scores a small mixed SSH/web/firewall scenario batch.

## 6. Run ELK With Podman

Use this path if you want to avoid Docker Desktop.

### macOS / Windows With Podman Machine

Install Podman and `podman-compose` first. On macOS with Homebrew:

```bash
brew install podman podman-compose
```

Create or start the Podman machine:

```bash
podman machine init
podman machine set --memory 4096
podman machine start
```

Set the Elasticsearch kernel limit inside the VM:

```bash
podman machine ssh "sudo sysctl -w vm.max_map_count=262144"
```

Start ELK:

```bash
podman-compose -f compose.yaml up -d
```

### Linux With Podman

Install Podman and `podman-compose` using your distribution package manager, then set the Elasticsearch kernel limit:

```bash
sudo sysctl -w vm.max_map_count=262144
podman-compose -f compose.yaml up -d
```

## 7. Run ELK With Docker

Use this path if you already have Docker installed.

### macOS / Windows

Install and start Docker Desktop. On Windows, enable WSL2 integration if you are running commands inside WSL2.

Start ELK:

```bash
docker compose -f compose.yaml up -d
```

### Linux

Install Docker Engine and Docker Compose, then set the Elasticsearch kernel limit:

```bash
sudo sysctl -w vm.max_map_count=262144
docker compose -f compose.yaml up -d
```

## 8. Verify ELK Is Running

With Podman:

```bash
podman-compose -f compose.yaml ps
```

With Docker:

```bash
docker compose -f compose.yaml ps
```

Expected services:

```text
cyberlog-elasticsearch
cyberlog-kibana
cyberlog-logstash
```

Open:

```text
Elasticsearch: http://localhost:9200
Kibana:        http://localhost:5601
```

Check indexed events:

```bash
curl 'http://localhost:9200/_cat/indices/cyberlog-events-*?v'
```

Create or use the Kibana data view:

```text
Cyber Log Events
cyberlog-events-*
time field: @timestamp
```

## 9. What ELK Reads

Logstash reads the sample raw logs:

```text
elk/sample-logs/ssh.log
elk/sample-logs/web_access.log
elk/sample-logs/firewall.log
```

Those are demo files for the same log families the ML model targets. They are not the original public training datasets.

The relationship is:

```text
Logstash reads raw sample files
Elasticsearch stores parsed events
ML bridge reads Elasticsearch events
ML bridge converts events into model features
ML bridge scores events and writes predictions back
Kibana displays both raw parsed events and ML predictions
```

## 10. Export ELK Events To CSV

```bash
./.venv/bin/python scripts/export_elk_events.py \
  --output data/scenarios/elk_exported_events.csv
```

This writes a small CSV snapshot of parsed Elasticsearch events.

## 11. Score ELK Events With ML

If models already exist:

```bash
./.venv/bin/python scripts/score_elk_events.py \
  --write-back \
  --create-kibana-data-view
```

If `models/` does not exist yet, train local demo models first:

```bash
./.venv/bin/python scripts/score_elk_events.py \
  --train-demo-models-if-missing \
  --write-back \
  --create-kibana-data-view
```

Outputs:

```text
data/scenarios/elk_ml_scored_events.csv
cyberlog-ml-predictions-YYYY.MM.dd
```

Open Kibana and use:

```text
Cyber Log ML Predictions
cyberlog-ml-predictions-*
time field: @timestamp
```

Useful Kibana filters:

```text
ml.predicted_binary_label: attack
```

```text
log_source: ssh
```

```text
ml.predicted_attack_category: firewall_block
```

## 12. Near-Real-Time Demo Mode

The current project supports polling-based demo scoring:

```bash
./.venv/bin/python scripts/score_elk_events.py \
  --write-back \
  --create-kibana-data-view \
  --watch \
  --interval-seconds 30
```

This is not a production streaming service. It repeatedly checks Elasticsearch, scores events, and writes prediction documents back. A production design should turn this logic into a service, queue consumer, or streaming job.

## 13. Stop ELK

With Podman:

```bash
podman-compose -f compose.yaml down
```

Remove the local Elasticsearch volume too:

```bash
podman-compose -f compose.yaml down -v
```

With Docker:

```bash
docker compose -f compose.yaml down
docker compose -f compose.yaml down -v
```

## 14. Rebuild The Presentation

```bash
./.venv/bin/pip install -r requirements-presentation.txt
./.venv/bin/python scripts/build_presentation.py
```

Output:

```text
presentation/cyber_log_attack_detection_overview.pptx
```

## 15. Troubleshooting

### `podman compose` says no compose provider is installed

Use `podman-compose`:

```bash
brew install podman-compose
podman-compose -f compose.yaml up -d
```

### Elasticsearch complains about `vm.max_map_count`

Podman machine:

```bash
podman machine ssh "sudo sysctl -w vm.max_map_count=262144"
```

Linux host:

```bash
sudo sysctl -w vm.max_map_count=262144
```

### Kibana is slow to open

Kibana can take 1-3 minutes after Elasticsearch starts. Check logs:

```bash
podman logs -f cyberlog-kibana
```

or:

```bash
docker logs -f cyberlog-kibana
```

### Yellow Elasticsearch index health

Yellow is expected for this local single-node demo because replicas cannot be assigned to another node. Ingestion still works.

### Model artifacts are missing

Run the full pipeline:

```bash
./.venv/bin/python scripts/run_multisource_pipeline.py --source synthetic
```

or let the ELK scorer create small local demo models:

```bash
./.venv/bin/python scripts/score_elk_events.py --train-demo-models-if-missing
```

### Windows path issues

Prefer WSL2 Ubuntu and clone the repository inside the Linux filesystem:

```text
~/projects/cyber-log-attack-detection
```

Avoid running heavy Linux-container workflows from a mounted Windows path like `/mnt/c/...` unless you know the performance tradeoff.

## 16. Quick Command Summary

ML only:

```bash
git clone https://github.com/H-devigner/cyber-log-attack-detection.git
cd cyber-log-attack-detection
git switch feature/elk-log-ingestion
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt
./.venv/bin/python scripts/run_multisource_pipeline.py --source synthetic
```

ELK plus ML scoring with Podman:

```bash
podman machine start
podman machine ssh "sudo sysctl -w vm.max_map_count=262144"
podman-compose -f compose.yaml up -d
./.venv/bin/python scripts/score_elk_events.py \
  --train-demo-models-if-missing \
  --write-back \
  --create-kibana-data-view
```

ELK plus ML scoring with Docker:

```bash
docker compose -f compose.yaml up -d
./.venv/bin/python scripts/score_elk_events.py \
  --train-demo-models-if-missing \
  --write-back \
  --create-kibana-data-view
```
