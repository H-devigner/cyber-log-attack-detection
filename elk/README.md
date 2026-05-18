# ELK Log Ingestion Branch

This branch adds a local ELK setup for the same three log families as the ML pipeline:

- SSH authentication logs
- Web-server access logs
- Firewall traffic logs

It is intended for local development and demos. Logstash reads the sample logs in `elk/sample-logs/`, parses them into normalized security-event fields, and indexes them into Elasticsearch. Kibana then lets you inspect and dashboard those indexed events.

The sample files are examples of the same kinds of logs the ML project targets. They are not the training datasets themselves. The ML model expects normalized feature rows, while Logstash reads raw log lines. The bridge script `scripts/score_elk_events.py` connects those worlds by reading indexed ELK events, converting them into model features, scoring them, and writing predictions back to Elasticsearch.

## Requirements

- Podman
- `podman compose` or `podman-compose`
- At least 4 GB of memory available to the Podman machine

This project now uses `compose.yaml` as the stack definition. The container images still come from Elastic's `docker.elastic.co` registry; Podman can pull from that registry without Docker Desktop.

When this branch was updated, Podman CLI existed locally but no Podman machine had been initialized yet, so the stack files were updated but not run locally.

## Start The Stack

On macOS, create and start the Podman VM first:

```bash
podman machine init
podman machine set --memory 4096
podman machine start
```

If Elasticsearch fails with a `vm.max_map_count` message, set it inside the Podman VM:

```bash
podman machine ssh "sudo sysctl -w vm.max_map_count=262144"
```

Start the stack from the repository root:

```bash
podman-compose -f compose.yaml up -d
```

If `podman-compose` is missing, install it first:

```bash
brew install podman-compose
podman-compose -f compose.yaml up -d
```

Open:

- Kibana: `http://localhost:5601`
- Elasticsearch: `http://localhost:9200`

In Kibana, create a data view named:

```text
cyberlog-events-*
```

Use `@timestamp` as the time field.

## What Logstash Does

The Logstash pipeline in `elk/logstash/pipeline/cyberlog.conf`:

- tags each event with `log_source`: `ssh`, `web`, or `firewall`
- parses useful source IP, user, URL, HTTP status, firewall action, and port fields
- adds a lightweight `event.action`
- adds a demo `labels.attack_category` value when the sample pattern is clearly suspicious
- writes events to Elasticsearch index `cyberlog-events-YYYY.MM.dd`

This does not replace the ML models. ELK is the ingestion and exploration layer:

```text
raw logs -> Logstash parsing -> Elasticsearch storage -> Kibana review
                                    |
                                    v
                         ML feature conversion
                                    |
                                    v
                         hybrid model scoring
                                    |
                                    v
                         predictions back to Elasticsearch/Kibana
```

## Export Events For ML

After the stack is running and Logstash has indexed sample events:

```bash
./.venv/bin/python scripts/export_elk_events.py \
  --output data/scenarios/elk_exported_events.csv
```

That CSV is a bridge format for later ML scoring. It gives the data-science pipeline normalized rows coming from ELK instead of directly from local CSV/log generators.

## Score ELK Events With ML

The integrated scoring path is:

```text
cyberlog-events-* in Elasticsearch
  -> scripts/score_elk_events.py
  -> model feature table
  -> unified binary detector
  -> source-specific category detector when attack
  -> cyberlog-ml-predictions-* in Elasticsearch
```

If model artifacts already exist in `models/`:

```bash
./.venv/bin/python scripts/score_elk_events.py \
  --write-back \
  --create-kibana-data-view
```

If `models/` is missing, train local synthetic demo models first:

```bash
./.venv/bin/python scripts/score_elk_events.py \
  --train-demo-models-if-missing \
  --write-back \
  --create-kibana-data-view
```

After scoring, open Kibana and use the data view:

```text
cyberlog-ml-predictions-*
```

Useful Kibana filters:

```text
ml.predicted_binary_label: attack
```

```text
log_source: ssh
```

```text
ml.predicted_attack_category: web_sql_injection
```

For near-real-time demo scoring, run the script in polling mode:

```bash
./.venv/bin/python scripts/score_elk_events.py \
  --write-back \
  --create-kibana-data-view \
  --watch \
  --interval-seconds 30
```

This keeps checking Elasticsearch and writing/updating prediction documents. It is suitable for a demo, but a production deployment should use a long-running service, queue, or streaming consumer.

## Stop The Stack

```bash
podman-compose -f compose.yaml down
```

To also remove the local Elasticsearch volume:

```bash
podman-compose -f compose.yaml down -v
```
