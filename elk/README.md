# ELK Log Ingestion Branch

This branch adds a local ELK setup for the same three log families as the ML pipeline:

- SSH authentication logs
- Web-server access logs
- Firewall traffic logs

It is intended for local development and demos. Logstash reads the sample logs in `elk/sample-logs/`, parses them into normalized security-event fields, and indexes them into Elasticsearch. Kibana then lets you inspect and dashboard those indexed events.

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
podman machine start
```

If Elasticsearch fails with a `vm.max_map_count` message, set it inside the Podman VM:

```bash
podman machine ssh "sudo sysctl -w vm.max_map_count=262144"
```

Start the stack from the repository root:

```bash
podman compose up -d
```

If `podman compose` reports that no compose provider is installed, use `podman-compose`:

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
                         exported normalized events
                                    |
                                    v
                         ML feature extraction/scoring
```

## Export Events For ML

After the stack is running and Logstash has indexed sample events:

```bash
./.venv/bin/python scripts/export_elk_events.py \
  --output data/scenarios/elk_exported_events.csv
```

That CSV is a bridge format for later ML scoring. It gives the data-science pipeline normalized rows coming from ELK instead of directly from local CSV/log generators.

## Stop The Stack

```bash
podman compose down
```

To also remove the local Elasticsearch volume:

```bash
podman compose down -v
```

If you started it with `podman-compose`, use:

```bash
podman-compose -f compose.yaml down
podman-compose -f compose.yaml down -v
```
