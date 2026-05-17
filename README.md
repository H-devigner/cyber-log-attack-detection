# Cyber Log Attack Detection

This project detects security problems in **SSH auth logs**, **web-server logs**, and **firewall logs**.

It uses a multi-source data science pipeline:

```text
raw SSH/web/firewall logs
  -> source-specific parsing and feature extraction
  -> normalized event table
  -> EDA reports
  -> binary and attack-category models
  -> saved model artifacts and prediction CSVs
```

The current dataset is a mix of public real logs and simulated labeled examples. That is deliberate: public logs often cover only one side of the problem, such as honeypot attacks without normal traffic, or web access logs without attack labels.

## Current Scope

The pipeline handles three log families:

| Log source | Example problems |
| --- | --- |
| SSH auth logs | brute force, invalid-user scan, suspicious success after failures, suspicious post-auth commands |
| Web-server logs | SQL injection, XSS, path traversal, scanner activity |
| Firewall logs | blocked traffic, port scans, suspicious outbound traffic |

It trains two unified models plus specialist models for each log source:

| Model | Target |
| --- | --- |
| `multisource_binary_detector.joblib` | `normal` vs `attack` |
| `multisource_attack_category_detector.joblib` | specific problem category across all sources |
| `specialist_ssh_*_detector.joblib` | SSH-only detection/category routing |
| `specialist_web_*_detector.joblib` | web-only detection/category routing |
| `specialist_firewall_*_detector.joblib` | firewall-only detection/category routing |

## Project Structure

```text
cyber-log-attack-detection/
  data/
    raw/multisource/          # downloaded public SSH/web/firewall datasets
    processed/multisource/    # normalized labeled event table and scoring sample
  models/                     # trained model artifacts
  reports/multisource/
    figures/                  # EDA and confusion matrix plots
    metrics/                  # JSON metrics, classification reports, sample predictions
  elk/
    logstash/                 # local parsing pipeline for SSH/web/firewall logs
    sample-logs/              # small demo logs for Kibana/Logstash
  scripts/
    export_elk_events.py
    run_multisource_pipeline.py
    run_scenario_demo.py
  src/cyberlog_ml/
    eda.py
    modeling.py
    multisource_data.py
    predict.py
    predict_hybrid.py
```

## Quick Start

From the project folder:

```bash
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt
./.venv/bin/python scripts/run_multisource_pipeline.py --source auto
```

Use the offline synthetic-only mode when you do not want downloads:

```bash
./.venv/bin/python scripts/run_multisource_pipeline.py --source synthetic
```

Run the small scenario demo batch:

```bash
./.venv/bin/python scripts/run_scenario_demo.py
```

## Optional ELK Stack

The `feature/elk-log-ingestion` branch adds a Docker Compose setup for:

- Elasticsearch on `http://localhost:9200`
- Kibana on `http://localhost:5601`
- Logstash with a parser for sample SSH, web, and firewall logs

Start it from the project root:

```bash
docker compose up -d
```

Then create a Kibana data view named `cyberlog-events-*` using `@timestamp` as the time field.

After Logstash indexes the sample events, export them into a CSV bridge for ML experiments:

```bash
./.venv/bin/python scripts/export_elk_events.py \
  --output data/scenarios/elk_exported_events.csv
```

See `elk/README.md` for the full ELK workflow.

## Latest Local Run

I ran the multi-source pipeline on **2026-05-17** with:

```bash
./.venv/bin/python scripts/run_multisource_pipeline.py \
  --source auto \
  --synthetic-rows-per-source 12000 \
  --real-firewall-limit 15000 \
  --real-web-limit 8000 \
  --real-ssh-limit 8000
```

Loaded sources:

| Source | Rows |
| --- | ---: |
| UCI firewall | 15,000 |
| NASA web access plus simulated web attacks | 12,000 |
| Zenodo SSH honeypot | 8,000 |
| Synthetic SSH auth logs | 12,000 |
| Synthetic web-server logs | 12,000 |
| Synthetic firewall logs | 12,000 |

Final source mix:

| Log source | Rows |
| --- | ---: |
| firewall | 27,000 |
| web | 24,000 |
| ssh | 20,000 |

Binary label distribution:

| Label | Rows |
| --- | ---: |
| attack | 36,103 |
| normal | 34,897 |

Headline test metrics:

| Model | Accuracy | Balanced Accuracy | Macro F1 | Weighted F1 |
| --- | ---: | ---: | ---: | ---: |
| Multi-source binary detector | 0.9929 | 0.9930 | 0.9929 | 0.9929 |
| Binary baseline | 0.5085 | 0.5000 | 0.3371 | 0.3428 |
| Multi-source category detector | 0.9747 | 0.9552 | 0.9447 | 0.9753 |
| Category baseline | 0.4915 | 0.0769 | 0.0507 | 0.3240 |

Unified-vs-specialist comparison on the same held-out test rows:

| Target | Source | Test rows | Unified macro F1 | Specialist macro F1 | Specialist delta |
| --- | --- | ---: | ---: | ---: | ---: |
| attack category | firewall | 5,400 | 0.9349 | 0.9775 | +0.0426 |
| attack category | ssh | 4,000 | 1.0000 | 1.0000 | +0.0000 |
| attack category | web | 4,800 | 0.9068 | 0.9310 | +0.0242 |
| binary | firewall | 5,400 | 0.9847 | 0.9966 | +0.0119 |
| binary | ssh | 4,000 | 1.0000 | 1.0000 | +0.0000 |
| binary | web | 4,800 | 0.9957 | 0.9974 | +0.0017 |

Final decision from this comparison:

```text
Use the unified binary detector for first-pass triage.
Then route SSH/web/firewall rows to specialist category detectors for diagnosis.
```

Artifacts from this run:

- Dataset: `data/processed/multisource/multisource_security_logs_labeled.csv`
- Source manifest: `data/processed/multisource/multisource_source_manifest.json`
- Summary: `reports/multisource/multisource_pipeline_summary.md`
- Decision report: `reports/multisource/model_strategy_decision.md`
- Comparison CSV: `reports/multisource/metrics/unified_vs_specialist_comparison.csv`
- EDA plots: `reports/multisource/figures/`
- Metrics: `reports/multisource/metrics/`
- Models: unified models plus six source-specialist models in `models/`

## Modeling Approach

The current model is a regularized logistic classifier trained with stochastic gradient descent:

```python
SGDClassifier(
    loss="log_loss",
    penalty="elasticnet",
    class_weight="balanced",
    early_stopping=True,
)
```

Preprocessing:

- Numeric features: median imputation and standard scaling
- Categorical features: most-frequent imputation and one-hot encoding
- Evaluation: stratified 80/20 train/test split
- Internal training validation: 10% of the training split for early stopping

## Batch Prediction

Recommended hybrid scoring:

```bash
PYTHONPATH=src ./.venv/bin/python -m cyberlog_ml.predict_hybrid \
  --input data/processed/multisource/sample_multisource_for_scoring.csv \
  --output reports/multisource/metrics/sample_multisource_hybrid_predictions.csv
```

The hybrid predictor uses the two-pass production flow:

```text
normalized row
  -> unified binary model
  -> if normal: stop, final category = normal
  -> if attack: route by log_source to SSH/web/firewall category specialist
```

Score with one specific model:

```bash
PYTHONPATH=src ./.venv/bin/python -m cyberlog_ml.predict \
  --model models/multisource_binary_detector.joblib \
  --input data/processed/multisource/sample_multisource_for_scoring.csv \
  --output reports/multisource/metrics/sample_multisource_predictions.csv
```

## One Model Or One Per Log Source?

Short answer: use a **hybrid design**.

For this project, the best architecture is:

```text
parser per source
  -> shared normalized schema
  -> unified binary triage model
  -> source-specialist category models
```

One broad model is useful because it gives a single triage score across SSH, web, and firewall events. It is simpler to deploy, easier to monitor at first, and can learn cross-source context such as the same source IP showing suspicious behavior in more than one place.

Separate models are useful because each log source has different structure and attack signals. SSH brute force is mostly about users, failures, IPs, and time windows. Web attacks are mostly about methods, paths, status codes, user agents, and payload tokens. Firewall attacks are mostly about actions, ports, protocols, bytes, packets, and deny patterns.

Final recommendation from the current experiment:

- Use `multisource_binary_detector.joblib` for first-pass `normal` vs `attack` triage.
- Use `specialist_ssh_attack_category_detector.joblib` for SSH diagnosis.
- Use `specialist_web_attack_category_detector.joblib` for web diagnosis.
- Use `specialist_firewall_attack_category_detector.joblib` for firewall diagnosis.
- Keep `multisource_attack_category_detector.joblib` as the fallback when `log_source` is missing or unknown.

## Scenario Demo

The scenario demo creates an 18-row mixed batch that looks like a small morning shift:

- normal SSH, web, and firewall activity
- SSH brute force, invalid-user scan, suspicious success, and post-auth command
- web SQL injection, XSS, path traversal, and scanner requests
- firewall blocks, port scan, and suspicious outbound traffic

Files:

- Batch: `data/scenarios/mixed_shift_scenario.csv`
- Human-readable raw examples: `data/scenarios/mixed_shift_raw_examples.md`
- Predictions: `reports/scenario/mixed_shift_hybrid_predictions.csv`
- Report: `reports/scenario/scenario_summary.md`

Latest scenario result:

- Rows scored: `18`
- Expected attacks: `12`
- Predicted attacks: `11`
- Binary accuracy: `0.944`
- Category accuracy on expected attack rows: `0.833`

The scenario intentionally keeps mistakes visible. In the latest run, one SQL injection was classified as XSS, and one suspicious outbound firewall event was missed by the first-pass binary gate. This is useful: it shows why analyst review, better outbound features, and more real firewall labels matter.

## Decision Windows

The model scores one normalized row at a time, but for many security problems that row should summarize a short rolling window.

| Problem type | Minimum useful evidence | Better evidence |
| --- | --- | --- |
| SSH single login success/failure | 1 event | 5-10 minutes of user/IP history |
| SSH brute force | 5-10 failed attempts in 5-10 minutes | 20+ failed attempts or many usernames from one IP |
| Web SQLi/XSS/path traversal | 1 high-signal request | 5-20 requests from same IP/session |
| Web scanner | 3-5 suspicious paths | 10+ suspicious paths |
| Firewall block | 1 deny to a sensitive port | 10+ denies from the same IP |
| Firewall port scan | 10+ denied ports or destinations | 20-50+ denied attempts in a short window |
| Suspicious outbound firewall traffic | 1 unusual allowed connection can be reviewed | repeated connections, high volume, destination context |

Practical default: aggregate raw logs into 5-minute and 10-minute windows per source IP, username, URL path, destination port, and action before scoring.

## Important Limitations

- The current labels are a mix of real public data, weak labels, and simulated labels.
- These metrics prove the pipeline runs; they do not prove production readiness.
- Real deployment should use chronological splits, rolling-window features, drift monitoring, and analyst-reviewed false positives.
- The best next dataset upgrade is your own SSH auth logs, web access/error logs, and firewall logs.
