# Cyber Log Attack Detection - Detailed Methodology

This document explains the project in presentation language: what data was used, why synthetic data was added, what labels exist, how preprocessing works, how the models are trained, what the results mean, and what should be improved before production.

## 1. Project Goal

The goal is to detect security problems from three common log sources:

| Log source | Examples of problems |
| --- | --- |
| SSH authentication logs | brute force, invalid usernames, suspicious success after failures, suspicious commands |
| Web-server logs | SQL injection, XSS, path traversal, scanner traffic |
| Firewall logs | blocked traffic, port scans, suspicious outbound traffic |

The current design is a two-pass pipeline:

```text
raw SSH/web/firewall log
  -> parser and feature extraction
  -> normalized event row
  -> pass 1: unified binary model predicts normal vs attack
  -> pass 2: if attack, route by log_source to a specialist category model
```

The first pass answers: "Should an analyst look at this?"

The second pass answers: "What kind of problem is it?"

## 2. Short Answers To The Main Questions

### Did we use public datasets for all types?

Yes, the pipeline tries one public data source for each log family when run with `--source auto`.

| Log type | Public source used | What it gives us | Important caveat |
| --- | --- | --- | --- |
| Firewall | UCI Internet Firewall Data | Firewall-style tabular traffic records with an action field | Labels are weakly inferred from the action field |
| Web | NASA HTTP access log, July 1995 | Real web access log shape and normal web traffic | It is not an attack-labeled dataset |
| SSH | Zenodo SSH honeypot dataset | Real SSH attack/honeypot activity | It is attack-heavy and does not provide normal business SSH behavior |

### Did we add synthetic data for all of them?

Yes. The pipeline adds synthetic rows for SSH, web, and firewall every time. In the latest run it added `12,000` synthetic rows per log source:

| Synthetic source | Rows in latest run | Why it exists |
| --- | ---: | --- |
| `synthetic_ssh` | 12,000 | Adds normal SSH and controlled SSH attack categories |
| `synthetic_web` | 12,000 | Adds labeled web attacks and normal web traffic |
| `synthetic_firewall` | 12,000 | Adds port scans and suspicious outbound cases not covered enough by public data |

The NASA web loader also creates simulated attack rows from real NASA-like rows, because the NASA log itself is normal web access data without attack labels.

### Do we have labeled data for all of them?

Yes. The final normalized dataset has labels for every row:

- `binary_label`: `normal` or `attack`
- `attack_category`: specific category such as `ssh_bruteforce`, `web_sql_injection`, or `firewall_port_scan`

But the label quality is not identical across all sources:

| Source | Binary label source | Category label source | Label confidence |
| --- | --- | --- | --- |
| UCI firewall | `allow` is treated as normal; other actions as attack | non-allow actions become `firewall_block` | Medium. Useful weak labels, but not analyst-reviewed attack truth |
| NASA web | Original real rows are treated as normal | original rows are `normal`; injected attack rows get simulated categories | Medium for normal traffic shape; simulated for attacks |
| Zenodo SSH honeypot | Treated as attack | mapped heuristically from event, username, and command fields | Medium. Good attack behavior, weak category mapping |
| Synthetic SSH/web/firewall | Created directly by the simulator | Created directly by the simulator | High for internal consistency, but not real-world proof |

This is why the project should be presented as a working prototype and methodology, not as a production-ready detector.

## 3. Data Collection

The main data loading code is in:

```text
src/cyberlog_ml/multisource_data.py
```

The pipeline command is:

```bash
./.venv/bin/python scripts/run_multisource_pipeline.py --source auto
```

In the latest local run, the pipeline used:

```bash
./.venv/bin/python scripts/run_multisource_pipeline.py \
  --source auto \
  --synthetic-rows-per-source 12000 \
  --real-firewall-limit 15000 \
  --real-web-limit 8000 \
  --real-ssh-limit 8000
```

Loaded rows:

| Source | Rows |
| --- | ---: |
| UCI firewall | 15,000 |
| NASA web access plus simulated web attacks | 12,000 |
| Zenodo SSH honeypot | 8,000 |
| Synthetic SSH auth logs | 12,000 |
| Synthetic web-server logs | 12,000 |
| Synthetic firewall logs | 12,000 |

Final dataset size:

| Metric | Value |
| --- | ---: |
| Total rows | 71,000 |
| Columns | 46 |
| Firewall rows | 27,000 |
| Web rows | 24,000 |
| SSH rows | 20,000 |
| Attack rows | 36,103 |
| Normal rows | 34,897 |

## 4. Why Synthetic Data Was Necessary

Synthetic data was not added only as a simple augmentation trick. It was needed because public cybersecurity logs are usually incomplete for supervised machine learning.

Main reasons:

| Problem with public data | Example in this project | Why synthetic helps |
| --- | --- | --- |
| Normal-only logs | NASA web logs contain normal access behavior, but no reliable attack labels | Synthetic web attacks provide labeled SQLi, XSS, traversal, and scanner rows |
| Attack-only logs | SSH honeypots capture attackers, not normal employee/admin SSH behavior | Synthetic SSH normal rows create contrast between normal and suspicious login behavior |
| Weak labels | Firewall action fields are useful but not the same as analyst-confirmed attacks | Synthetic firewall rows add controlled port-scan and outbound categories |
| Different schemas | SSH, web, and firewall logs do not share columns | Synthetic rows are generated directly into the normalized schema |
| Missing categories | Public datasets rarely cover all categories needed for a demo | Synthetic data ensures every category has enough examples to train and evaluate |

In other words, synthetic data is used for prototype coverage and class balance. It makes the pipeline trainable and presentable while we wait for better real organization logs.

The limitation is important: synthetic patterns can be too clean. Final production confidence requires real labeled logs and analyst-reviewed false positives.

## 5. Labels And Attack Categories

The pipeline currently supports this label structure:

| Target | Meaning |
| --- | --- |
| `binary_label` | First-pass decision: `normal` or `attack` |
| `attack_category` | Second-pass explanation/category |

Categories used by source:

| Log source | Categories |
| --- | --- |
| SSH | `normal`, `ssh_bruteforce`, `ssh_invalid_user_scan`, `ssh_suspicious_success`, `ssh_post_auth_command`, `ssh_probe` |
| Web | `normal`, `web_sql_injection`, `web_xss`, `web_path_traversal`, `web_scanner` |
| Firewall | `normal`, `firewall_block`, `firewall_port_scan`, `firewall_suspicious_outbound` |

The final production pipeline does not run the category classifier for rows predicted as normal. It only runs category detection when the binary model predicts attack.

## 6. Preprocessing And Feature Engineering

The project converts different raw logs into one normalized event table.

### Common preprocessing

| Step | What happens | Why it matters |
| --- | --- | --- |
| Download/extract | Downloads ZIP, GZ, or TAR data where needed | Makes the pipeline repeatable |
| Parse raw format | Reads CSV, Apache common log lines, or SSH honeypot CSV fields | Each source has a different format |
| Normalize columns | Converts all sources into the same 46-column schema | Allows one unified model to train across sources |
| Create labels | Adds `binary_label` and `attack_category` | Supervised learning requires target labels |
| Create time features | Extracts `hour`, `day_of_week`, `is_weekend` | Time-of-day/week can change normal behavior |
| Fill missing values | Missing numeric values become 0; model pipeline also imputes | Log sources do not all contain the same fields |
| Encode categories | Categorical fields are one-hot encoded | Linear models need numeric inputs |
| Scale numeric values | Numeric features are standardized | Prevents large values from dominating the model |

### Source-specific features

SSH features:

| Feature | Meaning |
| --- | --- |
| `ssh_auth_result` | accepted, failed, post-auth, or unknown |
| `username_type` | privileged, service/cloud, suspicious, standard, unknown |
| `ssh_failed_logins_10m` | failed login count over a logical 10-minute window |
| `ssh_invalid_user` | invalid/suspicious username flag |
| `ssh_privileged_username` | root/admin/service username flag |
| `ssh_success_after_failures` | success after repeated failures |

Web features:

| Feature | Meaning |
| --- | --- |
| `http_method` | GET, POST, etc. |
| `http_status_family` | 2xx, 3xx, 4xx, 5xx |
| `http_user_agent_family` | browser, curl, sqlmap, nikto, script, unknown |
| `url_length` | length of URL path |
| `query_length` | length of query string |
| `url_depth` | path depth |
| `suspicious_path_tokens` | count of suspicious tokens like `../`, `union`, `<script`, `.env` |

Firewall features:

| Feature | Meaning |
| --- | --- |
| `firewall_action` | allow, deny, drop, reset, etc. |
| `firewall_is_allowed` | action is allow |
| `firewall_is_blocked` | action is not allow |
| `denied_admin_port` | blocked traffic to sensitive ports such as SSH/RDP/SMB |
| `src_event_count` | count-like burst feature for repeated source behavior |
| `dst_port`, `service`, `protocol` | network service context |
| `packets`, `bytes_sent`, `bytes_received`, `total_bytes` | volume behavior |

### Features intentionally excluded from modeling

The modeling code excludes raw identifiers and raw messages:

```text
timestamp, src_ip, dst_ip, username, url_path, user_agent, raw_message, source_dataset
```

Reasons:

- Avoid privacy-sensitive direct identifiers.
- Avoid memorizing dataset-specific IPs or usernames.
- Avoid overfitting to the exact raw text from synthetic examples.
- Force the model to learn generalized numeric and categorical behavior.

## 7. Window Aggregation

This project is mostly a tabular event-level model, not a true time-series model.

That means the model receives one normalized row at a time. Some rows already include count-like window features, but the current implementation does not yet compute full rolling windows from raw logs for every source.

Current state:

| Log source | Current window usage | Current implementation |
| --- | --- | --- |
| SSH | Yes, partial | Uses `ssh_failed_logins_10m`, a 10-minute failed-login style feature. For public SSH honeypot rows this is heuristic; for synthetic rows it is generated directly. |
| Web | Mostly no | Uses per-request features such as suspicious URL tokens, user agent, status, and URL length. Scanner windows are recommended but not fully implemented yet. |
| Firewall | Partial | Uses `src_event_count` and port/action features to approximate repeated behavior. True rolling windows by source IP and port are a recommended next step. |

Recommended production windows:

| Problem | Recommended window | Group by | Why |
| --- | --- | --- | --- |
| SSH brute force | 5-10 minutes | source IP, username, auth result | Single failures are common; repeated failures are suspicious |
| SSH suspicious success | 10 minutes | source IP, username | A success after many failures is higher risk |
| Web SQLi/XSS/traversal | 1 request plus 5-minute context | source IP, URL/session/user agent | Some payloads are suspicious in one request, but repetition improves confidence |
| Web scanner | 5-10 minutes | source IP, user agent | Scanner behavior is repeated path probing |
| Firewall block | 5-10 minutes | source IP, destination port, action | One deny may be noise; repeated denies are stronger evidence |
| Firewall port scan | 5 minutes | source IP, distinct destination ports/hosts | Port scans are patterns across many ports or hosts |
| Suspicious outbound traffic | 10-30 minutes | internal host, destination, port | Volume and repetition matter more than a single row |

## 8. EDA

EDA is implemented in:

```text
src/cyberlog_ml/eda.py
```

The pipeline writes CSV tables and plots under:

```text
reports/multisource/
```

Generated EDA outputs include:

| Output | Purpose |
| --- | --- |
| `dataset_summary.csv` | Row count, column count, duplicate count, source list |
| `column_profile.csv` | Data type, missing values, unique count, example value per column |
| `missing_values.csv` | Missing value counts |
| `numeric_summary.csv` | Numeric statistics and percentiles |
| `binary_label_distribution.csv` | Normal vs attack counts |
| `attack_category_distribution.csv` | Attack category counts |
| `log_source_distribution.csv` | SSH/web/firewall row counts |
| EDA figures | Label mix, attack by source, top services by attack rate, numeric correlation |

EDA matters because it answers:

- Are the classes balanced enough?
- Are all log sources represented?
- Are labels missing?
- Which features are most correlated with attack labels?
- Are there suspicious data quality problems before training?

## 9. Modeling

The current model is a regularized linear classifier:

```python
SGDClassifier(
    loss="log_loss",
    penalty="elasticnet",
    class_weight="balanced",
    early_stopping=True,
)
```

Why this model:

| Reason | Explanation |
| --- | --- |
| Fast | Good for a prototype and large tabular log data |
| Interpretable enough | Coefficients can be inspected to understand influential features |
| Handles many one-hot features | Works well with categorical log fields after encoding |
| Supports class balancing | Helps when normal/attack or categories are imbalanced |
| Produces probabilities internally | `log_loss` behaves like logistic regression |

The project also trains a dummy baseline using the most frequent class. This proves whether the real model is better than a trivial classifier.

## 10. Data Split

The current split is:

| Split | Current implementation |
| --- | --- |
| Train/test | 80/20 split |
| Stratification | By `log_source` plus target where possible |
| Validation | 10% internal validation inside SGD early stopping |

Important limitation:

The current split is random stratified, not chronological. For production security logs, the better evaluation is a time-based split:

```text
train on older weeks -> validate on newer days -> test on later unseen days
```

This reduces leakage and better simulates real deployment.

## 11. Models Trained

The pipeline trains:

| Model | Purpose |
| --- | --- |
| `multisource_binary_detector.joblib` | Unified first-pass normal vs attack model |
| `multisource_attack_category_detector.joblib` | Unified fallback category model |
| `specialist_ssh_binary_detector.joblib` | SSH-only binary model for comparison |
| `specialist_web_binary_detector.joblib` | Web-only binary model for comparison |
| `specialist_firewall_binary_detector.joblib` | Firewall-only binary model for comparison |
| `specialist_ssh_attack_category_detector.joblib` | SSH-only category model |
| `specialist_web_attack_category_detector.joblib` | Web-only category model |
| `specialist_firewall_attack_category_detector.joblib` | Firewall-only category model |

The final recommendation is:

```text
Use unified binary detection for triage.
If attack, route by log_source to the matching category specialist.
Use the unified category model only as fallback when log_source is unknown.
```

Routing logic:

| `log_source` | Second-pass category model |
| --- | --- |
| `ssh` | `specialist_ssh_attack_category_detector.joblib` |
| `web` | `specialist_web_attack_category_detector.joblib` |
| `firewall` | `specialist_firewall_attack_category_detector.joblib` |
| missing/unknown | `multisource_attack_category_detector.joblib` |

## 12. Results

Latest local run headline metrics:

| Model | Accuracy | Balanced accuracy | Macro F1 | Weighted F1 |
| --- | ---: | ---: | ---: | ---: |
| Multi-source binary detector | 0.9929 | 0.9930 | 0.9929 | 0.9929 |
| Binary baseline | 0.5085 | 0.5000 | 0.3371 | 0.3428 |
| Multi-source category detector | 0.9747 | 0.9552 | 0.9447 | 0.9753 |
| Category baseline | 0.4915 | 0.0769 | 0.0507 | 0.3240 |

Unified vs specialist comparison:

| Target | Source | Test rows | Unified macro F1 | Specialist macro F1 | Specialist gain |
| --- | --- | ---: | ---: | ---: | ---: |
| Binary | SSH | 4,000 | 1.0000 | 1.0000 | +0.0000 |
| Binary | Web | 4,800 | 0.9957 | 0.9974 | +0.0017 |
| Binary | Firewall | 5,400 | 0.9847 | 0.9966 | +0.0119 |
| Category | SSH | 4,000 | 1.0000 | 1.0000 | +0.0000 |
| Category | Web | 4,800 | 0.9068 | 0.9310 | +0.0242 |
| Category | Firewall | 5,400 | 0.9349 | 0.9775 | +0.0426 |

Interpretation:

- Unified binary detection is strong enough for first-pass triage.
- Specialist category models improve diagnosis for web and firewall.
- SSH looks perfect in this run, but that is likely because SSH synthetic and honeypot patterns are easier than real enterprise SSH behavior.
- Metrics are encouraging for a prototype, but should not be claimed as production-grade.

## 13. Scenario Batch Test

The project includes a small 18-row mixed scenario:

```text
data/scenarios/mixed_shift_scenario.csv
```

It simulates a morning shift with normal activity plus SSH, web, and firewall attacks.

Latest scenario result:

| Metric | Value |
| --- | ---: |
| Rows scored | 18 |
| Expected attacks | 12 |
| Predicted attacks | 11 |
| Binary accuracy | 0.944 |
| Category accuracy on expected attack rows | 0.833 |

Known mistakes in the scenario:

| Case | What happened | Lesson |
| --- | --- | --- |
| SQL injection predicted as XSS | Binary attack detection worked, category was wrong | Web attack payload categories need more examples and clearer features |
| Suspicious outbound firewall predicted normal | Binary gate stopped the category stage | Outbound firewall behavior needs richer window and destination features |

## 14. ELK And Podman Integration

The `feature/elk-log-ingestion` branch adds an ELK ingestion setup using Podman:

| Component | Role |
| --- | --- |
| Logstash | Parses sample SSH, web, and firewall logs |
| Elasticsearch | Stores normalized log events |
| Kibana | Lets an analyst inspect the events |

Run:

```bash
podman machine start
podman machine ssh "sudo sysctl -w vm.max_map_count=262144"
podman-compose -f compose.yaml up -d
```

Open Kibana:

```text
http://localhost:5601
```

Create a data view:

```text
cyberlog-events-*
```

Use `@timestamp` as the time field.

ELK is not the ML model. ELK is the log ingestion and analyst exploration layer. The ML pipeline consumes normalized/exported rows.

## 15. Limitations

| Limitation | Why it matters | Recommended fix |
| --- | --- | --- |
| Synthetic data is heavily used | Synthetic patterns can be easier than real attacks | Add real organization logs and analyst-reviewed labels |
| Some public labels are weak | Firewall action is not the same as confirmed attack | Validate labels with domain knowledge |
| Random split is optimistic | Logs are time-dependent | Add chronological train/validation/test split |
| Rolling windows are incomplete | Brute force and port scan are sequence patterns | Implement real 5-minute and 10-minute aggregations |
| Raw text is not modeled deeply | Some attacks live in payload text | Add safer text features or embeddings later |
| No live alerting service yet | Current flow is batch/scenario scoring | Add API or streaming scoring layer |

## 16. Recommended Next Steps

1. Collect real SSH auth logs, web access/error logs, and firewall logs from the target environment.
2. Build a labeling workflow with analyst review.
3. Add true rolling-window aggregation for SSH, web scanner, firewall port scan, and outbound traffic.
4. Use chronological splits for realistic evaluation.
5. Compare the current linear model against tree-based models such as Random Forest, XGBoost, or LightGBM.
6. Add probability thresholds and alert severity levels.
7. Connect ELK export to the ML scorer so indexed logs can be scored regularly.
8. Track false positives and false negatives after analyst review.

## 17. How To Run The Main Pipeline

Create the environment:

```bash
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt
```

Run with public sources plus synthetic rows:

```bash
./.venv/bin/python scripts/run_multisource_pipeline.py --source auto
```

Run offline with only synthetic data:

```bash
./.venv/bin/python scripts/run_multisource_pipeline.py --source synthetic
```

Run the scenario demo:

```bash
./.venv/bin/python scripts/run_scenario_demo.py
```

Score a CSV with the hybrid two-pass predictor:

```bash
PYTHONPATH=src ./.venv/bin/python -m cyberlog_ml.predict_hybrid \
  --input data/processed/multisource/sample_multisource_for_scoring.csv \
  --output reports/multisource/metrics/sample_multisource_hybrid_predictions.csv
```

## 18. Presentation Positioning

The honest way to present this project:

```text
This is a complete prototype data-science pipeline for SSH, web, and firewall log attack detection.
It uses public logs where possible, adds synthetic data to cover missing labels and attack scenarios,
performs EDA and preprocessing, trains unified and specialist models, compares strategies, and provides
an ELK ingestion demo.
```

Avoid saying:

```text
This is production-ready.
The reported accuracy proves it will work on any company network.
All labels are ground truth.
```

Better wording:

```text
The metrics show that the pipeline works end to end on the current mixed dataset.
The next production step is to replace or supplement synthetic labels with real analyst-reviewed logs.
```
