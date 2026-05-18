# Presentation Q&A

This file contains likely audience questions and concise answers. It is written for a technical but mixed audience.

## Data Questions

### 1. Did you use public datasets for all log types?

Yes. The pipeline attempts to use one public source for SSH, web, and firewall logs. Firewall uses UCI Internet Firewall Data, web uses NASA HTTP access logs, and SSH uses a Zenodo SSH honeypot dataset. The important detail is that the public sources do not all have equally strong labels.

### 2. Did you add synthetic data for all log types?

Yes. Synthetic SSH, web, and firewall rows are always added. This gives the prototype enough labeled examples for normal traffic and attack categories that are missing or underrepresented in public data.

### 3. Why not use only public data?

Because the public datasets are incomplete for this exact supervised problem. NASA web logs are useful for normal traffic but not labeled attacks. SSH honeypot data is useful for attacks but lacks normal enterprise SSH behavior. Firewall actions are useful but are weak labels. Synthetic data fills these gaps for the prototype.

### 4. Is synthetic data realistic?

It is realistic enough for a prototype and demo because it encodes known attack patterns such as failed SSH bursts, SQL injection strings, scanner paths, blocked admin ports, and port scans. It is not a substitute for real production data.

### 5. Are the labels ground truth?

Not all of them. Synthetic labels are known by construction. Public firewall labels are inferred from the action field. Public SSH labels are attack/honeypot based, with category labels inferred from event content. NASA web normal rows are treated as normal, while web attacks are simulated.

### 6. What labeled classes do you have?

There is a binary target, `normal` vs `attack`, and a category target. Categories include SSH brute force, SSH invalid-user scan, suspicious SSH success, post-auth command, web SQL injection, XSS, path traversal, web scanner, firewall block, firewall port scan, and suspicious outbound traffic.

### 7. How many rows were used in the latest run?

The latest run used 71,000 rows: 27,000 firewall rows, 24,000 web rows, and 20,000 SSH rows.

### 8. Are the raw datasets committed to GitHub?

No. Raw data, processed datasets, model artifacts, and large generated plots are ignored because they can be regenerated and should not bloat the repository. Small scenario files and summary reports are committed.

## Preprocessing Questions

### 9. Why normalize all logs into one table?

SSH, web, and firewall logs have different raw formats. Machine learning needs a consistent feature table. Normalization lets us compare one unified model against source-specific specialist models.

### 10. What features did you extract?

The pipeline extracts time features, categorical fields like `log_source` and `event_type`, web features like URL length and suspicious tokens, SSH features like failed login count and username type, and firewall features like action, port, service, packets, and bytes.

### 11. Why exclude raw IP addresses and raw log messages from the model?

To reduce privacy risk and overfitting. A model that memorizes IPs, usernames, or exact synthetic payload text may look good in testing but fail in a real environment.

### 12. How are missing values handled?

Numeric values are coerced to numbers and filled with 0 during normalization. The scikit-learn pipeline also applies median imputation for numeric features and most-frequent imputation for categorical features.

### 13. How are categorical values handled?

Categorical fields are one-hot encoded with `handle_unknown="ignore"`, so new categories at prediction time do not crash the model.

## Window And Time Questions

### 14. Is this a time-series model?

No. It is currently a tabular event-level model with time-derived features and some count-like window features. It is not using an LSTM, transformer, ARIMA, or other sequence model.

### 15. Are rolling windows used?

Partially. SSH uses a 10-minute failed-login style feature, `ssh_failed_logins_10m`. Firewall uses `src_event_count` as a burst-like count feature. Web detection is mostly per request right now.

### 16. What windows should be used in production?

SSH brute force should use 5-10 minute windows. Web scanner detection should use 5-10 minute windows per source IP or user agent. Firewall port scans should use 5-minute windows over distinct destination ports or hosts. Suspicious outbound traffic may need 10-30 minute windows.

### 17. Why not use a sequence model now?

The first priority was a clean end-to-end data-science pipeline. A tabular model is easier to debug and present. Once real chronological logs are available, rolling-window features or sequence models can be evaluated fairly.

## Modeling Questions

### 18. What model did you use?

The main model is `SGDClassifier` with logistic loss, elastic-net regularization, balanced class weights, and early stopping. It behaves like a scalable regularized logistic regression.

### 19. Why use this model instead of deep learning?

For a first cybersecurity log prototype, interpretability, speed, and reliable preprocessing matter more than model complexity. Deep learning would need much more real labeled data.

### 20. What is the train/test split?

The pipeline uses an 80/20 random stratified train/test split. Stratification tries to preserve both `log_source` and target label distribution. The model also uses 10% of training data internally for early stopping validation.

### 21. Is the split production-realistic?

Not fully. A chronological split would be better for production because security logs are time-dependent. This is listed as a recommended next step.

### 22. Did you train one model or several?

Both. The pipeline trains unified models across all sources and specialist models per log source. The final recommendation is unified binary detection first, then specialist category detection.

### 23. Why is the final design two-pass?

It matches how analysts work. First decide if something is suspicious. Only then spend more effort diagnosing the attack type. It also prevents normal events from being forced into an attack category.

### 24. How does the second pass choose the specialist?

It uses the normalized `log_source` field. If `log_source=ssh`, it uses the SSH category model. If `web`, it uses the web category model. If `firewall`, it uses the firewall category model. If the source is unknown, it falls back to the unified category model.

## Results Questions

### 25. What were the headline results?

The unified binary model achieved about 0.993 macro F1. The unified category model achieved about 0.945 macro F1. Specialist category models improved web and firewall category performance.

### 26. Are the results too good?

They may be optimistic because synthetic data and random splitting make the task easier than real deployment. The results prove the pipeline runs and learns useful patterns, not that it is production-ready.

### 27. Which source benefited most from specialist models?

Firewall category detection improved the most, with macro F1 increasing from about 0.935 to 0.978. Web category detection also improved, from about 0.907 to 0.931.

### 28. What mistakes happened in the scenario demo?

One web SQL injection was classified as XSS. One suspicious outbound firewall event was missed by the binary gate and therefore never reached the second-pass category model.

### 29. What do those mistakes teach us?

The web model needs better payload/category separation, and suspicious outbound firewall detection needs richer window, destination, and reputation features.

## ELK And Deployment Questions

### 30. What is Kibana/Logstash used for here?

Logstash parses raw sample logs, Elasticsearch stores indexed events, and Kibana lets an analyst inspect them. ELK is the ingestion and exploration layer, not the ML model itself.

### 31. Why use Podman?

Podman provides a container runtime without Docker Desktop. On macOS it uses a Podman machine VM. The project uses `podman-compose -f compose.yaml up -d` to start Elasticsearch, Kibana, and Logstash.

### 32. Does the ML model score logs directly from Kibana?

Not yet. The current bridge exports indexed Elasticsearch events to CSV using `scripts/export_elk_events.py`. The next step is connecting that export or an API to the ML scorer.

### 33. What would a production architecture look like?

Raw logs go to Logstash or another collector, normalized events go to Elasticsearch or a feature store, rolling-window features are computed, the binary model scores events, attack rows are routed to specialist models, and high-risk results become alerts for analysts.

## Risk And Improvement Questions

### 34. What is the biggest limitation?

The biggest limitation is label realism. The pipeline needs real labeled logs from the target environment and analyst-reviewed false positives/false negatives.

### 35. What should be improved next?

Add real rolling-window aggregation, use chronological train/validation/test splits, collect real logs, add analyst labeling, calibrate probability thresholds, and compare more model families.

### 36. Can this detect zero-day attacks?

Not directly. It can flag behavior that looks similar to known suspicious patterns. For unknown attacks, anomaly detection and analyst feedback would be needed.

### 37. How much data is needed?

For a prototype, tens of thousands of rows are enough to validate the pipeline. For production, each log source should have weeks or months of logs and enough analyst-labeled examples of each category. Rare categories may need special collection or semi-supervised methods.

### 38. What should we say if asked whether it is ready to deploy?

Say: "It is ready as a prototype pipeline and demo. It is not ready as an unsupervised production security control until we validate it on real organization logs with analyst-reviewed labels."

### 39. Why not simply write rules instead of ML?

Rules are useful and should still exist. ML helps combine many signals at once, compare sources, and learn thresholds from labeled examples. In practice, rules plus ML plus analyst feedback is stronger than only one approach.

### 40. What is the final takeaway?

The project demonstrates a complete end-to-end cybersecurity log ML pipeline: data collection, synthetic gap filling, normalization, EDA, supervised training, unified vs specialist comparison, scenario testing, and ELK ingestion. The next step is replacing synthetic assumptions with real labeled operational logs.
