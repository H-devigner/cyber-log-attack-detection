# Multi-Source Pipeline Summary

## Dataset

- Source: `mixed_real_and_synthetic_logs`
- Rows: `71000`
- Columns: `46`
- Processed path: `/Users/houcine/Desktop/Random/cyber-log-attack-detection/data/processed/multisource/multisource_security_logs_labeled.csv`

## Source Loading

- `uci_firewall`: loaded, rows `15000`
- `nasa_web_access`: loaded, rows `12000`
- `zenodo_ssh_honeypot`: loaded, rows `8000`
- `synthetic_ssh`: loaded, rows `12000`
- `synthetic_web`: loaded, rows `12000`
- `synthetic_firewall`: loaded, rows `12000`

## Binary Detector

- Model: accuracy `0.9929`, balanced accuracy `0.9930`, macro F1 `0.9929`, weighted F1 `0.9929`
- Baseline: accuracy `0.5085`, balanced accuracy `0.5000`, macro F1 `0.3371`, weighted F1 `0.3428`
- Model artifact: `/Users/houcine/Desktop/Random/cyber-log-attack-detection/models/multisource_binary_detector.joblib`
- Metrics JSON: `/Users/houcine/Desktop/Random/cyber-log-attack-detection/reports/multisource/metrics/multisource_binary_detector_metrics.json`
- Classification report: `/Users/houcine/Desktop/Random/cyber-log-attack-detection/reports/multisource/metrics/multisource_binary_detector_classification_report.csv`
- Confusion matrix: `/Users/houcine/Desktop/Random/cyber-log-attack-detection/reports/multisource/figures/multisource_binary_detector_confusion_matrix.png`

## Attack Category Detector

- Model: accuracy `0.9747`, balanced accuracy `0.9552`, macro F1 `0.9447`, weighted F1 `0.9753`
- Baseline: accuracy `0.4915`, balanced accuracy `0.0769`, macro F1 `0.0507`, weighted F1 `0.3240`
- Model artifact: `/Users/houcine/Desktop/Random/cyber-log-attack-detection/models/multisource_attack_category_detector.joblib`
- Metrics JSON: `/Users/houcine/Desktop/Random/cyber-log-attack-detection/reports/multisource/metrics/multisource_attack_category_detector_metrics.json`
- Classification report: `/Users/houcine/Desktop/Random/cyber-log-attack-detection/reports/multisource/metrics/multisource_attack_category_detector_classification_report.csv`
- Confusion matrix: `/Users/houcine/Desktop/Random/cyber-log-attack-detection/reports/multisource/figures/multisource_attack_category_detector_confusion_matrix.png`

## Specialist Models

- Specialist models trained: `6`
- Unified-vs-specialist comparison CSV: `/Users/houcine/Desktop/Random/cyber-log-attack-detection/reports/multisource/metrics/unified_vs_specialist_comparison.csv`
- Model strategy decision report: `/Users/houcine/Desktop/Random/cyber-log-attack-detection/reports/multisource/model_strategy_decision.md`
- Final strategy: `hybrid_unified_binary_plus_specialist_categories`
- Decision summary: Use the unified binary detector for first-pass triage, then route SSH/web/firewall rows to specialist category detectors for source-specific diagnosis.

## Scoring Sample

- Feature-only sample CSV: `/Users/houcine/Desktop/Random/cyber-log-attack-detection/data/processed/multisource/sample_multisource_for_scoring.csv`
