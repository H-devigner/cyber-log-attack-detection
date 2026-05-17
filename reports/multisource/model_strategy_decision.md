# Model Strategy Decision

## Final Decision

- Strategy: `hybrid_unified_binary_plus_specialist_categories`
- Summary: Use the unified binary detector for first-pass triage, then route SSH/web/firewall rows to specialist category detectors for source-specific diagnosis.
- Average binary macro-F1 specialist delta: `0.0046`
- Average category macro-F1 specialist delta: `0.0223`

## Unified Vs Specialist Comparison

| target | log_source | test_rows | unified_macro_f1 | specialist_macro_f1 | delta_macro_f1_specialist_minus_unified | unified_weighted_f1 | specialist_weighted_f1 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| attack_category | firewall | 5400 | 0.9349 | 0.9775 | 0.0426 | 0.9804 | 0.9950 |
| attack_category | ssh | 4000 | 1.0000 | 1.0000 | 0.0000 | 1.0000 | 1.0000 |
| attack_category | web | 4800 | 0.9068 | 0.9310 | 0.0242 | 0.9490 | 0.9627 |
| binary_label | firewall | 5400 | 0.9847 | 0.9966 | 0.0119 | 0.9850 | 0.9967 |
| binary_label | ssh | 4000 | 1.0000 | 1.0000 | 0.0000 | 1.0000 | 1.0000 |
| binary_label | web | 4800 | 0.9957 | 0.9974 | 0.0017 | 0.9958 | 0.9975 |

## Specialist Model Artifacts

- `specialist_firewall_binary_detector.joblib`: accuracy `0.9967`, balanced accuracy `0.9962`, macro F1 `0.9966`, weighted F1 `0.9967`
- `specialist_ssh_binary_detector.joblib`: accuracy `1.0000`, balanced accuracy `1.0000`, macro F1 `1.0000`, weighted F1 `1.0000`
- `specialist_web_binary_detector.joblib`: accuracy `0.9975`, balanced accuracy `0.9969`, macro F1 `0.9974`, weighted F1 `0.9975`
- `specialist_firewall_attack_category_detector.joblib`: accuracy `0.9950`, balanced accuracy `0.9746`, macro F1 `0.9775`, weighted F1 `0.9950`
- `specialist_ssh_attack_category_detector.joblib`: accuracy `1.0000`, balanced accuracy `1.0000`, macro F1 `1.0000`, weighted F1 `1.0000`
- `specialist_web_attack_category_detector.joblib`: accuracy `0.9625`, balanced accuracy `0.9341`, macro F1 `0.9310`, weighted F1 `0.9627`
