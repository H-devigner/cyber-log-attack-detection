# Scenario Batch Report

## Scenario

A mixed morning-shift batch combines SSH auth events, web-server requests, and firewall events.
Some rows are single events, while brute-force and scan rows include rolling-window features such as `ssh_failed_logins_10m` and `src_event_count`.

## Files

- Scenario batch: `/Users/houcine/Desktop/Random/cyber-log-attack-detection/data/scenarios/mixed_shift_scenario.csv`
- Raw examples: `/Users/houcine/Desktop/Random/cyber-log-attack-detection/data/scenarios/mixed_shift_raw_examples.md`
- Hybrid predictions: `/Users/houcine/Desktop/Random/cyber-log-attack-detection/reports/scenario/mixed_shift_hybrid_predictions.csv`

## Results

- Rows scored: `18`
- Expected attacks: `12`
- Predicted attacks: `11`
- Binary accuracy on this batch: `0.944`
- Category accuracy on all rows: `0.889`
- Category accuracy on expected attack rows: `0.833`

## Pipeline Run

1. A normalized SSH/web/firewall row is created from raw logs.
2. The unified binary model predicts `normal` or `attack`.
3. If the row is predicted `normal`, the category stage is not run and the final category is `normal`.
4. If the row is predicted `attack`, `log_source` routes it to the SSH, web, or firewall category specialist.
5. If `log_source` is missing or unknown, the unified category model is used as fallback.

## Prediction Table

| case_id | log_source | binary_label | predicted_binary_label | attack_category | predicted_attack_category | category_model_used |
| --- | --- | --- | --- | --- | --- | --- |
| case_01 | ssh | normal | normal | normal | normal | not_run_binary_normal |
| case_02 | firewall | normal | normal | normal | normal | not_run_binary_normal |
| case_03 | web | normal | normal | normal | normal | not_run_binary_normal |
| case_04 | ssh | normal | normal | normal | normal | not_run_binary_normal |
| case_05 | web | normal | normal | normal | normal | not_run_binary_normal |
| case_06 | firewall | normal | normal | normal | normal | not_run_binary_normal |
| case_07 | ssh | attack | attack | ssh_bruteforce | ssh_bruteforce | specialist_ssh_attack_category_detector |
| case_08 | firewall | attack | attack | firewall_block | firewall_block | specialist_firewall_attack_category_detector |
| case_09 | web | attack | attack | web_sql_injection | web_xss | specialist_web_attack_category_detector |
| case_10 | firewall | attack | attack | firewall_port_scan | firewall_port_scan | specialist_firewall_attack_category_detector |
| case_11 | ssh | attack | attack | ssh_invalid_user_scan | ssh_invalid_user_scan | specialist_ssh_attack_category_detector |
| case_12 | web | attack | attack | web_xss | web_xss | specialist_web_attack_category_detector |
| case_13 | web | attack | attack | web_path_traversal | web_path_traversal | specialist_web_attack_category_detector |
| case_14 | ssh | attack | attack | ssh_suspicious_success | ssh_suspicious_success | specialist_ssh_attack_category_detector |
| case_15 | web | attack | attack | web_scanner | web_scanner | specialist_web_attack_category_detector |
| case_16 | ssh | attack | attack | ssh_post_auth_command | ssh_post_auth_command | specialist_ssh_attack_category_detector |
| case_17 | firewall | attack | normal | firewall_suspicious_outbound | normal | not_run_binary_normal |
| case_18 | firewall | attack | attack | firewall_block | firewall_block | specialist_firewall_attack_category_detector |

## Mismatches

- `case_09` expected `web_sql_injection`, predicted `web_xss`. The first pass detected an attack, but the specialist chose a different category.
- `case_17` expected `firewall_suspicious_outbound`, predicted `normal`. The first-pass binary detector stopped the second pass, so the specialist category model never ran.

## How Much Data Is Needed To Decide?

The model scores one normalized event row at a time, but some event rows should represent a short rolling window rather than one raw line.

| Problem type | Minimum useful evidence | Stronger evidence | Why |
| --- | --- | --- | --- |
| SSH single login success/failure | 1 event can be scored | 5-10 minutes of user/IP history | A single failed login is often normal; repeated failures or success-after-failure changes the decision. |
| SSH brute force | 5-10 failed attempts in 5-10 minutes | 20+ failed attempts or many usernames from one IP | The useful feature is a rolling count such as `ssh_failed_logins_10m`. |
| Web SQLi/XSS/path traversal | 1 high-signal request can be suspicious | 5-20 requests from same IP/session | Payload tokens can be decisive, but repeated probes reduce false positives. |
| Web scanner | 3-5 suspicious paths | 10+ paths like `/.env`, `/wp-login.php`, `/phpmyadmin` | Scanners are best detected by repeated path patterns. |
| Firewall block | 1 deny event to sensitive ports can be suspicious | 10+ denies from same IP | One deny may be background noise; bursts are more actionable. |
| Firewall port scan | 10+ denied ports or destinations | 20-50+ denied attempts in a short window | Port scans are a pattern across many events. |
| Suspicious outbound firewall traffic | 1 unusual allowed connection may be reviewed | Volume, destination reputation, repeated connections | Context matters; byte/packet volume and destination behavior help. |

Practical default: aggregate raw logs into 5-minute and 10-minute windows per source IP, username, URL path, destination port, and action. Then score the resulting normalized rows.
