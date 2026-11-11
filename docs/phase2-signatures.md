# Phase 2: Signatures

Deliverable: network scans, brute force and automated web attacks from Kali each raise a specific, high-level Wazuh alert.

## What was added

| Layer | Where | What it detects |
|---|---|---|
| Suricata 8 + ET Open (~53k rules) | target VM, interface `enp0s3` | network attacks: scans, exploits, malware traffic |
| WAF rules 100103-100105 | `detection/wazuh/local_rules.xml` | bursts of blocked requests, login brute force |
| Suricata rules 100110-100111 | same file | scan signatures, port scans |
| Built-in Wazuh rules 5760 / 5763 | already on the manager | SSH failed logins / SSH brute force |

## Setup

On the target VM:
```bash
sudo bash /opt/cloud-sec-lab/detection/suricata/setup.sh          # installs, configures, restarts Suricata
```
Then add the second `<localfile>` from `detection/wazuh/agent-ossec-localfile.xml` to the agent's `ossec.conf` and `sudo systemctl restart wazuh-agent`.

On the Wazuh manager: copy `detection/wazuh/local_rules.xml` to `/var/ossec/etc/rules/`, check it with `sudo /var/ossec/bin/wazuh-analysisd -t`, then `sudo systemctl restart wazuh-manager`.

Key decision: `HOME_NET` is set to the target only (`192.168.56.40/32` + Docker). Most ET SCAN rules only fire for traffic from `$EXTERNAL_NET`, and Suricata's default `HOME_NET` (all of 192.168.0.0/16) would treat Kali as internal and stay silent.

Suricata writes two files:
- `/var/log/suricata/eve-alerts.json`: alerts only, shipped to Wazuh
- `/var/log/suricata/eve.json`: everything (flows, HTTP, DNS), kept locally as training data for Phase 5

## Tests (run from Kali)

```bash
# 1. Port scan: expect 100110 (level 8) and 100111 (level 12)
sudo nmap -sS -p 1433,1521,3306,5432,22,80 192.168.56.40

# 2. Juice Shop login brute force: expect 100104 (level 5) and 100105 (level 12)
hydra -l admin@juice-sh.op -P /usr/share/wordlists/metasploit/unix_passwords.txt -t 4 -f 192.168.56.40 \
  http-post-form '/rest/user/login:{"email"\:"^USER^","password"\:"^PASS^"}:Invalid email or password:H=Content-Type\: application/json'

# 3. Automated web attack: expect 100103 (level 13)
nikto -h http://192.168.56.40 -maxtime 60s

# 4. SSH brute force: expect built-in 5760 and 5763
hydra -l soc-target -P /usr/share/wordlists/metasploit/unix_passwords.txt -t 4 ssh://192.168.56.40 -I -W 1
```

In the dashboard (Threat Hunting → Events, last 15 minutes):
```
rule.id:(100103 or 100105 or 100111 or 5763)
```

## Verified

Run from the host (192.168.56.1) on 2026-11-11:

| Traffic | Alert |
|---|---|
| `nmap -sT` on 4 database ports | 100110 ×3, then 100111 (level 12) |
| 12 failed logins in a few seconds | 100105 (level 12) |
| 12 SQLi requests | 100103 (level 13) |
