# Self-hosted Cloud + Security Lab

Attack it, watch it, detect it, block it, learn. Full architecture: [docs/cloud-security-lab.pdf](docs/cloud-security-lab.pdf).

| Folder | Contents |
|---|---|
| `infra/` | Docker Compose, NGINX + ModSecurity (OWASP CRS), Juice Shop / DVWA, nftables, Terraform |
| `detection/` | Wazuh config and custom rules, Suricata (ET Open) |
| `soar/` | Shuffle workflows, Wazuh Active Response |
| `monitoring/` | Prometheus, node_exporter, cAdvisor, Grafana dashboards |
| `ml/` | FastAPI scoring service, scikit-learn models, MLflow retraining |
| `docs/` | Architecture and notes |

## Build order
1. **Lab base**: Compose + Wazuh up ✅
2. **Signatures**: CRS + Suricata rules ✅
3. **Health**: Prometheus, Grafana
4. **SOAR**: Shuffle blocks IPs
5. **ML loop**: train, score, retrain
6. **DevSecOps**: CI scans, Terraform

## Lab

| VM | IP | Role |
|---|---|---|
| Kali | 192.168.56.103 | Attacker |
| Ubuntu-Target (Ubuntu 26.04) | 192.168.56.40 | Juice Shop behind NGINX + ModSecurity (CRS 4), Wazuh agent |
| Wazuh 4.14.10 (OVA) | 192.168.56.104 | Manager, indexer, dashboard |

All on a VirtualBox host-only network. Setup steps: [docs/phase1-lab-base.md](docs/phase1-lab-base.md).

## Phase 1: attack → block → alert

Normal traffic reaches Juice Shop through the WAF:

![Juice Shop through the WAF](docs/screenshots/01-juiceshop.png)

XSS and SQL injection from Kali are blocked with 403; a normal search still returns 200:

![curl attacks blocked](docs/screenshots/02-kali-403.png)

sqlmap finds nothing injectable: 89 of its requests were blocked by the WAF:

![sqlmap blocked by the WAF](docs/screenshots/03-sqlmap-waf.png)

The Wazuh agent ships the WAF's JSON audit log, and custom rules ([detection/wazuh/local_rules.xml](detection/wazuh/local_rules.xml)) raise level-12 alerts with the attacker's IP and MITRE T1190:

![Wazuh SQL injection alerts](docs/screenshots/04-wazuh-alerts.png)

![Wazuh agent active](docs/screenshots/05-wazuh-agent.png)

| Rule | Level | Fires on |
|---|---|---|
| 100100 | 3 | Any ModSecurity audit event |
| 100101 | 10 | Request blocked (403) |
| 100102 | 12 | SQL injection blocked (CRS 942xxx) |

> Keep the lab on an isolated network. Only attack systems you own. Plan for ~16 GB RAM (Wazuh alone needs ~8 GB).
