# Phase 3: Health and usage monitoring

Deliverable: one Grafana dashboard showing the target's CPU, RAM, disk, network and per-container usage, plus Prometheus alerts when something breaks.

## Layout

| Component | Runs on | Port | Role |
|---|---|---|---|
| node_exporter 1.12.1 | target (host network) | 9100 | host CPU, RAM, disk, network |
| cAdvisor 0.60.6 | target (Docker) | 8081 | per-container CPU, RAM |
| Prometheus 3.16.0 | host machine (192.168.56.1) | 9090 | scrapes every 15s, keeps 15 days, evaluates alerts |
| Grafana 13.2.6 | host machine | 3000 | "Lab health" dashboard |

Prometheus and Grafana run on the host instead of a VM: the host has RAM to spare, and the target's 4 GB is already shared by Juice Shop, the WAF, Suricata and the Wazuh agent.

## Setup

On the target:
```bash
cd /opt/cloud-sec-lab/monitoring/exporters && docker compose up -d
```

On the host:
```bash
cd monitoring
printf 'GRAFANA_ADMIN_PASSWORD=%s\n' "$(openssl rand -base64 18 | tr -d '/+=')" > .env   # gitignored
docker compose up -d
```
Grafana: http://localhost:3000 (user `admin`, password in `monitoring/.env`). The Prometheus data source and the dashboard are provisioned from files, so nothing needs clicking.

## Alerts (`monitoring/prometheus/alerts.yml`)

| Alert | Fires when |
|---|---|
| TargetDown | an exporter stops answering for 1 min |
| HighCPU | CPU above 85% for 5 min |
| LowMemory | under 10% RAM available for 5 min |
| DiskAlmostFull | root disk above 85% for 5 min |
| ContainerDown | Juice Shop or WAF container missing for 1 min |

Active alerts: http://localhost:9090/alerts

## Gotcha: CPU on VirtualBox guests

The standard formula `100 - idle%` showed the target at 50-80% CPU while `top` showed about 4%. On this VM the per-mode CPU counters only add up to ~76% of wall time, and "100 minus idle" counts the missing part as busy. The dashboard and the HighCPU alert use busy time divided by total counted time instead, which gave 2%, matching `top`.

## Verified (2026-11-11)

- All 3 scrape targets up; all 14 dashboard queries return data.
- Stopping cAdvisor fired `TargetDown` after ~1 min; starting it again cleared the alert.

## Not done yet

- Wazuh alerts in Grafana (OpenSearch data source pointing at the Wazuh indexer). Needs a read-only indexer user.
- Alert notifications (Alertmanager). Phase 4 sets up Telegram/Discord for Shuffle; Alertmanager can reuse the same channel.
- node_exporter on the Wazuh VM.
