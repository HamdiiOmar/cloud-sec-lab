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
1. **Lab base**: Compose + Wazuh up
2. **Signatures**: CRS + Suricata rules
3. **Health**: Prometheus, Grafana
4. **SOAR**: Shuffle blocks IPs
5. **ML loop**: train, score, retrain
6. **DevSecOps**: CI scans, Terraform

> Keep the lab on an isolated network. Only attack systems you own. Plan for ~16 GB RAM (Wazuh alone needs ~8 GB).
