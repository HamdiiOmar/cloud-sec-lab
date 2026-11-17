# Phase 5: ML detection loop

Deliverable: a model that flags malicious HTTP requests the WAF signatures miss, retrained on attacks injected from Kali, versioned in MLflow, and wired into Wazuh and Shuffle like any other detection.

## Flow

```
Locust (host, normal) ─┐                                     ┌─► ml-alerts.json ─► Wazuh agent ─► rules 100120-100123 ─► Shuffle
Kali (labattack)  ─────┴─► WAF ─► Juice Shop                 │
                     Suricata eve.json (all requests + headers) ─► ML service (target :8000) scores each request
                                                             │
Kali labattack ─► POST /labels (attack windows) ─────────────┘
nightly: ml/pipeline/run.sh  collect ─► train (MLflow) ─► gates ─► deploy model.joblib ─► service hot-reloads
```

| Piece | Where | File |
|---|---|---|
| Normal traffic (20 simulated shoppers, wide range of browsers) | host | `ml/traffic/locustfile.py` |
| Attack labels: each attack run is a time window | Kali | `ml/kali/labattack` |
| Features (URL, encoding, keywords, request headers) | shared | `ml/lab_ml/features.py` |
| Scoring service: tails eve.json, writes verdicts, Prometheus metrics | target | `ml/service/app.py` |
| Training: labeling, split, both models, MLflow, quality gates | host | `ml/pipeline/train.py` |
| Nightly loop: collect, train, deploy | host | `ml/pipeline/run.sh` |
| MLflow + trainer | host, http://localhost:5000 | `ml/docker-compose.yml` |
| Wazuh rules 100120-100123 | manager | `detection/wazuh/local_rules.xml` |

## Models

- **Classifier** (Random Forest, class-balanced): normal vs sqli / xss / scan / ... Trained on labeled data. Does the real work.
- **Anomaly detector** (Isolation Forest): trained on normal traffic only, threshold at 0.2% false positives. Meant for attacks with no labeled example. Weak in practice (see limitations), so an "anomaly" verdict also needs the classifier to be at least 50% suspicious.

Not used as features: response status and size. A 403 means the WAF already blocked the request, and training on it would teach the model to copy the WAF.

## Labeling

- Requests from the host (Locust) = normal.
- Requests from Kali inside a `labattack` window = that attack type, **only if they carry a payload** (attack keywords or special characters in the URL or a header).
- Everything else is dropped: Kali traffic outside windows, requests in overlapping windows of different types, and payload-free requests the tools send between attacks.

Split: per label, the newest 20% is the test set. Promotion gates: false positive rate ≤ 0.5%, and anomaly recall no worse than production.

## Results (model 20261115-1433, scored on real logged traffic)

| | Result |
|---|---|
| Real normal requests flagged | 0 / 120 |
| Attacker requests carrying a payload, caught | 100% (URL and header injection) |
| Attacker requests with no payload | called normal (correct) |
| Anomaly detector false-positive rate (test) | 0.16% |

End to end: `X-Forwarded-For: ' OR 1=1-- -` passes the WAF (HTTP 200); the classifier flags it as sqli; Wazuh raises **100122** ("suspicious request NOT blocked by the WAF", level 12) and, after 5 in 60 s, **100123**, which goes to Shuffle.

## What went wrong, and the fixes

| Iteration | Problem | Fix |
|---|---|---|
| 1 | 2.7% false positives: my own test calls to the ML API and Prometheus scrapes were in the "normal" data | Only port 80 (the web app) |
| 2 | Multi-word searches (`apple%20pomace`) flagged: encoded spaces counted as attack encoding | Encoding features ignore `%20` |
| 2 | No attacks in the test set: one global time cut, attacks all in an earlier burst | Newest 20% of **each** label |
| 3 | 0% recall on sqlmap `--level 3`: payloads in headers, which Suricata didn't log | Suricata `dump-all-headers: request`, header features |
| 3 | Classifier separated attacks by user-agent length (Locust: 5 modern browsers; sqlmap: old ones) | Dropped UA length; Locust generates ~6 years of real browser strings |
| 4 | **Label noise:** classifier called every non-Locust-shaped request sqli. 24% of "sqli" and 39% of "scan" rows were tool baseline requests with no payload. Test F1 was 0.995 because the test set was mislabeled the same way | Keep an attack-labeled request only if it carries a payload (dropped ~17k rows); verify on real logged traffic, not just MLflow metrics |
| 5 | Anomaly detector flagged normal review writing (rare but legitimate) | Classifier vetoes weak anomaly flags; stricter threshold; rule 100122 requires the classifier |

## Known limitations

- The anomaly detector catches almost nothing the classifier misses. Its value here is mostly as a documented baseline.
- Payload-free scanning (e.g. nikto requesting `/.ssh/authorized_keys`) is not flagged per request; it is caught by the burst rules and Suricata's ET SCAN signatures (Phase 2).
- Labels depend on time windows; overlapping attacks lose data. Run `labattack` commands one at a time.
- POST bodies are not inspected (Suricata does not log them by default).

## Operate

```bash
# Kali: record an attack as training data
~/labattack sqli sqlmap -u "http://192.168.56.40/rest/products/search?q=apple" --batch
# Target: stop Kali being auto-blocked while collecting (expires; reboot ends it)
sudo lab-block pause 192.168.56.103 60      # sudo lab-block resume 192.168.56.103
# Host: retrain now (also what the nightly cron runs)
ml/pipeline/run.sh
```
