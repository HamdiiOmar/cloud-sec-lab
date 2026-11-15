#!/usr/bin/env bash
# Phase 5: nightly ML loop on the host: collect new data -> train -> deploy if promoted.
# Cron (host):  15 3 * * *  /home/baril/cloud-sec-lab/ml/pipeline/run.sh >> /home/baril/cloud-sec-lab/ml/data/run.log 2>&1
set -euo pipefail
cd "$(dirname "$0")/.."
TARGET=soc-target@192.168.56.40
SSH="ssh -o BatchMode=yes $TARGET"
mkdir -p data models
echo "== $(date -Is) ML loop"

# 1. Collect: HTTP events newer than the last run (current + rotated eve.json), and the attack labels.
#    Only port 80 (the web app the model protects; not Prometheus scrapes or the ML API itself).
#    -R + fromjson? skips half-written lines (e.g. the target VM was killed mid-write) instead of aborting.
LAST=$(cat data/.last_ts 2>/dev/null || echo "1970-01-01T00:00:00")
$SSH "sudo sh -c 'for f in \$(ls -tr /var/log/suricata/eve.json*); do zcat -f \"\$f\"; done' \
      | jq -cR --arg last '$LAST' 'fromjson? | select(.event_type==\"http\" and .dest_port==80 and .timestamp > \$last) | {timestamp, src_ip, dest_ip, flow_id, http}'" \
      > data/new.jsonl
NEW=$(wc -l < data/new.jsonl)
if [ "$NEW" -gt 0 ]; then
	cat data/new.jsonl >> data/http.jsonl
	python3 -c "import json,sys; print(max(json.loads(l)[\"timestamp\"] for l in open(sys.argv[1])))" data/new.jsonl > data/.last_ts   # host has no jq
fi
rm -f data/new.jsonl
$SSH "sudo cat /var/lib/lab-ml/data/labels.jsonl" > data/labels.jsonl
echo "collected $NEW new http events (total $(wc -l < data/http.jsonl)), $(grep -c '"type"' data/labels.jsonl || true) attack windows"

# 2. Train (logs to MLflow; writes models/model.joblib only if the gates pass)
docker compose up -d mlflow >/dev/null
HOST_UID=$(id -u) HOST_GID=$(id -g) docker compose run --rm --build trainer

# 3. Deploy if the promoted model changed; the service reloads it within 30 s
[ -f models/model.joblib ] || { echo "no promoted model yet"; exit 0; }
SHA=$(sha256sum models/model.joblib | cut -d' ' -f1)
if [ "$SHA" != "$(cat data/.deployed_sha 2>/dev/null)" ]; then
	scp -q models/model.joblib "$TARGET:/tmp/model.joblib"
	$SSH "sudo install -o 10001 -g 10001 -m 644 /tmp/model.joblib /var/lib/lab-ml/models/model.joblib.new \
	      && sudo mv /var/lib/lab-ml/models/model.joblib.new /var/lib/lab-ml/models/model.joblib && rm /tmp/model.joblib"
	echo "$SHA" > data/.deployed_sha
	echo "deployed new model"
else
	echo "model unchanged, nothing to deploy"
fi
