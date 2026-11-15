"""Phase 5: ML scoring service (runs on the target VM).

- Follows Suricata's eve.json, scores every HTTP request with the current model bundle and appends
  suspicious ones to ALERT_PATH as JSON lines; the Wazuh agent ships that file to the manager.
- POST /labels/start and /labels/{id}/end: Kali's `labattack` wrapper records attack windows (training labels).
- POST /score: score one request on demand. GET /health, /model, /metrics (Prometheus).
- Reloads the model when MODEL_PATH changes on disk (the nightly retrain drops a new one there).
"""
import json
import os
import threading
import time
import uuid
from datetime import datetime, timezone

import joblib
import numpy as np
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import PlainTextResponse
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest

from lab_ml.features import FEATURE_NAMES, FEATURE_VERSION, extract

MODEL_PATH = os.environ.get("MODEL_PATH", "/models/model.joblib")
EVE_PATH = os.environ.get("EVE_PATH", "/var/log/suricata/eve.json")
ALERT_PATH = os.environ.get("ALERT_PATH", "/data/ml-alerts.json")
LABELS_PATH = os.environ.get("LABELS_PATH", "/data/labels.jsonl")
LABEL_TOKEN = os.environ.get("LABEL_TOKEN", "")
ATTACK_PROBA = float(os.environ.get("ATTACK_PROBA", "0.8"))
SKIP_SOURCES = set(os.environ.get("SKIP_SOURCES", "").split(",")) - {""}

SCORED = Counter("ml_events_scored_total", "HTTP requests scored")
ALERTS = Counter("ml_alerts_total", "Requests flagged", ["verdict", "waf_blocked"])
LATENCY = Histogram("ml_score_seconds", "Time to score one request")
MODEL_INFO = Gauge("ml_model_info", "Loaded model (value 1)", ["version", "trained_at"])
MODEL_LOADED = Gauge("ml_model_loaded", "1 if a model is loaded")

app = FastAPI(title="lab-ml", version="1")
_model = {"bundle": None, "mtime": 0.0}
_lock = threading.Lock()


def now():
    return datetime.now(timezone.utc).isoformat()


def load_model():
    try:
        mtime = os.path.getmtime(MODEL_PATH)
    except FileNotFoundError:
        return
    if mtime == _model["mtime"]:
        return
    bundle = joblib.load(MODEL_PATH)
    if bundle["feature_version"] != FEATURE_VERSION or bundle["feature_names"] != FEATURE_NAMES:
        print(f"{now()} model {bundle.get('version')} uses other features, not loading", flush=True)
        _model["mtime"] = mtime
        return
    with _lock:
        _model["bundle"], _model["mtime"] = bundle, mtime
    MODEL_INFO.clear()
    MODEL_INFO.labels(bundle["version"], bundle["trained_at"]).set(1)
    MODEL_LOADED.set(1)
    print(f"{now()} loaded model {bundle['version']}", flush=True)


def score(http: dict) -> dict | None:
    with _lock:
        b = _model["bundle"]
    if b is None:
        return None
    feats = extract(http)
    x = np.array([[feats[n] for n in FEATURE_NAMES]], dtype=float)
    out = {"model_version": b["version"]}
    # IsolationForest: lower score_samples = more abnormal; flip so higher = more abnormal
    a = float(-b["anomaly"].score_samples(x)[0])
    out.update(anomaly_score=round(a, 4), anomaly_threshold=round(b["threshold"], 4), is_anomaly=a > b["threshold"])
    if b.get("classifier") is not None:
        proba = b["classifier"].predict_proba(x)[0]
        classes = list(b["classifier"].classes_)
        best = int(np.argmax(proba))
        p_attack = 1.0 - float(proba[classes.index("normal")]) if "normal" in classes else float(proba[best])
        out.update(attack_proba=round(p_attack, 4), predicted_class=classes[best])
    else:
        p_attack = 0.0
    out["verdict"] = ("attack" if p_attack >= ATTACK_PROBA else "anomaly" if out["is_anomaly"] else "normal")
    out["top_features"] = {k: v for k, v in feats.items() if k.startswith(("kw_", "c_", "ua_tool", "dotdot")) and v}
    return out


def follow(path):
    """tail -F: yields new lines, survives logrotate (inode change or truncation)."""
    f, inode = None, None
    while True:
        try:
            st = os.stat(path)
            if f is None or st.st_ino != inode or st.st_size < f.tell():
                if f:
                    f.close()
                f = open(path, "r", errors="replace")
                if inode is None:
                    f.seek(0, os.SEEK_END)          # first start: only new events
                inode = st.st_ino
            line = f.readline()
            if line:
                yield line
                continue
        except FileNotFoundError:
            pass
        time.sleep(0.5)


def watcher():
    last_reload = 0.0
    for line in follow(EVE_PATH):
        if time.time() - last_reload > 30:
            load_model()
            last_reload = time.time()
        if '"event_type":"http"' not in line:
            continue
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if ev.get("src_ip") in SKIP_SOURCES:
            continue
        with LATENCY.time():
            res = score(ev.get("http", {}))
        if res is None:
            continue
        SCORED.inc()
        if res["verdict"] == "normal":
            continue
        status = ev["http"].get("status")
        waf_blocked = status == 403
        ALERTS.labels(res["verdict"], str(waf_blocked).lower()).inc()
        alert = {
            "timestamp": ev.get("timestamp", now()),
            "event_source": "lab-ml",
            "src_ip": ev.get("src_ip"),
            "dest_ip": ev.get("dest_ip"),
            "flow_id": ev.get("flow_id"),
            "http": {k: ev["http"].get(k) for k in ("http_method", "url", "status", "http_user_agent")},
            "waf_blocked": waf_blocked,
            "ml": res,
        }
        with open(ALERT_PATH, "a") as out:
            out.write(json.dumps(alert) + "\n")


@app.on_event("startup")
def start():
    os.makedirs(os.path.dirname(ALERT_PATH), exist_ok=True)
    MODEL_LOADED.set(0)
    load_model()
    threading.Thread(target=watcher, daemon=True).start()


@app.get("/health")
def health():
    b = _model["bundle"]
    return {"status": "ok", "model": b["version"] if b else None}


@app.get("/model")
def model():
    b = _model["bundle"]
    if not b:
        raise HTTPException(404, "no model loaded yet")
    return {k: b[k] for k in ("version", "trained_at", "threshold", "metrics", "mlflow_run_id") if k in b}


@app.post("/score")
def score_one(event: dict):
    res = score(event.get("http", event))
    if res is None:
        raise HTTPException(503, "no model loaded yet")
    return res


def check_token(token):
    if not LABEL_TOKEN or token != LABEL_TOKEN:
        raise HTTPException(401, "bad token")


@app.post("/labels/start")
def label_start(body: dict, x_label_token: str = Header("")):
    check_token(x_label_token)
    rec = {"id": str(uuid.uuid4()), "type": body["type"], "src_ip": body["src_ip"],
           "start": body.get("start") or now(), "end": None, "command": body.get("command", "")[:300]}
    with open(LABELS_PATH, "a") as f:
        f.write(json.dumps(rec) + "\n")
    return rec


@app.post("/labels/{label_id}/end")
def label_end(label_id: str, body: dict, x_label_token: str = Header("")):
    check_token(x_label_token)
    rec = {"id": label_id, "end": body.get("end") or now()}
    with open(LABELS_PATH, "a") as f:
        f.write(json.dumps(rec) + "\n")
    return rec


@app.get("/tools/labattack", response_class=PlainTextResponse)
def labattack_script():
    """So Kali can fetch the wrapper: curl -s http://192.168.56.40:8000/tools/labattack -o ~/labattack"""
    return open(os.path.join(os.path.dirname(__file__), "labattack")).read()


@app.get("/metrics")
def metrics():
    return PlainTextResponse(generate_latest(), media_type=CONTENT_TYPE_LATEST)
