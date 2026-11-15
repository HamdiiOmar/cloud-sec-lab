"""Phase 5: train the HTTP models, log them to MLflow, and promote only if they pass the gates.

Input (in DATA_DIR, produced by collect.sh):
  http.jsonl    Suricata http events (all sources)
  labels.jsonl  attack windows recorded by Kali's `labattack` wrapper (start + end records)
Labeling:
  src == NORMAL_SRC                         -> "normal"
  src == attacker inside a labeled window   -> the window's attack type
  anything else                             -> dropped (e.g. Kali browsing outside an attack)
Output: OUT_DIR/model.joblib if promoted, plus an MLflow run with metrics and the model.
"""
import json
import os
import sys
from datetime import datetime, timedelta, timezone

import joblib
import mlflow
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lab_ml.features import FEATURE_NAMES, FEATURE_VERSION, extract  # noqa: E402

DATA_DIR = os.environ.get("DATA_DIR", "/data")
OUT_DIR = os.environ.get("OUT_DIR", "/out")
NORMAL_SRC = os.environ.get("NORMAL_SRC", "192.168.56.1")
OPEN_WINDOW_MIN = int(os.environ.get("OPEN_WINDOW_MIN", "15"))   # cap for windows whose end never arrived
TARGET_FPR = float(os.environ.get("TARGET_FPR", "0.002"))        # anomaly threshold = this quantile of normal
MAX_FPR = float(os.environ.get("MAX_FPR", "0.005"))               # gate: test false positive rate
MIN_NORMAL = int(os.environ.get("MIN_NORMAL", "10000"))   # too little data = rare legit actions look abnormal
MIN_ATTACK_FOR_CLF = int(os.environ.get("MIN_ATTACK_FOR_CLF", "50"))
MODEL_NAME = "lab-http-detector"


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def load_windows():
    path = os.path.join(DATA_DIR, "labels.jsonl")
    if not os.path.exists(path):
        return []
    starts, ends = {}, {}
    for line in open(path):
        r = json.loads(line)
        (starts if "type" in r else ends)[r["id"]] = r
    out = []
    for i, s in starts.items():
        start = ts(s["start"])
        end = ts(ends[i]["end"]) if i in ends else start + timedelta(minutes=OPEN_WINDOW_MIN)
        out.append({"type": s["type"], "src": s["src_ip"], "start": start, "end": end})
    return out


# Columns that mean "this request carries an attack payload" (in URL or in a header).
SIGNAL_COLS = [c for c in FEATURE_NAMES if c.startswith(("kw_", "hdr_kw_", "hdr_special"))] + \
    ["dotdot", "dash_dash", "c_lt", "c_gt", "c_quote", "c_semicolon", "c_pipe", "c_backtick", "c_dollar", "c_star"]


def attack_signal(f):
    return sum(f.get(c, 0) for c in SIGNAL_COLS)


def load_events(windows):
    rows, dropped_benign = [], 0
    for line in open(os.path.join(DATA_DIR, "http.jsonl")):
        ev = json.loads(line)
        src, t = ev.get("src_ip"), ts(ev["timestamp"])
        if src == NORMAL_SRC:
            label = "normal"
        else:
            types = {w["type"] for w in windows if w["src"] == src and w["start"] <= t <= w["end"]}
            if len(types) != 1:
                continue      # outside any window, or inside overlapping windows of different types: ambiguous
            label = types.pop()
        if "request_headers" not in ev.get("http", {}):
            continue      # v3 features need the request headers (logged since Phase 5); older events can't show header attacks
        f = extract(ev.get("http", {}))
        # Attack tools (sqlmap, nikto) send many benign baseline requests mixed with their payloads. Those
        # carry no attack signal, so labeling them as the attack poisons the classifier (it then flags any
        # non-Locust-shaped request). Keep an attack-labeled request only if it actually carries a payload.
        if label != "normal" and attack_signal(f) == 0:
            dropped_benign += 1
            continue
        f.update(_label=label, _time=t, _src=src)
        rows.append(f)
    print(f"dropped {dropped_benign} attacker requests with no payload (tool baseline traffic)")
    return pd.DataFrame(rows)


def current_production():
    try:
        mv = mlflow.MlflowClient().get_model_version_by_alias(MODEL_NAME, "production")
        return mlflow.get_run(mv.run_id).data.metrics
    except Exception:
        return None


def main():
    mlflow.set_experiment("lab-http-detector")
    windows = load_windows()
    df = load_events(windows).sort_values("_time")
    counts = df["_label"].value_counts().to_dict()
    print("rows per label:", counts)
    if counts.get("normal", 0) < MIN_NORMAL:
        sys.exit(f"only {counts.get('normal', 0)} normal requests, need {MIN_NORMAL}: let the traffic generator run longer")

    # Time-based split per label: the newest 20% of EACH label is the test set. A single global time cut
    # (first version) put every attack in train, because attacks come in short bursts.
    parts = [g.iloc[: int(len(g) * 0.8)] for _, g in df.groupby("_label")]
    train = pd.concat(parts).sort_values("_time")
    test = df.drop(train.index)
    X = lambda d: d[FEATURE_NAMES].to_numpy(dtype=float)
    normal_tr = train[train["_label"] == "normal"]

    with mlflow.start_run() as run:
        mlflow.log_params({"feature_version": FEATURE_VERSION, "n_features": len(FEATURE_NAMES),
                           "target_fpr": TARGET_FPR, "train_rows": len(train), "test_rows": len(test),
                           "attack_windows": len(windows)})
        mlflow.log_dict({"rows_per_label": counts}, "data_summary.json")

        # Layer 1: anomaly detector on normal traffic only. Threshold from a held-out slice of normal.
        fit_part, cal_part = normal_tr.iloc[: int(len(normal_tr) * 0.8)], normal_tr.iloc[int(len(normal_tr) * 0.8):]
        iforest = IsolationForest(n_estimators=300, max_samples=min(4096, len(fit_part)), random_state=42, n_jobs=-1)
        iforest.fit(X(fit_part))
        threshold = float(np.quantile(-iforest.score_samples(X(cal_part)), 1 - TARGET_FPR))

        test_scores = -iforest.score_samples(X(test))
        flagged = test_scores > threshold
        is_normal = (test["_label"] == "normal").to_numpy()
        metrics = {"anomaly_fpr": float(flagged[is_normal].mean()) if is_normal.any() else 0.0}
        for t in sorted(set(test["_label"]) - {"normal"}):
            m = (test["_label"] == t).to_numpy()
            metrics[f"anomaly_recall_{t}"] = float(flagged[m].mean())
        if (~is_normal).any():
            metrics["anomaly_recall_all"] = float(flagged[~is_normal].mean())

        # Layer 2: supervised classifier, once there are enough labeled attacks
        classifier = None
        n_attack_train = int((train["_label"] != "normal").sum())
        if n_attack_train >= MIN_ATTACK_FOR_CLF:
            classifier = RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=42, n_jobs=-1)
            classifier.fit(X(train), train["_label"])
            pred = classifier.predict(X(test))
            report = classification_report(test["_label"], pred, output_dict=True, zero_division=0)
            mlflow.log_dict(report, "classifier_report.json")
            labels = sorted(set(test["_label"]) | set(pred))
            mlflow.log_dict({"labels": labels, "matrix": confusion_matrix(test["_label"], pred, labels=labels).tolist()},
                            "confusion_matrix.json")
            metrics["clf_macro_f1"] = float(report["macro avg"]["f1-score"])
            metrics["clf_normal_precision"] = float(report.get("normal", {}).get("precision", 0))
            importances = sorted(zip(FEATURE_NAMES, classifier.feature_importances_), key=lambda x: -x[1])[:15]
            mlflow.log_dict(dict(importances), "top_features.json")
        else:
            print(f"classifier skipped: {n_attack_train} labeled attack requests in train, need {MIN_ATTACK_FOR_CLF}")
        metrics["classifier_trained"] = float(classifier is not None)
        mlflow.log_metrics(metrics)
        print("metrics:", json.dumps(metrics, indent=1))

        version = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
        bundle = {"version": version, "trained_at": datetime.now(timezone.utc).isoformat(),
                  "feature_version": FEATURE_VERSION, "feature_names": FEATURE_NAMES,
                  "anomaly": iforest, "threshold": threshold, "classifier": classifier,
                  "metrics": metrics, "mlflow_run_id": run.info.run_id}
        os.makedirs(OUT_DIR, exist_ok=True)
        cand = os.path.join(OUT_DIR, "candidate.joblib")
        joblib.dump(bundle, cand)
        mlflow.log_artifact(cand, "bundle")

        # Gates: low false positives, and no worse than production at catching attacks
        prod = current_production()
        reasons = []
        if metrics["anomaly_fpr"] > MAX_FPR:
            reasons.append(f"FPR {metrics['anomaly_fpr']:.4f} > {MAX_FPR}")
        if prod and "anomaly_recall_all" in prod and "anomaly_recall_all" in metrics \
                and metrics["anomaly_recall_all"] < prod["anomaly_recall_all"] - 0.05:
            reasons.append(f"recall {metrics['anomaly_recall_all']:.3f} < production {prod['anomaly_recall_all']:.3f}")
        promoted = not reasons
        mlflow.set_tag("promoted", str(promoted).lower())
        if reasons:
            mlflow.set_tag("rejected_because", "; ".join(reasons))

        # The bundle is a plain joblib file, not an MLflow "logged model", so register it with the
        # low-level client (mlflow.register_model in MLflow 3 only accepts logged models).
        client = mlflow.MlflowClient()
        try:
            client.create_registered_model(MODEL_NAME)
        except mlflow.exceptions.MlflowException:
            pass                                      # already exists
        mv = client.create_model_version(MODEL_NAME, source=f"{run.info.artifact_uri}/bundle", run_id=run.info.run_id,
                                         tags={"promoted": str(promoted).lower()})
        if promoted:
            client.set_registered_model_alias(MODEL_NAME, "production", mv.version)
            os.replace(cand, os.path.join(OUT_DIR, "model.joblib"))
            print(f"PROMOTED {version} (registry v{mv.version})")
        else:
            print(f"NOT promoted {version}: {'; '.join(reasons)}")


if __name__ == "__main__":
    main()
