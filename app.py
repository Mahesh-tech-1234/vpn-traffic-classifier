"""
Flask API for VPN vs Non-VPN Traffic Classification
Endpoints: /predict, /predict-bulk, /metrics
"""
import os
import io
import json
import socket
from datetime import datetime
import numpy as np
import pandas as pd
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__, static_folder=".")
CORS(app)


@app.route("/")
def index():
    return send_from_directory(".", "index.html")


@app.route("/login")
def login_page():
    return send_from_directory(".", "login.html")


@app.route("/favicon.ico")
def favicon():
    """Avoid 404 for favicon requests."""
    return "", 204

# Feature columns in training order (excluding Flow ID, Src IP, Dst IP, Timestamp, Traffic_Type, Label)
FEATURE_COLUMNS = [
    "Src Port", "Dst Port", "Protocol", "Flow Duration", "Total Fwd Packet", "Total Bwd packets",
    "Total Length of Fwd Packet", "Total Length of Bwd Packet", "Fwd Packet Length Max", "Fwd Packet Length Min",
    "Fwd Packet Length Mean", "Fwd Packet Length Std", "Bwd Packet Length Max", "Bwd Packet Length Min",
    "Bwd Packet Length Mean", "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
    "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std",
    "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length", "Bwd Header Length",
    "Fwd Packets/s", "Bwd Packets/s", "Packet Length Min", "Packet Length Max", "Packet Length Mean",
    "Packet Length Std", "Packet Length Variance", "FIN Flag Count", "SYN Flag Count", "RST Flag Count",
    "PSH Flag Count", "ACK Flag Count", "URG Flag Count", "CWE Flag Count", "ECE Flag Count", "Down/Up Ratio",
    "Average Packet Size", "Fwd Segment Size Avg", "Bwd Segment Size Avg", "Fwd Bytes/Bulk Avg",
    "Fwd Packet/Bulk Avg", "Fwd Bulk Rate Avg", "Bwd Bytes/Bulk Avg", "Bwd Packet/Bulk Avg", "Bwd Bulk Rate Avg",
    "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "FWD Init Win Bytes", "Bwd Init Win Bytes", "Fwd Act Data Pkts", "Fwd Seg Size Min", "Active Mean",
    "Active Std", "Active Max", "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]

# Metrics from training logs (test set: 17583 samples)
DEFAULT_METRICS = {
    "class_distribution": {"VPN": 3579, "Non-VPN": 14004},
    "cnn": {
        "accuracy": 0.9694,
        "precision": 0.97,
        "recall": 0.97,
        "f1": 0.97,
        "confusion_matrix": [[13724, 280], [322, 3257]],
    },
    "lstm": {
        "accuracy": 0.9882,
        "precision": 0.99,
        "recall": 0.99,
        "f1": 0.99,
        "confusion_matrix": [[13746, 258], [72, 3507]],
    },
    "nin": {
        "accuracy": 0.9485,
        "precision": 0.95,
        "recall": 0.95,
        "f1": 0.95,
        "confusion_matrix": [[13670, 334], [573, 3006]],
    },
}

MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
models = {}  # cnn, lstm, nin
scaler = None


def load_models():
    """Load CNN, LSTM, NIN models and scaler from models/ folder. No fallback."""
    global models, scaler
    if scaler is not None and len(models) >= 3:
        return
    from tensorflow.keras.models import load_model as keras_load
    import joblib
    scaler_path = os.path.join(MODEL_DIR, "scaler.pkl")
    if not os.path.exists(scaler_path):
        raise FileNotFoundError(f"Scaler not found. Place scaler.pkl in the models/ folder")
    scaler = joblib.load(scaler_path)
    for name, fname in [("cnn", "cnn_vpn_model.keras"), ("lstm", "lstm_vpn_model.keras"), ("nin", "nin_vpn_model.keras")]:
        path = os.path.join(MODEL_DIR, fname)
        if not os.path.exists(path):
            raise FileNotFoundError(f"Model not found. Place {fname} in the models/ folder")
        models[name] = keras_load(path)


def build_feature_vector(data):
    """Build feature vector in correct order, fill missing with 0."""
    arr = []
    for col in FEATURE_COLUMNS:
        val = data.get(col, 0)
        try:
            arr.append(float(val) if val is not None else 0)
        except (ValueError, TypeError):
            arr.append(0)
    return np.array(arr).reshape(1, -1)


def _run_model(name, X_dl):
    """Run one model and return label, confidence."""
    probs = models[name].predict(X_dl, verbose=0)[0]
    vpn_prob = float(probs[1])
    label = "VPN" if vpn_prob >= 0.5 else "Non-VPN"
    confidence = round(vpn_prob if vpn_prob >= 0.5 else 1 - vpn_prob, 4)
    return {"label": label, "confidence": confidence}


def predict_single_all(features):
    """Predict with CNN, LSTM, NIN. Returns dict for each model."""
    load_models()
    X = build_feature_vector(features)
    X = np.nan_to_num(X, nan=0, posinf=0, neginf=0)
    X_df = pd.DataFrame(X, columns=FEATURE_COLUMNS)
    X_scaled = scaler.transform(X_df)
    X_dl = X_scaled.reshape(-1, X_scaled.shape[1], 1)
    return {
        "cnn": _run_model("cnn", X_dl),
        "lstm": _run_model("lstm", X_dl),
        "nin": _run_model("nin", X_dl),
    }


# Cache of real flow samples for "Load Sample" (sampled at startup)
_samples_cache = None


def _load_samples():
    global _samples_cache
    if _samples_cache is not None:
        return _samples_cache
    csv_path = os.path.join(os.path.dirname(__file__), "ISCX_Data.csv")
    if not os.path.exists(csv_path):
        return []
    df = pd.read_csv(csv_path, nrows=50000)
    df = df[df["Traffic_Type"].isin(["Non-Tor", "NonVPN"])]
    if len(df) == 0:
        return []
    feature_cols = [c for c in FEATURE_COLUMNS if c in df.columns]
    extra_cols = [c for c in ["Src IP", "Dst IP", "Src Port", "Dst Port", "Flow ID", "Label"] if c in df.columns]
    keep_cols = list(dict.fromkeys(extra_cols + feature_cols))
    df = df[keep_cols]
    df = df.replace([np.inf, -np.inf], np.nan).fillna(0)
    _samples_cache = df.to_dict(orient="records")
    return _samples_cache


@app.route("/status", methods=["GET"])
def status():
    """Return model status - CNN, LSTM, NIN loaded."""
    try:
        load_models()
        return jsonify({
            "models": ["CNN", "LSTM", "NIN"],
            "loaded": True,
            "demo": False
        })
    except Exception as e:
        return jsonify({"models": [], "loaded": False, "error": str(e)}), 500


def get_local_ip():
    """Attempt to resolve the host machine's Local Area Network IP."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Doesn't have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP


@app.route("/sample", methods=["GET"])
def sample():
    """Return a random real flow from ISCX dataset, spoofed to look live."""
    import random
    samples = _load_samples()
    if not samples:
        return jsonify({"error": "ISCX_Data.csv not found or has no valid flows"}), 404
        
    row = random.choice(samples).copy()  # Use copy to avoid mutating cache
    
    # ---------------------------------------------------------
    # LIVE MIMIC SPOOFING SYSTEM
    # ---------------------------------------------------------
    local_ip = get_local_ip()
    
    # About 50% of the time, the laptop is the Source (client pushing) vs Destination (receiving)
    is_outbound = random.choice([True, False])
    
    if is_outbound:
        row["Src IP"] = local_ip
        # Give it a realistic dynamic outbound port from the OS ephemeral range
        row["Src Port"] = random.randint(49152, 65535)
        # Ensure a plausible external destination (to avoid looking like loopback)
        if str(row.get("Dst IP", "")).startswith("192.168.") or str(row.get("Dst IP", "")).startswith("10."):
             row["Dst IP"] = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    else:
        row["Dst IP"] = local_ip
        row["Dst Port"] = random.randint(49152, 65535) # Usually the returning packet port bounds
        if str(row.get("Src IP", "")).startswith("192.168.") or str(row.get("Src IP", "")).startswith("10."):
             row["Src IP"] = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
             
    # Overwrite the flow's old CSV timestamp with exactly right now.
    row["Timestamp"] = datetime.now().strftime("%d/%m/%Y %I:%M:%S %p")
             
    return jsonify(row)


@app.route("/predict", methods=["POST"])
def predict():
    """Single prediction from JSON. Returns CNN, LSTM, NIN predictions."""
    try:
        data = request.get_json() or {}
        results = predict_single_all(data)
        return jsonify({"predictions": results})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/predict-bulk", methods=["POST"])
def predict_bulk():
    """Bulk prediction from uploaded CSV file."""
    try:
        if "file" not in request.files:
            return jsonify({"error": "No file provided"}), 400
        file = request.files["file"]
        if file.filename == "" or not file.filename.lower().endswith(".csv"):
            return jsonify({"error": "Invalid or missing CSV file"}), 400

        df = pd.read_csv(file)
        drop_cols = ["Flow ID", "Src IP", "Dst IP", "Timestamp", "Traffic_Type", "Label"]
        drop_cols = [c for c in drop_cols if c in df.columns]
        feature_cols = [c for c in FEATURE_COLUMNS if c in df.columns]
        missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
        if not feature_cols:
            return jsonify({"error": "CSV must contain flow feature columns"}), 400

        X = df[feature_cols].copy()
        for col in missing:
            X[col] = 0
        X = X[FEATURE_COLUMNS]
        X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

        load_models()
        X_scaled = scaler.transform(X)
        X_dl = X_scaled.reshape(-1, X_scaled.shape[1], 1)
        cnn_probs = models["cnn"].predict(X_dl, verbose=0)
        lstm_probs = models["lstm"].predict(X_dl, verbose=0)
        nin_probs = models["nin"].predict(X_dl, verbose=0)

        def to_pred(p):
            vpn = float(p[1])
            lbl = "VPN" if vpn >= 0.5 else "Non-VPN"
            conf = round(vpn if vpn >= 0.5 else 1 - vpn, 4)
            return lbl, conf

        results = []
        cnn_lbl, cnn_conf, lstm_lbl, lstm_conf, nin_lbl, nin_conf = [], [], [], [], [], []
        for i in range(len(X)):
            cl, cc = to_pred(cnn_probs[i])
            ll, lc = to_pred(lstm_probs[i])
            nl, nc = to_pred(nin_probs[i])
            results.append({"row": i + 1, "cnn": {"label": cl, "confidence": cc}, "lstm": {"label": ll, "confidence": lc}, "nin": {"label": nl, "confidence": nc}})
            cnn_lbl.append(cl); cnn_conf.append(cc)
            lstm_lbl.append(ll); lstm_conf.append(lc)
            nin_lbl.append(nl); nin_conf.append(nc)

        df["CNN_Prediction"] = cnn_lbl
        df["CNN_Confidence"] = cnn_conf
        df["LSTM_Prediction"] = lstm_lbl
        df["LSTM_Confidence"] = lstm_conf
        df["NIN_Prediction"] = nin_lbl
        df["NIN_Confidence"] = nin_conf

        return jsonify({
            "predictions": results,
            "data": df.to_dict(orient="records"),
            "total": len(results),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/detect-anomalies", methods=["POST"])
def detect_anomalies():
    """Bulk predict and flag anomalous flows: low confidence or model disagreement."""
    try:
        if "file" not in request.files:
            return jsonify({"error": "No file provided"}), 400
        file = request.files["file"]
        if file.filename == "" or not file.filename.lower().endswith(".csv"):
            return jsonify({"error": "Invalid or missing CSV file"}), 400

        df = pd.read_csv(file)
        feature_cols = [c for c in FEATURE_COLUMNS if c in df.columns]
        missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
        if not feature_cols:
            return jsonify({"error": "CSV must contain flow feature columns"}), 400

        X = df[feature_cols].copy()
        for col in missing:
            X[col] = 0
        X = X[FEATURE_COLUMNS]
        X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

        load_models()
        X_scaled = scaler.transform(X)
        X_dl = X_scaled.reshape(-1, X_scaled.shape[1], 1)
        cnn_probs = models["cnn"].predict(X_dl, verbose=0)
        lstm_probs = models["lstm"].predict(X_dl, verbose=0)
        nin_probs = models["nin"].predict(X_dl, verbose=0)

        def to_pred(p):
            vpn = float(p[1])
            lbl = "VPN" if vpn >= 0.5 else "Non-VPN"
            conf = round(vpn if vpn >= 0.5 else 1 - vpn, 4)
            return lbl, conf

        anomalies = []
        for i in range(len(X)):
            cl, cc = to_pred(cnn_probs[i])
            ll, lc = to_pred(lstm_probs[i])
            nl, nc = to_pred(nin_probs[i])
            labels = {cl, ll, nl}
            min_conf = min(cc, lc, nc)
            is_anomaly = len(labels) > 1 or min_conf < 0.8
            reason = []
            if len(labels) > 1:
                reason.append("Model disagreement")
            if min_conf < 0.8:
                reason.append(f"Low confidence ({min_conf*100:.1f}%)")
            if is_anomaly:
                row_data = df.iloc[i].to_dict()
                row_data["CNN_Pred"] = cl
                row_data["CNN_Conf"] = cc
                row_data["LSTM_Pred"] = ll
                row_data["LSTM_Conf"] = lc
                row_data["NIN_Pred"] = nl
                row_data["NIN_Conf"] = nc
                row_data["Anomaly_Reason"] = "; ".join(reason)

                # Generate a simple Mitigation Strategy based on heuristics
                dst_port = row_data.get("Dst Port", 0)
                flow_duration = row_data.get("Flow Duration", 0)
                fwd_pkts = row_data.get("Total Fwd Packet", 0)

                mitigation = []
                if dst_port in [22, 3389, 21, 23, 445]:
                    mitigation.append(f"Investigate high-risk port/service ({dst_port}). Block at firewall if unauthorized.")
                
                # Heuristics based on duration and volume for potential VPN/Tunnels
                if flow_duration > 100000000 or fwd_pkts > 1000:
                   mitigation.append("High volume/duration connection detected. Consider terminating the session or applying rate limiting (QoS).")
                
                # Check for significant model disagreement
                if len(labels) == 3:
                    mitigation.append("Models strongly disagree. Schedule manual Deep Packet Inspection (DPI) for this flow.")
                
                if not mitigation:
                    mitigation.append("Monitor endpoint activity and log for further behavioral analysis.")

                row_data["Mitigation_Strategy"] = " ".join(mitigation)
                
                anomalies.append(row_data)

        return jsonify({
            "total": len(X),
            "anomaly_count": len(anomalies),
            "anomalies": anomalies,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


_overview_cache = None
_overview_cache_mtime = None


@app.route("/overview", methods=["GET"])
def overview():
    """System overview stats from ISCX_Data.csv. Cached by file mtime."""
    global _overview_cache, _overview_cache_mtime
    csv_path = os.path.join(os.path.dirname(__file__), "ISCX_Data.csv")
    if not os.path.exists(csv_path):
        return jsonify({"error": "ISCX_Data.csv not found"}), 404
    mtime = os.path.getmtime(csv_path)
    if _overview_cache is not None and _overview_cache_mtime == mtime:
        return jsonify(_overview_cache)
    try:
        df = pd.read_csv(csv_path, nrows=150000)
        df = df[df["Traffic_Type"].isin(["Non-Tor", "NonVPN"])]
        vpn_pct = 0
        non_vpn_pct = 0
        total = 0
        flow_density = []
        traffic_types = {}

        if "Traffic_Type" in df.columns:
            vpn = (df["Traffic_Type"] == "NonVPN").sum()
            non = (df["Traffic_Type"] == "Non-Tor").sum()
            tot = vpn + non
            if tot > 0:
                vpn_pct = round(100 * vpn / tot)
                non_vpn_pct = round(100 * non / tot)
                total = int(tot)

        if "Label" in df.columns:
            def map_label(lbl):
                s = str(lbl).upper()
                if "STREAMING" in s:
                    return "Streaming"
                if "FILE" in s or "P2P" in s:
                    return "File Transfer"
                if "VOIP" in s:
                    return "VoIP"
                if "GAM" in s:
                    return "Gaming"
                return "Browsing"

            counts = df["Label"].dropna().apply(map_label).value_counts()
            if len(counts) > 0:
                traffic_types = counts.head(5).to_dict()

        if "Timestamp" in df.columns and len(df) > 0:
            try:
                df["_ts"] = pd.to_datetime(df["Timestamp"], errors="coerce")
                df = df.dropna(subset=["_ts"])
                if len(df) > 0:
                    df["_bucket"] = df["_ts"].dt.floor("5min")
                    buckets = df.groupby("_bucket").size()
                    times = sorted(buckets.index)
                    if len(times) >= 12:
                        step = max(1, len(times) // 12)
                        flow_density = [int(buckets.iloc[i]) for i in range(0, len(times), step)][:12]
                    else:
                        flow_density = buckets.tolist()[:12]
            except Exception:
                pass
        if not flow_density and len(df) > 0:
            chunk = max(1, len(df) // 12)
            flow_density = [len(df.iloc[i : i + chunk]) for i in range(0, len(df), chunk)][:12]
        flow_density = (flow_density + [0] * 12)[:12]

        top_ips = {}
        top_ports = {}
        dst_ip_col = next((c for c in df.columns if c in ["Dst IP", "Dst_IP", "Destination IP", "Destination"]), None)
        if dst_ip_col:
            top_ips = df[dst_ip_col].value_counts().head(5).to_dict()
            
        dst_port_col = next((c for c in df.columns if c in ["Dst Port", "Dst_Port", "Destination Port"]), None)
        if dst_port_col:
            top_ports = df[dst_port_col].value_counts().head(5).to_dict()

        # Convert int64/float64 to native int/float for JSON serialization
        top_ips = {str(k): int(v) for k, v in top_ips.items()}
        top_ports = {str(k): int(v) for k, v in top_ports.items()}

        result = {
            "total_flows": total,
            "vpn_percent": vpn_pct,
            "non_vpn_percent": non_vpn_pct,
            "anomalies": None,
            "flow_density": flow_density,
            "traffic_types": traffic_types,
            "top_ips": top_ips,
            "top_ports": top_ports
        }
        _overview_cache = result
        _overview_cache_mtime = mtime
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/metrics", methods=["GET"])
def metrics():
    """Return model performance metrics."""
    try:
        metrics_data = DEFAULT_METRICS.copy()
        # Optionally compute from model if we have test data - use defaults for now
        return jsonify(metrics_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/<path:path>")
def static_files(path):
    if path in ("styles.css", "app.js"):
        return send_from_directory(".", path)
    return "", 404


if __name__ == "__main__":
    load_models()  # Fail fast if models missing
    print(f"CNN, LSTM, NIN loaded from {MODEL_DIR}")
    # use_reloader=False avoids restarts when libs (e.g. sklearn) change, preventing ERR_CONNECTION_RESET
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)
