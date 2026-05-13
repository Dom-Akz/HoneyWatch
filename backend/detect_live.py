import time
import pandas as pd
import joblib
import json
import os
import threading
from datetime import datetime, timedelta, timezone
from math import log2
from scapy.all import sniff, IP 
from collections import deque

MODEL_PATH = "models/ddos_model.joblib"
LOG_PATH = "data/traffic_log.csv"
ALERTS_PATH = "data/alerts.jsonl"

WINDOW_SECONDS = 1
POLL_INTERVAL = 1.0  
TOP_N_SRCS = 5       

def load_model():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError("Model not found. Run backend/train_model.py first.")
    print(f"[*] Loading model from {MODEL_PATH}")
    return joblib.load(MODEL_PATH)

def compute_window_features(df_window):
    if df_window.empty:
        return None

    pkts = len(df_window)
    bytes_ = int(df_window['length'].sum()) if 'length' in df_window.columns else 0
    avg_pkt_size = float(df_window['length'].mean()) if pkts else 0.0
    unique_srcs = int(df_window['src_ip'].nunique()) if 'src_ip' in df_window.columns else 0
    unique_dsts = int(df_window['dst_ip'].nunique()) if 'dst_ip' in df_window.columns else 0
    tcp_ratio = float((df_window['protocol'] == "TCP").mean()) if 'protocol' in df_window.columns else 0.0
    udp_ratio = float((df_window['protocol'] == "UDP").mean()) if 'protocol' in df_window.columns else 0.0
    icmp_ratio = float((df_window['protocol'] == "ICMP").mean()) if 'protocol' in df_window.columns else 0.0

    src_counts = df_window['src_ip'].value_counts(normalize=True) if 'src_ip' in df_window.columns else pd.Series([])
    entropy_src = 0.0
    if len(src_counts) > 0:
        for p in src_counts:
            if p > 0:
                entropy_src -= p * log2(p)

    top_srcs = []
    if 'src_ip' in df_window.columns:
        top_srcs = df_window['src_ip'].value_counts().head(TOP_N_SRCS).to_dict()

    return {
        "pkts": pkts,
        "bytes": bytes_,
        "avg_pkt_size": avg_pkt_size,
        "unique_srcs": unique_srcs,
        "unique_dsts": unique_dsts,
        "tcp_ratio": tcp_ratio,
        "udp_ratio": udp_ratio,
        "icmp_ratio": icmp_ratio,
        "entropy_src": float(entropy_src),
        "top_srcs": top_srcs
    }

def monitor_and_detect(model):
    print("[*] Starting real-time packet capture...")

    pkt_buffer = deque(maxlen=10000)  

    def packet_handler(pkt):
        if IP in pkt:
            pkt_buffer.append({
                "timestamp": datetime.now(timezone.utc),
                "src_ip": pkt[IP].src,
                "dst_ip": pkt[IP].dst,
                "length": len(pkt),
                "protocol": pkt[IP].proto
            })

    threading.Thread(target=lambda: sniff(prn=packet_handler, store=False), daemon=True).start()

    while True:
        if len(pkt_buffer) == 0:
            time.sleep(POLL_INTERVAL)
            continue

        df_window = pd.DataFrame(list(pkt_buffer))
        if df_window.empty:
            time.sleep(POLL_INTERVAL)
            continue

        proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
        df_window["protocol"] = df_window["protocol"].map(proto_map).fillna("OTHER")

        feats = compute_window_features(df_window)
        if feats is None:
            time.sleep(POLL_INTERVAL)
            continue

        X = pd.DataFrame([{
            "pkts": feats["pkts"],
            "bytes": feats["bytes"],
            "avg_pkt_size": feats["avg_pkt_size"],
            "unique_srcs": feats["unique_srcs"],
            "unique_dsts": feats["unique_dsts"],
            "tcp_ratio": feats["tcp_ratio"],
            "udp_ratio": feats["udp_ratio"],
            "icmp_ratio": feats["icmp_ratio"],
            "entropy_src": feats["entropy_src"]
        }])

        try:
            expected = model.feature_names_in_
            X = X.reindex(columns=expected, fill_value=0)
        except Exception:
            pass

        pred = int(model.predict(X)[0])
        prob = None
        try:
            prob = float(model.predict_proba(X)[0].max())
        except Exception:
            prob = None

        alert = {
            "window_start": datetime.now(timezone.utc).isoformat(),
            "window_end": datetime.now(timezone.utc).isoformat(),
            "predicted_label": pred,
            "probability": round(prob, 4) if prob is not None else None,
            "pkts": feats["pkts"],
            "unique_srcs": feats["unique_srcs"],
            "entropy_src": feats["entropy_src"],
            "top_srcs": feats["top_srcs"],
            "detected_at": datetime.now(timezone.utc).isoformat()
        }
        
        if pred == 1 or (prob is not None and prob > 0.8):
            os.makedirs(os.path.dirname(ALERTS_PATH) or ".", exist_ok=True)
            with open(ALERTS_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(alert) + "\n")
                
            print(f"[ALERT] {alert['detected_at']} pkts={alert['pkts']} srcs={alert['unique_srcs']} prob={alert['probability']}")
        else:
            print(f"[ok] {alert['detected_at']} pkts={alert['pkts']} prob={alert['probability']}")

        time.sleep(POLL_INTERVAL)

def start_background_detection():
    """Start detection without blocking the main thread (used by server.py)."""
    model = load_model()

    thread = threading.Thread(target=monitor_and_detect, args=(model,), daemon=True)
    thread.start()
    print("[server] Background DDoS detection started.")
    return thread

def main():
    model = load_model()
    monitor_and_detect(model)

if __name__ == "__main__":
    main()
