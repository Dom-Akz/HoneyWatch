import json
import os
import time
from datetime import datetime, timezone
import argparse

OUT = "data/alerts.jsonl"

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def make_alert(top_srcs, pkts=1000, prob=0.95, label=1):
    ts = now_iso()
    return {
        "window_start": ts,
        "window_end": ts,
        "predicted_label": label,
        "probability": round(prob, 2),
        "pkts": pkts,
        "unique_srcs": len(top_srcs),
        "entropy_src": 0.1,
        "top_srcs": top_srcs,
        "detected_at": ts
    }

def append_alert(alert):
    os.makedirs(os.path.dirname(OUT) or ".", exist_ok=True)
    with open(OUT, "a", encoding="utf-8") as f:
        f.write(json.dumps(alert) + "\n")
    print("WROTE:", alert["detected_at"], "pkts=", alert["pkts"], "srcs=", list(alert["top_srcs"].keys()))

def demo_sequence(sleep_between=1.0, repeat=1):
    demo_alerts = [
        ({"8.8.8.8": 1200, "1.1.1.1": 300}, 1500, 0.98),
        ({"104.244.42.1": 700}, 700, 0.90),
        ({"208.21.2.184": 4000}, 4000, 0.99),
        ({"104.26.8.44": 2000, "142.250.67.214": 800}, 2800, 0.96)
    ]

    for _ in range(repeat):
        for srcs, pkts, prob in demo_alerts:
            a = make_alert(top_srcs=srcs, pkts=pkts, prob=prob, label=1)
            append_alert(a)
            time.sleep(sleep_between)

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--sleep", type=float, default=1.0, help="Seconds between alerts")
    p.add_argument("--repeat", type=int, default=1, help="How many times to cycle demo alerts")
    args = p.parse_args()

    demo_sequence(sleep_between=args.sleep, repeat=args.repeat)
