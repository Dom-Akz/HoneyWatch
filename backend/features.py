import argparse
import math
import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP, ICMP
from collections import Counter
from datetime import datetime, timezone

def entropy_from_counts(counts):
    total = sum(counts)
    if total <= 0:
        return 0.0
    ent = 0.0
    for c in counts:
        p = c / total
        if p > 0:
            ent -= p * math.log2(p)
    return ent

def parse_pcap_to_dataframe(pcap_file):
    """Convert PCAP into a structured DataFrame with timestamp, src_ip, dst_ip, length, protocol"""
    packets = rdpcap(pcap_file)
    rows = []
    for pkt in packets:
        if IP in pkt:
            proto = "OTHER"
            if TCP in pkt:
                proto = "TCP"
            elif UDP in pkt:
                proto = "UDP"
            elif ICMP in pkt:
                proto = "ICMP"
            rows.append({
                'timestamp': datetime.fromtimestamp(pkt.time, tz=timezone.utc),
                'src_ip': pkt[IP].src,
                'dst_ip': pkt[IP].dst,
                'length': len(pkt),
                'protocol': proto
            })
    df = pd.DataFrame(rows)
    return df

def build_features(df, window_seconds=5):
    df['epoch'] = pd.to_datetime(df['timestamp']).astype('int64') // 1_000_000_000
    df['window_id'] = (df['epoch'] // window_seconds).astype(int)

    records = []
    for wid, g in df.groupby('window_id'):
        t0 = int(wid * window_seconds)
        window_start = datetime.fromtimestamp(t0, tz=timezone.utc).isoformat()
        window_end = datetime.fromtimestamp(t0 + window_seconds, tz=timezone.utc).isoformat()

        pkts = len(g)
        bytes_sum = g['length'].sum()
        avg_pkt_size = (bytes_sum / pkts) if pkts else 0.0
        unique_srcs = g['src_ip'].nunique()
        unique_dsts = g['dst_ip'].nunique()

        proto_counts = g['protocol'].value_counts().to_dict()
        tcp_ratio = proto_counts.get('TCP', 0) / pkts if pkts else 0.0
        udp_ratio = proto_counts.get('UDP', 0) / pkts if pkts else 0.0
        icmp_ratio = proto_counts.get('ICMP', 0) / pkts if pkts else 0.0

        entropy_src = entropy_from_counts(g['src_ip'].value_counts().tolist())

        records.append({
            'window_start': window_start,
            'window_end': window_end,
            'pkts': int(pkts),
            'bytes': int(bytes_sum),
            'avg_pkt_size': float(avg_pkt_size),
            'unique_srcs': int(unique_srcs),
            'unique_dsts': int(unique_dsts),
            'tcp_ratio': float(round(tcp_ratio, 4)),
            'udp_ratio': float(round(udp_ratio, 4)),
            'icmp_ratio': float(round(icmp_ratio, 4)),
            'entropy_src': float(round(entropy_src, 4)),
        })
    return pd.DataFrame(records)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', default='data/traffic_log.csv', help='Input CSV of raw packets')
    parser.add_argument('--out', default='data/features.csv', help='Output CSV for features')
    parser.add_argument('--window', type=int, default=5, help='Window size in seconds (integer)')
    args = parser.parse_args()

    print("[*] Reading:", args.input)

    df = pd.read_csv(args.input)

    if 'timestamp' not in df.columns:
        raise SystemExit("Input CSV must have 'timestamp' column")

    print(f"[*] Rows loaded: {len(df)}")
    feat_df = build_features(df, window_seconds=args.window)

    print(f"[*] Windows produced: {len(feat_df)}")
    feat_df.to_csv(args.out, index=False)
    print("[*] Wrote features to:", args.out)
    print(feat_df.head(10).to_string(index=False))

if __name__ == '__main__':
    main()
