import argparse
import csv
import os
import sys
from datetime import datetime

try:
    from scapy.all import sniff, rdpcap, IP, TCP, UDP, ICMP, conf
except Exception as e:
    print("Scapy failed to import:", e)
    sys.exit(1)

OUT_DIR = "data"
OUT_FILE = os.path.join(OUT_DIR, "traffic_log.csv")
CSV_FIELDS = ['timestamp', 'src_ip', 'dst_ip', 'protocol', 'length']


def ensure_outfile():
    os.makedirs(OUT_DIR, exist_ok=True)
    if not os.path.exists(OUT_FILE):
        with open(OUT_FILE, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
            writer.writeheader()


def pkt_to_row(pkt):
    row = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "src_ip": None,
        "dst_ip": None,
        "protocol": "OTHER",
        "length": len(pkt) if hasattr(pkt, "__len__") else 0
    }
    if IP in pkt:
        ip = pkt[IP]
        row["src_ip"] = ip.src
        row["dst_ip"] = ip.dst
        if TCP in pkt:
            row["protocol"] = "TCP"
        elif UDP in pkt:
            row["protocol"] = "UDP"
        elif ICMP in pkt:
            row["protocol"] = "ICMP"
        else:
            row["protocol"] = "IP"
    return row


def write_row(row):
    with open(OUT_FILE, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writerow(row)


def process_live(pkt):
    row = pkt_to_row(pkt)
    write_row(row)


def get_default_iface():
    """Try to auto-select a likely active interface on Windows."""
    try:
        iface = conf.iface
        print(f"[*] Auto-detected default interface: {iface}")
        return iface
    except Exception:
        return None


def live_sniff(iface, count, timeout, filter_expr):
    print(f"[+] Starting live capture on iface='{iface}' filter='{filter_expr}' count={count} timeout={timeout}s")
    print("    Press Ctrl-C to stop early.")
    try:
        sniff(
            iface=iface,
            prn=process_live,
            store=False,
            count=count if count > 0 else 0,
            filter=filter_expr,
            timeout=timeout
        )
    except PermissionError:
        print("Permission error: live sniffing usually requires admin privileges.")
        sys.exit(1)
    except Exception as e:
        print("Live sniff error:", e)
        sys.exit(1)


def pcap_read(pcap_path):
    if not os.path.exists(pcap_path):
        print("PCAP file not found:", pcap_path)
        sys.exit(1)
    print(f"[+] Reading pcap file: {pcap_path}")
    pkts = rdpcap(pcap_path)
    print(f"[+] {len(pkts)} packets found. Writing metadata to {OUT_FILE}")
    for pkt in pkts:
        row = pkt_to_row(pkt)
        write_row(row)


def main():
    parser = argparse.ArgumentParser(description="Capture network packets to data/traffic_log.csv")
    parser.add_argument("--iface", "-i", help="Interface to sniff (optional on Windows)")
    parser.add_argument("--pcap", "-p", help="Read from existing pcap file instead of live capture")
    parser.add_argument("--filter", "-f", help="BPF filter (e.g., 'tcp or udp')", default=None)
    parser.add_argument("--count", "-c", type=int, help="Number of packets to capture (0 = unlimited)", default=0)
    parser.add_argument("--timeout", "-t", type=int, help="Stop capture after N seconds", default=None)
    args = parser.parse_args()

    ensure_outfile()

    if args.pcap:
        pcap_read(args.pcap)
    else:
        iface = args.iface or get_default_iface()
        if not iface:
            print("Error: Could not auto-detect interface. Please use --iface <name>")
            sys.exit(1)
        live_sniff(iface, args.count, args.timeout, args.filter)


if __name__ == "__main__":
    main()
