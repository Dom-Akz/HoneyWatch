import argparse
import socket
import threading
import time
import sys
from collections import Counter

DEFAULT_THREADS = 2
DEFAULT_PKTS = 200
DEFAULT_PAYLOAD = 64
DEFAULT_DELAY = 0.02
DEFAULT_MAX_PACKETS = 1000

LOCAL_ALLOWED = {"127.0.0.1", "localhost", "::1"}

def is_localhost(addr):
    try:
        return addr in LOCAL_ALLOWED or addr.startswith("127.") or addr.startswith("::1")
    except Exception:
        return False
    
def udp_worker(target, port, pkts, payload, delay, dry_run, stats, tid):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent = 0
    for i in range(pkts):
        if dry_run:
            pass
        else:
            try:
                s.sendto(payload, (target, port))
            except Exception:
                pass
        sent += 1
        stats["sent"] += 1
        if delay:
            time.sleep(delay)
    s.close()
    return sent

def tcp_worker(target, port, pkts, payload, delay, dry_run, stats, tid):
    sent = 0
    for i in range(pkts):
        if dry_run:
            pass
        else:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.0)
                s.connect((target, port))
                s.sendall(payload)
                s.close()
            except Exception:
                pass
        sent += 1
        stats["sent"] += 1
        if delay:
            time.sleep(delay)
    return sent

def main():
    parser = argparse.ArgumentParser(description="Safe UDP/TCP burst generator (localhost only by default)")
    parser.add_argument("--mode", choices=["udp","tcp"], default="udp")
    parser.add_argument("--target", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9999)
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS)
    parser.add_argument("--pkts", type=int, default=DEFAULT_PKTS, help="Packets per thread (will be scaled if exceeding max)")
    parser.add_argument("--payload-size", type=int, default=DEFAULT_PAYLOAD)
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY)
    parser.add_argument("--max-packets", type=int, default=DEFAULT_MAX_PACKETS)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--allow-remote", action="store_true", help="Allow non-localhost (dangerous)")
    args = parser.parse_args()

    if not args.allow_remote and not is_localhost(args.target):
        print("ERROR: Target is not localhost. Use --allow-remote to override (not recommended).")
        sys.exit(1)

    planned = args.threads * args.pkts
    if planned > args.max_packets:
        per_thread = max(1, args.max_packets // args.threads)
        print(f"Planned total {planned} > max {args.max_packets}; reducing pkts/thread -> {per_thread}")
        args.pkts = per_thread

    print(f"Mode={args.mode} target={args.target}:{args.port} threads={args.threads} pkts/thread={args.pkts} delay={args.delay} dry_run={args.dry_run}")
    if not args.dry_run:
        answer = input("Type 'y' to start, anything else to abort: ").strip().lower()
        if answer != "y":
            print("Aborted.")
            sys.exit(0)
    stats = Counter()
    payload = b"x" * max(1, args.payload_size)
    threads = []
    start = time.time()
    for i in range(args.threads):
        if args.mode == "udp":
            t = threading.Thread(target=udp_worker, args=(args.target, args.port, args.pkts, payload, args.delay, args.dry_run, stats, i), daemon=True)
        else:
            t = threading.Thread(target=tcp_worker, args=(args.target, args.port, args.pkts, payload, args.delay, args.dry_run, stats, i), daemon=True)
        threads.append(t)
        t.start()

    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("Interrupted by user.")
    duration = time.time() - start
    print(f"Completed. Sent (or planned) {stats['sent']} packets in {duration:.2f}s")

if __name__ == "__main__":
    main()