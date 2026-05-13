import threading
import time
import argparse
import requests

def send_http_requests(url, num_requests, delay, dry_run=False):
    """Send multiple GET requests to a target URL."""
    for i in range(num_requests):
        if dry_run:
            print(f"[DRY RUN] thread{threading.get_ident()} would GET {url}")
        else:
            try:
                r = requests.get(url, timeout=1)
                print(f"[{threading.get_ident()}] {r.status_code}")
            except Exception as e:
                print(f"[ERROR] {e}")
        time.sleep(delay)

def main():
    parser = argparse.ArgumentParser(description="Safe local HTTP traffic generator")
    parser.add_argument("--url", type=str, default="http://127.0.0.1:8000/", help="Target URL")
    parser.add_argument("--threads", type=int, default=1, help="Number of concurrent threads")
    parser.add_argument("--requests", type=int, default=10, help="Number of requests per thread")
    parser.add_argument("--delay", type=float, default=0.02, help="Delay between requests (seconds)")
    parser.add_argument("--dry-run", action="store_true", help="Dry run (no traffic sent)")
    args = parser.parse_args()

    print(f"Starting safe HTTP generator -> url={args.url} threads={args.threads} reqs/thread={args.requests} delay={args.delay}")
    if args.dry_run:
        print("DRY RUN: no network traffic will be sent.")
    else:
        confirm = input("⚠️  Do you want to send real traffic? (y/n): ").strip().lower()
        if confirm != "y":
            print("Aborted by user.")
            return

    threads = []
    for _ in range(args.threads):
        t = threading.Thread(target=send_http_requests, args=(args.url, args.requests, args.delay, args.dry_run))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print("✅ Traffic generation completed safely.")

if __name__ == "__main__":
    main()