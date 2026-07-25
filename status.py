"""
status.py -- Quick CLI overview of ACF's current state

Usage:
  python status.py
  python status.py --recent 20
"""

import argparse
import datetime
import sqlite3

from utils import load_config


def format_ts(ts):
    if ts is None:
        return "-"
    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def print_status(conn, recent_n=10):
    traffic_count = conn.execute("SELECT COUNT(*) FROM traffic").fetchone()[0]
    alert_count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    blocked_count = conn.execute("SELECT COUNT(*) FROM blocked_ips").fetchone()[0]

    first_ts = conn.execute("SELECT MIN(timestamp) FROM traffic").fetchone()[0]
    last_ts = conn.execute("SELECT MAX(timestamp) FROM traffic").fetchone()[0]

    print("=" * 60)
    print("ACF STATUS")
    print("=" * 60)
    print(f"Traffic rows logged:   {traffic_count:,}")
    print(f"Alerts fired:           {alert_count:,}")
    if traffic_count > 0:
        rate = (alert_count / traffic_count) * 100
        print(f"Alert rate:              {rate:.4f}%")
    print(f"Currently blocked IPs:   {blocked_count}")
    print(f"Data spans:              {format_ts(first_ts)}  to  {format_ts(last_ts)}")
    print()

    print(f"--- Currently blocked ({blocked_count}) ---")
    rows = conn.execute(
        "SELECT ip, blocked_at, reason, dry_run FROM blocked_ips ORDER BY blocked_at DESC"
    ).fetchall()
    if not rows:
        print("  (none)")
    else:
        for ip, blocked_at, reason, dry_run in rows:
            mode = "dry-run" if dry_run else "LIVE"
            print(f"  {ip:<18} {format_ts(blocked_at):<20} [{mode}]  {reason or ''}")
    print()

    print(f"--- Most recent {recent_n} alerts ---")
    rows = conn.execute(
        "SELECT timestamp, src_ip, dst_ip, score, rule_reason, top_reasons "
        "FROM alerts ORDER BY id DESC LIMIT ?",
        (recent_n,),
    ).fetchall()
    if not rows:
        print("  (none)")
    else:
        for ts, src_ip, dst_ip, score, rule_reason, top_reasons in rows:
            reason = rule_reason or top_reasons or "(no reason recorded)"
            print(f"  {format_ts(ts)}  {src_ip:<16} -> {dst_ip:<16} score={score:+.3f}")
            print(f"      {reason}")
    print("=" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Show ACF's current detection status")
    parser.add_argument("--recent", type=int, default=10, help="Number of recent alerts to show")
    parser.add_argument("--config", default="config.yml")
    args = parser.parse_args()

    cfg = load_config(args.config)
    conn = sqlite3.connect(cfg["db_path"])
    print_status(conn, recent_n=args.recent)
    conn.close()
