"""
retention.py -- Log rotation / archival for the SQLite database

Keeps the traffic table from growing unbounded. Policy:
  - traffic: archived (optional) then deleted after --traffic-days
  - alerts: kept much longer (they're the audit trail), deleted after --alert-days
  - blocked_ips: never auto-deleted (use blocklist.py to manage manually)

Usage:
  python retention.py --dry-run              # show what WOULD be deleted
  python retention.py                          # actually delete old rows
  python retention.py --archive               # also export old traffic rows to CSV first
"""

import argparse
import csv
import os
import sqlite3
import time

from utils import load_config
from db import TRAFFIC_COLUMNS


def archive_traffic(conn, cutoff_ts, archive_dir="data/archive"):
    rows = conn.execute(
        f"SELECT {', '.join(TRAFFIC_COLUMNS)} FROM traffic WHERE timestamp < ?",
        (cutoff_ts,),
    ).fetchall()
    if not rows:
        return 0

    os.makedirs(archive_dir, exist_ok=True)
    filename = f"{archive_dir}/traffic_archive_{int(time.time())}.csv"
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(TRAFFIC_COLUMNS)
        writer.writerows(rows)

    print(f"[retention] Archived {len(rows)} traffic row(s) to {filename}")
    return len(rows)


def prune_table(conn, table, cutoff_ts, dry_run):
    count = conn.execute(
        f"SELECT COUNT(*) FROM {table} WHERE timestamp < ?", (cutoff_ts,)
    ).fetchone()[0]

    if count == 0:
        print(f"[retention] {table}: nothing older than cutoff, nothing to prune")
        return 0

    if dry_run:
        print(f"[retention] {table}: WOULD delete {count} row(s) (dry-run, no changes made)")
    else:
        conn.execute(f"DELETE FROM {table} WHERE timestamp < ?", (cutoff_ts,))
        conn.commit()
        print(f"[retention] {table}: deleted {count} row(s)")
    return count


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Prune old ACF database rows")
    parser.add_argument("--traffic-days", type=int, default=7,
                         help="Delete traffic rows older than this many days (default: 7)")
    parser.add_argument("--alert-days", type=int, default=90,
                         help="Delete alert rows older than this many days (default: 90)")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be deleted, change nothing")
    parser.add_argument("--archive", action="store_true", help="Export old traffic rows to CSV before deleting")
    parser.add_argument("--config", default="config.yml")
    args = parser.parse_args()

    cfg = load_config(args.config)
    conn = sqlite3.connect(cfg["db_path"])

    now = time.time()
    traffic_cutoff = now - (args.traffic_days * 86400)
    alert_cutoff = now - (args.alert_days * 86400)

    print(f"[retention] Traffic cutoff: rows older than {args.traffic_days} day(s)")
    print(f"[retention] Alert cutoff:   rows older than {args.alert_days} day(s)")
    print()

    if args.archive and not args.dry_run:
        archive_traffic(conn, traffic_cutoff)

    traffic_pruned = prune_table(conn, "traffic", traffic_cutoff, args.dry_run)
    alerts_pruned = prune_table(conn, "alerts", alert_cutoff, args.dry_run)

    if not args.dry_run and (traffic_pruned or alerts_pruned):
        conn.execute("VACUUM")
        print("[retention] Reclaimed disk space (VACUUM complete)")

    conn.close()
