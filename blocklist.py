"""
blocklist.py -- Inspect and manage persisted IP blocks

Usage:
  python blocklist.py --list
  python blocklist.py --unblock 1.2.3.4
  python blocklist.py --clear-all
"""

import argparse
from db import get_connection, init_db
from firewall import unblock_ip
from utils import load_config


def list_blocks(conn):
    rows = conn.execute(
        "SELECT ip, blocked_at, reason, dry_run FROM blocked_ips ORDER BY blocked_at DESC"
    ).fetchall()
    if not rows:
        print("No IPs currently blocked.")
        return
    print(f"{'IP':<20} {'Blocked At':<22} {'Dry Run':<8} Reason")
    print("-" * 80)
    for ip, blocked_at, reason, dry_run in rows:
        import datetime
        ts = datetime.datetime.fromtimestamp(blocked_at).strftime("%Y-%m-%d %H:%M:%S")
        print(f"{ip:<20} {ts:<22} {'yes' if dry_run else 'no':<8} {reason or ''}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Manage ACF's persisted IP blocklist")
    parser.add_argument("--list", action="store_true", help="Show all currently blocked IPs")
    parser.add_argument("--unblock", metavar="IP", help="Remove a specific IP from the blocklist")
    parser.add_argument("--clear-all", action="store_true", help="Unblock every IP")
    parser.add_argument("--config", default="config.yml")
    args = parser.parse_args()

    cfg = load_config(args.config)
    conn = get_connection(cfg["db_path"])
    init_db(conn)
    dry_run = cfg.get("dry_run", True)

    if args.list:
        list_blocks(conn)
    elif args.unblock:
        unblock_ip(conn, args.unblock, dry_run=dry_run)
    elif args.clear_all:
        rows = conn.execute("SELECT ip FROM blocked_ips").fetchall()
        for (ip,) in rows:
            unblock_ip(conn, ip, dry_run=dry_run)
        print(f"Cleared {len(rows)} block(s).")
    else:
        parser.print_help()

    conn.close()
