"""
feedback.py -- Mark alerts as false_positive or confirmed_threat

This closes the loop: false positives get excluded from future training
data (so the model stops treating the same pattern as anomalous-but-normal),
and confirmed threats become reference examples for validating future
model versions.

Usage:
  python feedback.py --list                        # show unlabeled alerts
  python feedback.py --mark 5 --false-positive
  python feedback.py --mark 5 --confirmed-threat
  python feedback.py --summary                      # counts by label
"""

import argparse
import sqlite3
import datetime

from utils import load_config


def list_unlabeled(conn, limit=20):
    rows = conn.execute(
        "SELECT id, timestamp, src_ip, dst_ip, action, score, rule_reason, top_reasons "
        "FROM alerts WHERE feedback IS NULL ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    if not rows:
        print("No unlabeled alerts.")
        return
    print(f"{'ID':<6} {'Time':<20} {'Src IP':<16} {'Score':<8} Reason")
    print("-" * 90)
    for id_, ts, src_ip, dst_ip, action, score, rule_reason, top_reasons in rows:
        t = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
        reason = rule_reason or top_reasons or ""
        print(f"{id_:<6} {t:<20} {src_ip:<16} {score:+.3f}  {reason[:50]}")


def mark_alert(conn, alert_id, label):
    result = conn.execute("SELECT id FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if not result:
        print(f"No alert found with id {alert_id}")
        return
    conn.execute("UPDATE alerts SET feedback = ? WHERE id = ?", (label, alert_id))
    conn.commit()
    print(f"Alert {alert_id} marked as '{label}'")


def summary(conn):
    rows = conn.execute(
        "SELECT COALESCE(feedback, 'unlabeled'), COUNT(*) FROM alerts GROUP BY feedback"
    ).fetchall()
    print("Alert feedback summary:")
    for label, count in rows:
        print(f"  {label:<20} {count}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Mark ACF alerts as false positive or confirmed threat")
    parser.add_argument("--list", action="store_true", help="Show unlabeled alerts")
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--mark", type=int, metavar="ID", help="Alert ID to label")
    parser.add_argument("--false-positive", action="store_true")
    parser.add_argument("--confirmed-threat", action="store_true")
    parser.add_argument("--summary", action="store_true", help="Show counts by label")
    parser.add_argument("--config", default="config.yml")
    args = parser.parse_args()

    cfg = load_config(args.config)
    conn = sqlite3.connect(cfg["db_path"])

    from db import init_db
    init_db(conn)

    if args.list:
        list_unlabeled(conn, limit=args.limit)
    elif args.mark is not None:
        if args.false_positive:
            mark_alert(conn, args.mark, "false_positive")
        elif args.confirmed_threat:
            mark_alert(conn, args.mark, "confirmed_threat")
        else:
            print("Specify --false-positive or --confirmed-threat with --mark")
    elif args.summary:
        summary(conn)
    else:
        parser.print_help()

    conn.close()
