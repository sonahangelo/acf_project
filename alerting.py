"""
alerting.py -- Logging & Alerting

Writes traffic feature rows and decision alerts to CSV (SQLite/DB swap-in
comes later per the roadmap -- CSV is fine for the MVP).
"""

import csv
import os


def _write_row(path, row_dict):
    file_exists = os.path.exists(path)
    os.makedirs(os.path.dirname(path), exist_ok=True) if os.path.dirname(path) else None
    with open(path, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(row_dict.keys()))
        if not file_exists:
            writer.writeheader()
        writer.writerow(row_dict)


def log_traffic(csv_path, feature_dict):
    _write_row(csv_path, feature_dict)


def log_alert(csv_path, feature_dict, action, score, explanation=None):
    row = dict(feature_dict)
    row["action"] = action
    row["score"] = score
    if explanation:
        row["top_reasons"] = "; ".join(
            f"{name}={value} ({dev:+.2f} std)" for name, value, dev in explanation
        )
    _write_row(csv_path, row)
    if action == "BLOCK":
        reason_str = ""
        if explanation:
            top = explanation[0]
            reason_str = f" -- mainly due to {top[0]}={top[1]} ({top[2]:+.2f} std from normal)"
        print(f"[alert] BLOCK {feature_dict['src_ip']} -> {feature_dict['dst_ip']} "
              f"(score={score:.3f}){reason_str}")
