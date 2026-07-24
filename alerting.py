"""
alerting.py -- Logging & Alerting (SQLite-backed)
"""

from db import insert_row, TRAFFIC_COLUMNS


def log_traffic(conn, feature_dict):
    row = {col: feature_dict.get(col) for col in TRAFFIC_COLUMNS}
    insert_row(conn, "traffic", row)


def log_alert(conn, feature_dict, action, score, explanation=None):
    from db import TRAFFIC_COLUMNS
    row = {col: feature_dict.get(col) for col in TRAFFIC_COLUMNS}
    row["action"] = action
    row["score"] = score
    row["top_reasons"] = None
    row["rule_reason"] = feature_dict.get("rule_reason")

    if explanation:
        row["top_reasons"] = "; ".join(
            f"{name}={value} ({dev:+.2f} std)" for name, value, dev in explanation
        )

    insert_row(conn, "alerts", row)

    if action == "BLOCK":
        reason_str = ""
        if row["rule_reason"]:
            reason_str = f" -- {row['rule_reason']}"
        elif explanation:
            top = explanation[0]
            reason_str = f" -- mainly due to {top[0]}={top[1]} ({top[2]:+.2f} std from normal)"
        print(f"[alert] BLOCK {feature_dict['src_ip']} -> {feature_dict['dst_ip']} "
              f"(score={score:.3f}){reason_str}")
