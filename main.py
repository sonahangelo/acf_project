"""
main.py -- ACF Entry Point (CLI)

  python main.py --mode learn --count 5000   -> capture + log traffic to SQLite
  python main.py --mode detect                -> live detection (dry-run by default)
"""

import argparse

from capture import start_capture
from features import extract_features, to_model_vector
from flow_tracker import FlowTracker
from ai_model import AnomalyModel
from decision import decide
from firewall import block_ip, load_blocked_ips
from alerting import log_traffic, log_alert
from utils import load_config
from db import get_connection, init_db


def run_learn_mode(cfg, count):
    conn = get_connection(cfg["db_path"])
    init_db(conn)
    tracker = FlowTracker(
        scan_window_seconds=cfg.get("scan_window_seconds", 5),
        flow_timeout_seconds=cfg.get("flow_timeout_seconds", 30),
        syn_window_seconds=cfg.get("syn_window_seconds", 5),
        port_repeat_window_seconds=cfg.get("port_repeat_window_seconds", 10),
    )

    def handle(pkt):
        feats = extract_features(pkt)
        if not feats:
            return
        feats.update(tracker.update(feats))
        log_traffic(conn, feats)

    print(f"[main] LEARN mode: capturing {count} packets to {cfg['db_path']}")
    start_capture(cfg["interface"], cfg["bpf_filter"], handle, count=count)
    print("[main] Done. Now run: python ai_model.py --train")
    conn.close()


def check_hybrid_rules(feats, model, vector, cfg):
    explanation = model.explain(vector, top_n=len(vector))
    z_by_name = {name: z for name, _, z in explanation}

    # A real scan needs BOTH: many distinct ports AND a high rate.
    # High scan_pps alone (e.g. rapid DNS queries, all to port 53) isn't a
    # scan -- it's just a burst to one destination.
    scan_z_threshold = cfg.get("scan_zscore_threshold", 3.0)
    scan_min_ports = cfg.get("scan_min_distinct_ports", 5)
    if (z_by_name.get("scan_distinct_ports", 0) > scan_z_threshold
            and feats.get("scan_distinct_ports", 0) >= scan_min_ports):
        return True, f"port_scan (scan_pps={feats.get('scan_pps')}, distinct_ports={feats.get('scan_distinct_ports')})"

    syn_threshold = cfg.get("syn_flood_threshold", 20)
    if feats.get("syn_count", 0) >= syn_threshold:
        return True, f"syn_flood (syn_count={feats.get('syn_count')} in {cfg.get('syn_window_seconds', 5)}s)"

    port_repeat_threshold = cfg.get("port_repeat_threshold", 8)
    if feats.get("port_repeat_count", 0) >= port_repeat_threshold:
        return True, f"repeated_port_probe (attempts={feats.get('port_repeat_count')} to dst_port={feats.get('dst_port')})"

    exfil_bytes = cfg.get("exfil_bytes_threshold", 5_000_000)
    exfil_duration = cfg.get("exfil_min_duration_seconds", 5)
    if (feats.get("flow_byte_count", 0) >= exfil_bytes
            and feats.get("flow_duration", 0) >= exfil_duration):
        return True, f"possible_exfiltration (bytes={feats.get('flow_byte_count')}, duration={feats.get('flow_duration')}s)"

    return False, None


def run_detect_mode(cfg):
    conn = get_connection(cfg["db_path"])
    init_db(conn)

    model = AnomalyModel(contamination=cfg["contamination"], model_path=cfg["model_path"]).load()
    whitelist = set(cfg.get("whitelist", []) or [])
    dry_run = cfg.get("dry_run", True)
    already_alerted = load_blocked_ips(conn)  # don't re-alert on IPs already blocked from a prior run
    if already_alerted:
        print(f"[main] Loaded {len(already_alerted)} previously blocked IP(s) from database")
    tracker = FlowTracker(
        scan_window_seconds=cfg.get("scan_window_seconds", 5),
        flow_timeout_seconds=cfg.get("flow_timeout_seconds", 30),
        syn_window_seconds=cfg.get("syn_window_seconds", 5),
        port_repeat_window_seconds=cfg.get("port_repeat_window_seconds", 10),
    )

    def handle(pkt):
        feats = extract_features(pkt)
        if not feats:
            return

        feats.update(tracker.update(feats))
        log_traffic(conn, feats)

        vector = to_model_vector(feats)
        label, score = model.predict(vector)

        rule_triggered, rule_reason = check_hybrid_rules(feats, model, vector, cfg)
        effective_label = -1 if rule_triggered else label

        flow_count_for_decision = None if rule_triggered else feats.get("flow_packet_count")
        action = decide(effective_label, score, feats["src_ip"], whitelist,
                         flow_packet_count=flow_count_for_decision)

        if action == "BLOCK":
            if feats["src_ip"] not in already_alerted:
                top_explanation = model.explain(vector)
                if rule_triggered:
                    feats["rule_reason"] = rule_reason
                log_alert(conn, feats, action, score, explanation=top_explanation)
                already_alerted.add(feats["src_ip"])
            block_ip(conn, feats["src_ip"], dry_run=dry_run, reason=feats.get("rule_reason", ""))

    mode_str = "DRY-RUN (no real blocking)" if dry_run else "LIVE (will modify iptables!)"
    print(f"[main] DETECT mode -- {mode_str}")
    start_capture(cfg["interface"], cfg["bpf_filter"], handle, count=0)
    conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Adaptive Cognitive Firewall (ACF) MVP")
    parser.add_argument("--mode", choices=["learn", "detect"], required=True)
    parser.add_argument("--count", type=int, default=200)
    parser.add_argument("--config", default="config.yml")
    args = parser.parse_args()

    config = load_config(args.config)

    if args.mode == "learn":
        run_learn_mode(config, args.count)
    else:
        run_detect_mode(config)
