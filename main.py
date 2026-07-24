"""
main.py -- ACF Entry Point (CLI)

  python main.py --mode learn --count 3000   -> capture + log traffic (with flow/scan features)
  python main.py --mode detect                -> live detection (dry-run by default)
"""

import argparse

from capture import start_capture
from features import extract_features, to_model_vector
from flow_tracker import FlowTracker
from ai_model import AnomalyModel
from decision import decide
from firewall import block_ip
from alerting import log_traffic, log_alert
from utils import load_config


def run_learn_mode(cfg, count):
    tracker = FlowTracker(
        scan_window_seconds=cfg.get("scan_window_seconds", 5),
        flow_timeout_seconds=cfg.get("flow_timeout_seconds", 30),
    )

    def handle(pkt):
        feats = extract_features(pkt)
        if not feats:
            return
        feats.update(tracker.update(feats))
        log_traffic(cfg["traffic_log_csv"], feats)

    print(f"[main] LEARN mode: capturing {count} packets to {cfg['traffic_log_csv']}")
    start_capture(cfg["interface"], cfg["bpf_filter"], handle, count=count)
    print("[main] Done. Now run: python ai_model.py --train")


def run_detect_mode(cfg):
    model = AnomalyModel(contamination=cfg["contamination"], model_path=cfg["model_path"]).load()
    whitelist = set(cfg.get("whitelist", []) or [])
    dry_run = cfg.get("dry_run", True)
    already_alerted = set()
    tracker = FlowTracker(
        scan_window_seconds=cfg.get("scan_window_seconds", 5),
        flow_timeout_seconds=cfg.get("flow_timeout_seconds", 30),
    )

    def handle(pkt):
        feats = extract_features(pkt)
        if not feats:
            return

        feats.update(tracker.update(feats))
        log_traffic(cfg["traffic_log_csv"], feats)

        vector = to_model_vector(feats)
        label, score = model.predict(vector)

        # Hybrid check: scan-specific features are diluted in the full
        # ensemble score (2 of 10 features), so also check them directly
        # via z-score against training stats -- catches scans the general
        # anomaly model might miss.
        explanation = model.explain(vector, top_n=len(vector))
        scan_z_scores = {name: z for name, _, z in explanation
                          if name in ("scan_distinct_ports", "scan_pps")}
        is_scan_pattern = any(z > 3.0 for z in scan_z_scores.values())

        effective_label = -1 if is_scan_pattern else label
        action = decide(effective_label, score, feats["src_ip"], whitelist,
                         flow_packet_count=feats.get("flow_packet_count"))

        if action == "BLOCK":
            if feats["src_ip"] not in already_alerted:
                top_explanation = model.explain(vector)
                log_alert(cfg["alerts_log_csv"], feats, action, score, explanation=top_explanation)
                already_alerted.add(feats["src_ip"])
            block_ip(feats["src_ip"], dry_run=dry_run)

    mode_str = "DRY-RUN (no real blocking)" if dry_run else "LIVE (will modify iptables!)"
    print(f"[main] DETECT mode -- {mode_str}")
    start_capture(cfg["interface"], cfg["bpf_filter"], handle, count=0)


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
