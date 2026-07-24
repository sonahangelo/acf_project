"""
main.py -- ACF Entry Point (CLI)

  python main.py --mode learn --count 5000   -> capture + log traffic
  python main.py --mode detect                -> live detection (dry-run by default)

Detection is hybrid: the ML anomaly model catches general "doesn't look
like anything I've seen" cases; targeted rules catch specific known attack
shapes whose signal gets diluted in a full-feature ensemble score:
  - port scan:        many distinct ports from one source, quickly
  - SYN flood:         many connection attempts from one source, quickly
  - repeated probing:   many attempts at the same specific port
  - exfiltration:       a single connection moving a lot of data, sustained
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
        syn_window_seconds=cfg.get("syn_window_seconds", 5),
        port_repeat_window_seconds=cfg.get("port_repeat_window_seconds", 10),
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


def check_hybrid_rules(feats, model, vector, cfg):
    """
    Returns (triggered: bool, reason: str or None).
    Checks targeted rules that the general ML model's ensemble score can
    dilute across many unrelated features.
    """
    explanation = model.explain(vector, top_n=len(vector))
    z_by_name = {name: z for name, _, z in explanation}

    # Port scan: many distinct ports, quickly.
    if z_by_name.get("scan_distinct_ports", 0) > 3.0 or z_by_name.get("scan_pps", 0) > 3.0:
        return True, f"port_scan (scan_pps={feats.get('scan_pps')}, distinct_ports={feats.get('scan_distinct_ports')})"

    # SYN flood: many connection attempts from this source, quickly.
    syn_threshold = cfg.get("syn_flood_threshold", 20)
    if feats.get("syn_count", 0) >= syn_threshold:
        return True, f"syn_flood (syn_count={feats.get('syn_count')} in {cfg.get('syn_window_seconds', 5)}s)"

    # Repeated probing of one specific port.
    port_repeat_threshold = cfg.get("port_repeat_threshold", 8)
    if feats.get("port_repeat_count", 0) >= port_repeat_threshold:
        return True, f"repeated_port_probe (attempts={feats.get('port_repeat_count')} to dst_port={feats.get('dst_port')})"

    # Exfiltration: a lot of data moved in one sustained connection.
    exfil_bytes = cfg.get("exfil_bytes_threshold", 5_000_000)
    exfil_duration = cfg.get("exfil_min_duration_seconds", 5)
    if (feats.get("flow_byte_count", 0) >= exfil_bytes
            and feats.get("flow_duration", 0) >= exfil_duration):
        return True, f"possible_exfiltration (bytes={feats.get('flow_byte_count')}, duration={feats.get('flow_duration')}s)"

    return False, None


def run_detect_mode(cfg):
    model = AnomalyModel(contamination=cfg["contamination"], model_path=cfg["model_path"]).load()
    whitelist = set(cfg.get("whitelist", []) or [])
    dry_run = cfg.get("dry_run", True)
    already_alerted = set()
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
        log_traffic(cfg["traffic_log_csv"], feats)

        vector = to_model_vector(feats)
        label, score = model.predict(vector)

        rule_triggered, rule_reason = check_hybrid_rules(feats, model, vector, cfg)
        effective_label = -1 if rule_triggered else label

        # If a rule triggered, it's based on aggregated evidence across many
        # packets/flows over a time window -- it doesn't suffer from the
        # "first packet of a flow is unreliable" problem, so don't let the
        # single-flow guard suppress it.
        flow_count_for_decision = None if rule_triggered else feats.get("flow_packet_count")
        action = decide(effective_label, score, feats["src_ip"], whitelist,
                         flow_packet_count=flow_count_for_decision)

        if action == "BLOCK":
            if feats["src_ip"] not in already_alerted:
                top_explanation = model.explain(vector)
                if rule_triggered:
                    feats["rule_reason"] = rule_reason
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
