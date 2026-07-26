"""
main.py -- ACF Entry Point (CLI)

  python main.py --mode learn --count 5000   -> capture + log traffic to SQLite
  python main.py --mode detect                -> live detection (dry-run by default)
"""

import argparse

from scapy.all import ARP
from capture import start_capture
from features import extract_features, to_model_vector, extract_arp_features, extract_dns_features
from dns_monitor import DnsTunnelTracker, shannon_entropy
from flow_tracker import FlowTracker
from ttl_monitor import TtlTracker
from arp_monitor import ArpBindingTracker
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
        icmp_window_seconds=cfg.get("icmp_window_seconds", 5),
    )

    def handle(pkt):
        if pkt.haslayer(ARP):
            return  # learn mode only builds ML training data; ARP handled separately in detect mode
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
    # Stealth scan flag combinations (nmap -sN/-sF/-sX). These essentially
    # never occur in legitimate traffic -- unlike SYN-based scans, they're
    # specifically designed to evade SYN-flood/scan detectors, so this is
    # a stateless, immediate check rather than a volume-based one.
    if feats.get("protocol") == "TCP":
        flags = feats.get("tcp_flags") or ""
        flag_set = set(flags)
        if flags == "":
            return True, "stealth_scan (NULL scan: TCP packet with no flags set)"
        if flag_set == {"F"}:
            return True, "stealth_scan (FIN scan: only FIN flag set)"
        if {"F", "P", "U"} <= flag_set:
            return True, "stealth_scan (XMAS scan: FIN+PSH+URG flags set)"

        # Invalid/contradictory flag combinations -- a packet can't
        # logically be opening (SYN) and closing (FIN/RST) a connection
        # at the same time. Only crafted packets do this, typically for
        # firewall/IDS evasion or OS fingerprinting tools.
        if {"S", "F"} <= flag_set:
            return True, "invalid_flags (SYN+FIN set together: contradictory, crafted packet)"
        if {"S", "R"} <= flag_set:
            return True, "invalid_flags (SYN+RST set together: contradictory, crafted packet)"

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

    # Brute-force login attempts: repeated connection attempts to a known
    # authentication port, with a lower/faster threshold than the generic
    # port-probe rule below, since real brute-force tools hit these ports
    # very rapidly and we want to catch it earlier than a generic probe.
    brute_force_ports = set(cfg.get("brute_force_ports", [22, 23, 21, 3389, 3306, 5432, 1433, 5900]))
    brute_force_threshold = cfg.get("brute_force_threshold", 5)
    if (feats.get("dst_port") in brute_force_ports
            and feats.get("port_repeat_count", 0) >= brute_force_threshold):
        return True, (f"brute_force (port={feats.get('dst_port')}, "
                       f"attempts={feats.get('port_repeat_count')})")

    # Repeated probing of one specific port (generic, any port).
    port_repeat_threshold = cfg.get("port_repeat_threshold", 8)
    if feats.get("port_repeat_count", 0) >= port_repeat_threshold:
        return True, f"repeated_port_probe (attempts={feats.get('port_repeat_count')} to dst_port={feats.get('dst_port')})"

# ICMP flood (ping flood).
    icmp_threshold = cfg.get("icmp_flood_threshold", 50)
    if feats.get("icmp_count", 0) >= icmp_threshold:
        return True, f"icmp_flood (icmp_count={feats.get('icmp_count')} in {cfg.get('icmp_window_seconds', 5)}s)"

    exfil_bytes = cfg.get("exfil_bytes_threshold", 5_000_000)
    exfil_duration = cfg.get("exfil_min_duration_seconds", 5)
    if (feats.get("flow_byte_count", 0) >= exfil_bytes
            and feats.get("flow_duration", 0) >= exfil_duration):
        return True, f"possible_exfiltration (bytes={feats.get('flow_byte_count')}, duration={feats.get('flow_duration')}s)"

    return False, None

def check_arp_spoof(arp_feats, tracker):
    """
    Returns (triggered: bool, reason: str or None).
    """
    is_conflict, previous_mac = tracker.check(arp_feats["src_ip"], arp_feats["src_mac"])
    if is_conflict:
        reason = (f"arp_spoofing (ip={arp_feats['src_ip']} now claimed by "
                   f"mac={arp_feats['src_mac']}, previously mac={previous_mac})")
        return True, reason
    return False, None
def check_ttl_anomaly(feats, tracker, cfg):
    """
    Returns (triggered: bool, reason: str or None).
    """
    ttl = feats.get("ttl")
    if ttl is None:
        return False, None

    baseline, diff = tracker.check(feats["src_ip"], ttl)
    if baseline is None:
        return False, None  # first sighting, nothing to compare yet

    threshold = cfg.get("ttl_anomaly_threshold", 20)
    if diff >= threshold:
        return True, (f"ttl_anomaly (ip={feats['src_ip']} ttl={ttl} vs baseline={baseline}, "
                       f"diff={diff} -- possible IP spoofing)")
    return False, None

def check_dns_tunnel(pkt, tracker, cfg):
    """
    Returns (triggered: bool, reason: str or None).
    """
    dns_feats = extract_dns_features(pkt)
    if not dns_feats:
        return False, None

    distinct_subdomains = tracker.record(
        dns_feats["src_ip"], dns_feats["base_domain"],
        dns_feats["leftmost_label"], dns_feats["timestamp"],
    )

    min_distinct = cfg.get("dns_min_distinct_subdomains", 15)
    if distinct_subdomains >= min_distinct:
        return True, (f"dns_tunneling (many_subdomains: {distinct_subdomains} distinct "
                       f"labels under {dns_feats['base_domain']} from {dns_feats['src_ip']})")

    entropy = shannon_entropy(dns_feats["leftmost_label"])
    min_length = cfg.get("dns_min_label_length", 20)
    entropy_threshold = cfg.get("dns_entropy_threshold", 3.5)
    if len(dns_feats["leftmost_label"]) >= min_length and entropy >= entropy_threshold:
        return True, (f"dns_tunneling (high_entropy_label: '{dns_feats['leftmost_label'][:30]}...' "
                       f"entropy={entropy:.2f} under {dns_feats['base_domain']})")

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
    arp_tracker = ArpBindingTracker()
    dns_tracker = DnsTunnelTracker(window_seconds=cfg.get("dns_window_seconds", 10))
    ttl_tracker = TtlTracker()
    tracker = FlowTracker(
        scan_window_seconds=cfg.get("scan_window_seconds", 5),
        flow_timeout_seconds=cfg.get("flow_timeout_seconds", 30),
        syn_window_seconds=cfg.get("syn_window_seconds", 5),
        port_repeat_window_seconds=cfg.get("port_repeat_window_seconds", 10),
    )

    def handle(pkt):
        try:
            if pkt.haslayer(ARP):
                arp_feats = extract_arp_features(pkt)
                if not arp_feats:
                    return
                triggered, reason = check_arp_spoof(arp_feats, arp_tracker)
                if triggered:
                    log_traffic(conn, arp_feats)
                    if arp_feats["src_ip"] not in already_alerted:
                        arp_feats["rule_reason"] = reason
                        log_alert(conn, arp_feats, "BLOCK", 0.0, explanation=None)
                        already_alerted.add(arp_feats["src_ip"])
                    block_ip(conn, arp_feats["src_ip"], dry_run=dry_run, reason=reason)
                return

            feats = extract_features(pkt)
            if not feats:
                return

            feats.update(tracker.update(feats))
            log_traffic(conn, feats)

            vector = to_model_vector(feats)
            label, score = model.predict(vector)

            rule_triggered, rule_reason = check_hybrid_rules(feats, model, vector, cfg)

            dns_triggered, dns_reason = check_dns_tunnel(pkt, dns_tracker, cfg)
            if dns_triggered:
                rule_triggered = True
                rule_reason = dns_reason if not rule_reason else f"{rule_reason}; {dns_reason}"

            ttl_triggered, ttl_reason = check_ttl_anomaly(feats, ttl_tracker, cfg)
            if ttl_triggered:
                rule_triggered = True
                rule_reason = ttl_reason if not rule_reason else f"{rule_reason}; {ttl_reason}"

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
        except Exception as e:
            import traceback
            print(f"[main] ERROR in packet handler: {e}")
            traceback.print_exc()

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
