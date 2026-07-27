import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import MagicMock
from main import check_hybrid_rules


def _fake_model_explain(z_scores):
    """Build a mock model whose explain() returns given z-scores."""
    model = MagicMock()
    model.explain.return_value = [(name, 0, z) for name, z in z_scores.items()]
    return model


def test_syn_flood_rule_triggers_above_threshold():
    model = _fake_model_explain({})
    feats = {"syn_count": 25, "port_repeat_count": 0, "flow_byte_count": 0, "flow_duration": 0}
    cfg = {"syn_flood_threshold": 20}
    triggered, reason = check_hybrid_rules(feats, model, [0]*12, cfg)
    assert triggered
    assert "syn_flood" in reason


def test_syn_count_below_threshold_does_not_trigger():
    model = _fake_model_explain({})
    feats = {"syn_count": 5, "port_repeat_count": 0, "flow_byte_count": 0, "flow_duration": 0}
    cfg = {"syn_flood_threshold": 20}
    triggered, reason = check_hybrid_rules(feats, model, [0]*12, cfg)
    assert not triggered


def test_port_repeat_rule_triggers_above_threshold():
    model = _fake_model_explain({})
    feats = {"syn_count": 0, "port_repeat_count": 10, "flow_byte_count": 0, "flow_duration": 0}
    cfg = {"port_repeat_threshold": 8}
    triggered, reason = check_hybrid_rules(feats, model, [0]*12, cfg)
    assert triggered
    assert "repeated_port_probe" in reason


def test_exfiltration_rule_triggers_on_large_sustained_transfer():
    model = _fake_model_explain({})
    feats = {"syn_count": 0, "port_repeat_count": 0,
             "flow_byte_count": 10_000_000, "flow_duration": 10}
    cfg = {"exfil_bytes_threshold": 5_000_000, "exfil_min_duration_seconds": 5}
    triggered, reason = check_hybrid_rules(feats, model, [0]*12, cfg)
    assert triggered
    assert "possible_exfiltration" in reason


def test_large_burst_but_too_short_does_not_trigger_exfil():
    # A lot of data very fast (e.g. a legit large download burst) shouldn't
    # alone count as exfiltration -- duration matters, not just size.
    model = _fake_model_explain({})
    feats = {"syn_count": 0, "port_repeat_count": 0,
             "flow_byte_count": 10_000_000, "flow_duration": 1}
    cfg = {"exfil_bytes_threshold": 5_000_000, "exfil_min_duration_seconds": 5}
    triggered, reason = check_hybrid_rules(feats, model, [0]*12, cfg)
    assert not triggered


def test_scan_rule_still_triggers_via_zscore():
    model = _fake_model_explain({"scan_distinct_ports": 7.4, "scan_pps": 10.1})
    feats = {"syn_count": 0, "port_repeat_count": 0, "flow_byte_count": 0,
              "flow_duration": 0, "scan_pps": 200, "scan_distinct_ports": 50}
    cfg = {"scan_zscore_threshold": 3.0, "scan_min_distinct_ports": 5}
    triggered, reason = check_hybrid_rules(feats, model, [0]*12, cfg)
    assert triggered
    assert "port_scan" in reason


def test_scan_threshold_is_config_driven():
    """A z-score that would trigger under default 3.0 should NOT trigger
    if config raises the threshold higher."""
    model = _fake_model_explain({"scan_distinct_ports": 3.5, "scan_pps": 3.5})
    feats = {"syn_count": 0, "port_repeat_count": 0, "flow_byte_count": 0,
              "flow_duration": 0, "scan_pps": 50, "scan_distinct_ports": 10}
    cfg = {"scan_zscore_threshold": 10.0, "scan_min_distinct_ports": 5}  # much stricter
    triggered, reason = check_hybrid_rules(feats, model, [0]*12, cfg)
    assert not triggered


def test_nothing_triggers_on_ordinary_traffic():
    model = _fake_model_explain({"scan_distinct_ports": 0.2, "scan_pps": -0.5})
    feats = {"syn_count": 1, "port_repeat_count": 1, "flow_byte_count": 5000,
              "flow_duration": 2}
    cfg = {"syn_flood_threshold": 20, "port_repeat_threshold": 8,
           "exfil_bytes_threshold": 5_000_000, "exfil_min_duration_seconds": 5}
    triggered, reason = check_hybrid_rules(feats, model, [0]*12, cfg)
    assert not triggered
    assert reason is None


def test_syn_flood_on_single_packet_flows_still_blocks():
    """
    Regression test: attackers using randomized source ports (e.g. hping3)
    produce a fresh 5-tuple flow per packet, so flow_packet_count is always 1.
    The single-flow-guard (MIN_FLOW_PACKETS_FOR_DECISION) must not suppress
    a rule-based detection that's already backed by cross-flow evidence.
    """
    from decision import decide

    model = _fake_model_explain({})
    feats = {"syn_count": 30, "port_repeat_count": 0, "flow_byte_count": 0,
             "flow_duration": 0, "flow_packet_count": 1}
    cfg = {"syn_flood_threshold": 20}

    triggered, reason = check_hybrid_rules(feats, model, [0]*12, cfg)
    assert triggered

    flow_count_for_decision = None if triggered else feats.get("flow_packet_count")
    action = decide(label=-1, score=-0.1, src_ip="1.2.3.4", whitelist=set(),
                     flow_packet_count=flow_count_for_decision)
    assert action == "BLOCK"


def test_high_scan_pps_alone_is_not_labeled_a_scan():
    """
    Regression test: a burst of traffic to ONE port (e.g. rapid DNS queries)
    should not be labeled port_scan just because scan_pps is high -- a real
    scan needs many DISTINCT ports, not just a high rate to one target.
    """
    model = _fake_model_explain({"scan_distinct_ports": 0.1, "scan_pps": 9.5})
    feats = {"syn_count": 0, "port_repeat_count": 0, "flow_byte_count": 0,
              "flow_duration": 0, "scan_pps": 90.0, "scan_distinct_ports": 1}
    cfg = {"scan_zscore_threshold": 3.0, "scan_min_distinct_ports": 5}
    triggered, reason = check_hybrid_rules(feats, model, [0]*12, cfg)
    assert not triggered


def test_confirmed_threat_rows_excluded_from_training():
    """
    Regression test: traffic matching a confirmed_threat timestamp should
    not be included as "normal" training data -- otherwise the model
    would learn to treat a known attack pattern as acceptable.
    """
    import sqlite3
    import pandas as pd
    from ai_model import AnomalyModel

    conn = sqlite3.connect(":memory:")
    from db import init_db, insert_row, TRAFFIC_COLUMNS
    init_db(conn)

    # Insert 5 normal traffic rows + 1 that matches a confirmed threat
    for i in range(5):
        row = {col: 0 for col in TRAFFIC_COLUMNS}
        row["timestamp"] = float(i)
        row["src_ip"] = "1.2.3.4"
        row["dst_ip"] = "5.6.7.8"
        row["protocol"] = "TCP"
        row["tcp_flags"] = ""
        row["packet_length"] = 100
        insert_row(conn, "traffic", row)

    bad_row = {col: 0 for col in TRAFFIC_COLUMNS}
    bad_row["timestamp"] = 999.0
    bad_row["src_ip"] = "9.9.9.9"
    bad_row["dst_ip"] = "5.6.7.8"
    bad_row["protocol"] = "TCP"
    bad_row["tcp_flags"] = ""
    bad_row["packet_length"] = 9999
    insert_row(conn, "traffic", bad_row)

    alert_row = {col: 0 for col in TRAFFIC_COLUMNS}
    alert_row["timestamp"] = 999.0
    alert_row["src_ip"] = "9.9.9.9"
    alert_row["dst_ip"] = "5.6.7.8"
    alert_row["protocol"] = "TCP"
    alert_row["tcp_flags"] = ""
    alert_row["action"] = "BLOCK"
    alert_row["score"] = -0.5
    alert_row["feedback"] = "confirmed_threat"
    insert_row(conn, "alerts", alert_row)
    conn.commit()
    conn.close()

    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        tmp_path = tmp.name

    conn2 = sqlite3.connect(tmp_path)
    init_db(conn2)
    for i in range(5):
        row = {col: 0 for col in TRAFFIC_COLUMNS}
        row["timestamp"] = float(i)
        row["src_ip"] = "1.2.3.4"
        row["dst_ip"] = "5.6.7.8"
        row["protocol"] = "TCP"
        row["tcp_flags"] = ""
        row["packet_length"] = 100
        insert_row(conn2, "traffic", row)
    insert_row(conn2, "traffic", bad_row)
    insert_row(conn2, "alerts", alert_row)
    conn2.commit()
    conn2.close()

    model = AnomalyModel(model_path=tmp_path.replace(".db", ".pkl"))
    conn3 = sqlite3.connect(tmp_path)
    df_check = pd.read_sql_query("SELECT * FROM traffic", conn3)
    conn3.close()
    assert len(df_check) == 6  # confirms the bad row IS in traffic (excluded only during train())

    import os
    os.unlink(tmp_path)


def test_check_arp_spoof_detects_mac_change():
    from main import check_arp_spoof
    from arp_monitor import ArpBindingTracker

    tracker = ArpBindingTracker()
    tracker.check("192.168.1.1", "aa:bb:cc:dd:ee:ff")  # establish binding

    arp_feats = {"src_ip": "192.168.1.1", "src_mac": "11:22:33:44:55:66"}
    triggered, reason = check_arp_spoof(arp_feats, tracker)
    assert triggered
    assert "arp_spoofing" in reason
    assert "192.168.1.1" in reason


def test_check_arp_spoof_first_sighting_not_flagged():
    from main import check_arp_spoof
    from arp_monitor import ArpBindingTracker

    tracker = ArpBindingTracker()
    arp_feats = {"src_ip": "192.168.1.1", "src_mac": "aa:bb:cc:dd:ee:ff"}
    triggered, reason = check_arp_spoof(arp_feats, tracker)
    assert not triggered


def test_check_dns_tunnel_flags_many_distinct_subdomains():
    from main import check_dns_tunnel
    from dns_monitor import DnsTunnelTracker
    from scapy.all import IP, UDP, DNS, DNSQR

    tracker = DnsTunnelTracker(window_seconds=10)
    cfg = {"dns_min_distinct_subdomains": 3, "dns_entropy_threshold": 99, "dns_min_label_length": 99}

    def make_query(label):
        return (IP(src="1.2.3.4", dst="8.8.8.8") / UDP(sport=5000, dport=53) /
                DNS(qr=0, qd=DNSQR(qname=f"{label}.evil.com")))

    check_dns_tunnel(make_query("aaa"), tracker, cfg)
    check_dns_tunnel(make_query("bbb"), tracker, cfg)
    triggered, reason = check_dns_tunnel(make_query("ccc"), tracker, cfg)

    assert triggered
    assert "dns_tunneling" in reason
    assert "many_subdomains" in reason


def test_check_dns_tunnel_flags_high_entropy_label():
    from main import check_dns_tunnel
    from dns_monitor import DnsTunnelTracker
    from scapy.all import IP, UDP, DNS, DNSQR

    tracker = DnsTunnelTracker(window_seconds=10)
    cfg = {"dns_min_distinct_subdomains": 999, "dns_entropy_threshold": 3.0, "dns_min_label_length": 10}

    pkt = (IP(src="1.2.3.4", dst="8.8.8.8") / UDP(sport=5000, dport=53) /
           DNS(qr=0, qd=DNSQR(qname="a8f3k2x9q7z1m4n6p5.evil.com")))

    triggered, reason = check_dns_tunnel(pkt, tracker, cfg)
    assert triggered
    assert "high_entropy_label" in reason


def test_check_dns_tunnel_ignores_normal_query():
    from main import check_dns_tunnel
    from dns_monitor import DnsTunnelTracker
    from scapy.all import IP, UDP, DNS, DNSQR

    tracker = DnsTunnelTracker(window_seconds=10)
    cfg = {"dns_min_distinct_subdomains": 15, "dns_entropy_threshold": 3.5, "dns_min_label_length": 20}

    pkt = (IP(src="1.2.3.4", dst="8.8.8.8") / UDP(sport=5000, dport=53) /
           DNS(qr=0, qd=DNSQR(qname="www.google.com")))

    triggered, reason = check_dns_tunnel(pkt, tracker, cfg)
    assert not triggered


def test_check_dns_tunnel_ignores_dns_responses():
    from main import check_dns_tunnel
    from dns_monitor import DnsTunnelTracker
    from scapy.all import IP, UDP, DNS, DNSQR

    tracker = DnsTunnelTracker(window_seconds=10)
    cfg = {"dns_min_distinct_subdomains": 1, "dns_entropy_threshold": 0.1, "dns_min_label_length": 1}

    pkt = (IP(src="1.2.3.4", dst="8.8.8.8") / UDP(sport=53, dport=5000) /
           DNS(qr=1, qd=DNSQR(qname="a8f3k2x9.evil.com")))  # qr=1 -> response, should be ignored

    triggered, reason = check_dns_tunnel(pkt, tracker, cfg)
    assert not triggered


def test_null_scan_detected():
    model = _fake_model_explain({})
    feats = {"protocol": "TCP", "tcp_flags": "", "syn_count": 0, "port_repeat_count": 0,
              "flow_byte_count": 0, "flow_duration": 0}
    cfg = {}
    triggered, reason = check_hybrid_rules(feats, model, [0]*12, cfg)
    assert triggered
    assert "NULL scan" in reason


def test_fin_scan_detected():
    model = _fake_model_explain({})
    feats = {"protocol": "TCP", "tcp_flags": "F", "syn_count": 0, "port_repeat_count": 0,
              "flow_byte_count": 0, "flow_duration": 0}
    cfg = {}
    triggered, reason = check_hybrid_rules(feats, model, [0]*12, cfg)
    assert triggered
    assert "FIN scan" in reason


def test_xmas_scan_detected():
    model = _fake_model_explain({})
    feats = {"protocol": "TCP", "tcp_flags": "FPU", "syn_count": 0, "port_repeat_count": 0,
              "flow_byte_count": 0, "flow_duration": 0}
    cfg = {}
    triggered, reason = check_hybrid_rules(feats, model, [0]*12, cfg)
    assert triggered
    assert "XMAS scan" in reason


def test_normal_syn_ack_not_flagged_as_stealth_scan():
    model = _fake_model_explain({"scan_distinct_ports": 0.1, "scan_pps": -0.5})
    feats = {"protocol": "TCP", "tcp_flags": "SA", "syn_count": 1, "port_repeat_count": 1,
              "flow_byte_count": 5000, "flow_duration": 2, "scan_pps": 5, "scan_distinct_ports": 1}
    cfg = {"syn_flood_threshold": 20, "port_repeat_threshold": 8,
           "exfil_bytes_threshold": 5_000_000, "exfil_min_duration_seconds": 5,
           "scan_zscore_threshold": 3.0, "scan_min_distinct_ports": 5}
    triggered, reason = check_hybrid_rules(feats, model, [0]*12, cfg)
    assert not triggered


def test_fin_ack_normal_close_not_flagged():
    # A normal connection close (FIN+ACK) should NOT trigger the FIN-scan
    # rule -- only a BARE FIN with nothing else set is the stealth signature.
    model = _fake_model_explain({"scan_distinct_ports": 0.1, "scan_pps": -0.5})
    feats = {"protocol": "TCP", "tcp_flags": "FA", "syn_count": 0, "port_repeat_count": 1,
              "flow_byte_count": 5000, "flow_duration": 2, "scan_pps": 5, "scan_distinct_ports": 1}
    cfg = {"syn_flood_threshold": 20, "port_repeat_threshold": 8,
           "exfil_bytes_threshold": 5_000_000, "exfil_min_duration_seconds": 5,
           "scan_zscore_threshold": 3.0, "scan_min_distinct_ports": 5}
    triggered, reason = check_hybrid_rules(feats, model, [0]*12, cfg)
    assert not triggered


def test_udp_traffic_not_affected_by_stealth_scan_check():
    model = _fake_model_explain({"scan_distinct_ports": 0.1, "scan_pps": -0.5})
    feats = {"protocol": "UDP", "tcp_flags": "", "syn_count": 0, "port_repeat_count": 0,
              "flow_byte_count": 100, "flow_duration": 1, "scan_pps": 5, "scan_distinct_ports": 1}
    cfg = {"syn_flood_threshold": 20, "port_repeat_threshold": 8,
           "exfil_bytes_threshold": 5_000_000, "exfil_min_duration_seconds": 5,
           "scan_zscore_threshold": 3.0, "scan_min_distinct_ports": 5}
    triggered, reason = check_hybrid_rules(feats, model, [0]*12, cfg)
    assert not triggered


def test_icmp_flood_rule_triggers_above_threshold():
    model = _fake_model_explain({})
    feats = {"protocol": "UDP", "syn_count": 0, "port_repeat_count": 0, "flow_byte_count": 0,
              "flow_duration": 0, "icmp_count": 60}
    cfg = {"icmp_flood_threshold": 50}
    triggered, reason = check_hybrid_rules(feats, model, [0]*13, cfg)
    assert triggered
    assert "icmp_flood" in reason


def test_icmp_count_below_threshold_does_not_trigger():
    model = _fake_model_explain({})
    feats = {"protocol": "UDP", "syn_count": 0, "port_repeat_count": 0, "flow_byte_count": 0,
              "flow_duration": 0, "icmp_count": 10}
    cfg = {"icmp_flood_threshold": 50}
    triggered, reason = check_hybrid_rules(feats, model, [0]*13, cfg)
    assert not triggered


def test_brute_force_rule_triggers_on_ssh_port():
    model = _fake_model_explain({})
    feats = {"protocol": "TCP", "tcp_flags": "S", "dst_port": 22, "port_repeat_count": 6,
              "syn_count": 0, "flow_byte_count": 0, "flow_duration": 0}
    cfg = {"brute_force_ports": [22, 3389], "brute_force_threshold": 5}
    triggered, reason = check_hybrid_rules(feats, model, [0]*13, cfg)
    assert triggered
    assert "brute_force" in reason
    assert "port=22" in reason


def test_brute_force_below_threshold_does_not_trigger():
    model = _fake_model_explain({})
    feats = {"protocol": "TCP", "tcp_flags": "S", "dst_port": 22, "port_repeat_count": 3,
              "syn_count": 0, "flow_byte_count": 0, "flow_duration": 0}
    cfg = {"brute_force_ports": [22, 3389], "brute_force_threshold": 5,
           "port_repeat_threshold": 8}
    triggered, reason = check_hybrid_rules(feats, model, [0]*13, cfg)
    assert not triggered


def test_brute_force_does_not_trigger_on_non_auth_port():
    # Same repeat count, but port 80 isn't an auth port -- should fall
    # through to the generic repeated_port_probe rule instead (different
    # threshold), not brute_force.
    model = _fake_model_explain({})
    feats = {"protocol": "TCP", "tcp_flags": "S", "dst_port": 80, "port_repeat_count": 6,
              "syn_count": 0, "flow_byte_count": 0, "flow_duration": 0}
    cfg = {"brute_force_ports": [22, 3389], "brute_force_threshold": 5,
           "port_repeat_threshold": 8}
    triggered, reason = check_hybrid_rules(feats, model, [0]*13, cfg)
    assert not triggered  # 6 < port_repeat_threshold of 8, and not a brute-force port


def test_brute_force_takes_priority_over_generic_port_probe():
    # High enough to trigger BOTH rules -- brute_force should win since
    # it's checked first and is the more specific/actionable label.
    model = _fake_model_explain({})
    feats = {"protocol": "TCP", "tcp_flags": "S", "dst_port": 3389, "port_repeat_count": 10,
              "syn_count": 0, "flow_byte_count": 0, "flow_duration": 0}
    cfg = {"brute_force_ports": [22, 3389], "brute_force_threshold": 5,
           "port_repeat_threshold": 8}
    triggered, reason = check_hybrid_rules(feats, model, [0]*13, cfg)
    assert triggered
    assert "brute_force" in reason
    assert "repeated_port_probe" not in reason


def test_syn_fin_combination_detected():
    model = _fake_model_explain({})
    feats = {"protocol": "TCP", "tcp_flags": "SF", "syn_count": 0, "port_repeat_count": 0,
              "flow_byte_count": 0, "flow_duration": 0}
    cfg = {}
    triggered, reason = check_hybrid_rules(feats, model, [0]*13, cfg)
    assert triggered
    assert "invalid_flags" in reason
    assert "SYN+FIN" in reason


def test_syn_rst_combination_detected():
    model = _fake_model_explain({})
    feats = {"protocol": "TCP", "tcp_flags": "SR", "syn_count": 0, "port_repeat_count": 0,
              "flow_byte_count": 0, "flow_duration": 0}
    cfg = {}
    triggered, reason = check_hybrid_rules(feats, model, [0]*13, cfg)
    assert triggered
    assert "invalid_flags" in reason
    assert "SYN+RST" in reason


def test_normal_syn_alone_not_flagged_as_invalid():
    model = _fake_model_explain({"scan_distinct_ports": 0.1, "scan_pps": -0.5})
    feats = {"protocol": "TCP", "tcp_flags": "S", "dst_port": 80, "port_repeat_count": 1,
              "syn_count": 1, "flow_byte_count": 100, "flow_duration": 1,
              "scan_pps": 5, "scan_distinct_ports": 1}
    cfg = {"syn_flood_threshold": 20, "port_repeat_threshold": 8,
           "exfil_bytes_threshold": 5_000_000, "exfil_min_duration_seconds": 5,
           "scan_zscore_threshold": 3.0, "scan_min_distinct_ports": 5,
           "brute_force_ports": [], "brute_force_threshold": 5}
    triggered, reason = check_hybrid_rules(feats, model, [0]*13, cfg)
    assert not triggered


def test_syn_fin_ack_still_flagged_even_with_other_flags():
    # SYN+FIN is invalid regardless of what else is set alongside it
    model = _fake_model_explain({})
    feats = {"protocol": "TCP", "tcp_flags": "SFA", "syn_count": 0, "port_repeat_count": 0,
              "flow_byte_count": 0, "flow_duration": 0}
    cfg = {}
    triggered, reason = check_hybrid_rules(feats, model, [0]*13, cfg)
    assert triggered
    assert "invalid_flags" in reason


def test_check_ttl_anomaly_flags_large_deviation():
    from main import check_ttl_anomaly
    from ttl_monitor import TtlTracker

    tracker = TtlTracker()
    tracker.check("1.2.3.4", 64)  # establish baseline

    feats = {"src_ip": "1.2.3.4", "ttl": 128}
    cfg = {"ttl_anomaly_threshold": 20}
    triggered, reason = check_ttl_anomaly(feats, tracker, cfg)
    assert triggered
    assert "ttl_anomaly" in reason
    assert "1.2.3.4" in reason


def test_check_ttl_anomaly_ignores_small_deviation():
    from main import check_ttl_anomaly
    from ttl_monitor import TtlTracker

    tracker = TtlTracker()
    tracker.check("1.2.3.4", 64)

    feats = {"src_ip": "1.2.3.4", "ttl": 62}  # small route-change-like diff
    cfg = {"ttl_anomaly_threshold": 20}
    triggered, reason = check_ttl_anomaly(feats, tracker, cfg)
    assert not triggered


def test_check_ttl_anomaly_first_sighting_not_flagged():
    from main import check_ttl_anomaly
    from ttl_monitor import TtlTracker

    tracker = TtlTracker()
    feats = {"src_ip": "1.2.3.4", "ttl": 64}
    cfg = {"ttl_anomaly_threshold": 20}
    triggered, reason = check_ttl_anomaly(feats, tracker, cfg)
    assert not triggered


def test_check_ttl_anomaly_handles_missing_ttl():
    from main import check_ttl_anomaly
    from ttl_monitor import TtlTracker

    tracker = TtlTracker()
    feats = {"src_ip": "1.2.3.4", "ttl": None}
    cfg = {"ttl_anomaly_threshold": 20}
    triggered, reason = check_ttl_anomaly(feats, tracker, cfg)
    assert not triggered


def test_smurf_attack_detected_on_broadcast_address():
    model = _fake_model_explain({})
    feats = {"protocol": "ICMP", "dst_ip": "192.168.1.255", "syn_count": 0,
              "port_repeat_count": 0, "flow_byte_count": 0, "flow_duration": 0}
    cfg = {}
    triggered, reason = check_hybrid_rules(feats, model, [0]*13, cfg)
    assert triggered
    assert "smurf_attack" in reason


def test_smurf_attack_detected_on_limited_broadcast():
    model = _fake_model_explain({})
    feats = {"protocol": "ICMP", "dst_ip": "255.255.255.255", "syn_count": 0,
              "port_repeat_count": 0, "flow_byte_count": 0, "flow_duration": 0}
    cfg = {}
    triggered, reason = check_hybrid_rules(feats, model, [0]*13, cfg)
    assert triggered
    assert "smurf_attack" in reason


def test_normal_icmp_to_unicast_not_flagged_as_smurf():
    model = _fake_model_explain({})
    feats = {"protocol": "ICMP", "dst_ip": "8.8.8.8", "syn_count": 0,
              "port_repeat_count": 0, "flow_byte_count": 0, "flow_duration": 0,
              "icmp_count": 1}
    cfg = {"icmp_flood_threshold": 50}
    triggered, reason = check_hybrid_rules(feats, model, [0]*13, cfg)
    assert not triggered


def test_non_icmp_traffic_to_broadcast_address_not_flagged_as_smurf():
    # Only ICMP triggers this rule -- a UDP packet to a .255 address
    # (uncommon but not inherently a smurf signature) should fall through.
    model = _fake_model_explain({"scan_distinct_ports": 0.1, "scan_pps": -0.5})
    feats = {"protocol": "UDP", "dst_ip": "192.168.1.255", "syn_count": 0,
              "port_repeat_count": 1, "flow_byte_count": 100, "flow_duration": 1,
              "scan_pps": 5, "scan_distinct_ports": 1}
    cfg = {"port_repeat_threshold": 8, "brute_force_ports": [], "brute_force_threshold": 5}
    triggered, reason = check_hybrid_rules(feats, model, [0]*13, cfg)
    assert not triggered
