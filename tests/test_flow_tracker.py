import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flow_tracker import FlowTracker


def _pkt(ts, src_ip="1.2.3.4", dst_ip="5.6.7.8", src_port=1000, dst_port=80,
         protocol="TCP", packet_length=100):
    return {
        "timestamp": ts, "src_ip": src_ip, "dst_ip": dst_ip,
        "src_port": src_port, "dst_port": dst_port,
        "protocol": protocol, "packet_length": packet_length,
    }


def test_first_packet_of_flow_has_zero_rate_not_inflated_spike():
    # Regression test: first packet used to compute pps as length/0.001,
    # producing a misleading ~1000+ pps spike on every new connection.
    tracker = FlowTracker()
    feats = tracker.update(_pkt(ts=1000.0))
    assert feats["flow_packet_count"] == 1
    assert feats["flow_pps"] == 0.0
    assert feats["flow_bps"] == 0.0


def test_second_packet_computes_real_rate():
    tracker = FlowTracker()
    tracker.update(_pkt(ts=1000.0))
    feats = tracker.update(_pkt(ts=1000.5, packet_length=100))
    assert feats["flow_packet_count"] == 2
    assert feats["flow_pps"] > 0


def test_dns_traffic_excluded_from_scan_tracking():
    tracker = FlowTracker()
    feats = tracker.update(_pkt(ts=1000.0, protocol="UDP", dst_port=53))
    assert feats["scan_distinct_ports"] == 0


def test_dns_only_history_does_not_crash_scan_pps():
    # Regression test: an empty scan history (because the only packet seen
    # was DNS, which is excluded) used to crash on history[0][0].
    tracker = FlowTracker()
    feats1 = tracker.update(_pkt(ts=1000.0, protocol="UDP", dst_port=53))
    feats2 = tracker.update(_pkt(ts=1000.1, protocol="UDP", dst_port=53))
    assert feats2["scan_pps"] == 0.0


def test_scan_pattern_produces_multiple_distinct_ports():
    tracker = FlowTracker(scan_window_seconds=5)
    for i, port in enumerate([21, 22, 23, 80, 443]):
        tracker.update(_pkt(ts=1000.0 + i * 0.01, dst_port=port, protocol="TCP"))
    feats = tracker.update(_pkt(ts=1000.1, dst_port=8080, protocol="TCP"))
    assert feats["scan_distinct_ports"] == 6


def test_old_entries_fall_outside_scan_window():
    tracker = FlowTracker(scan_window_seconds=5)
    tracker.update(_pkt(ts=1000.0, dst_port=21))
    feats = tracker.update(_pkt(ts=1010.0, dst_port=22))  # 10s later, window is 5s
    assert feats["scan_distinct_ports"] == 1  # only the recent one counts


def test_syn_flood_counted_correctly():
    tracker = FlowTracker(syn_window_seconds=5)
    for i in range(5):
        feats = _pkt(ts=1000.0 + i * 0.1, dst_port=80)
        feats["tcp_flags"] = "S"
        result = tracker.update(feats)
    assert result["syn_count"] == 5


def test_non_syn_packets_dont_inflate_syn_count():
    tracker = FlowTracker(syn_window_seconds=5)
    feats = _pkt(ts=1000.0, dst_port=80)
    feats["tcp_flags"] = "PA"  # established connection traffic, not a new attempt
    result = tracker.update(feats)
    assert result["syn_count"] == 0


def test_syn_count_respects_window():
    tracker = FlowTracker(syn_window_seconds=5)
    old = _pkt(ts=1000.0, dst_port=80)
    old["tcp_flags"] = "S"
    tracker.update(old)

    recent = _pkt(ts=1010.0, dst_port=80)  # 10s later, window is 5s
    recent["tcp_flags"] = "S"
    result = tracker.update(recent)
    assert result["syn_count"] == 1  # old one should have expired


def test_repeated_port_probe_counted():
    tracker = FlowTracker(port_repeat_window_seconds=10)
    for i in range(4):
        feats = _pkt(ts=1000.0 + i * 0.5, dst_ip="9.9.9.9", dst_port=22)
        feats["tcp_flags"] = "S"
        result = tracker.update(feats)
    assert result["port_repeat_count"] == 4


def test_port_repeat_is_specific_to_one_endpoint():
    tracker = FlowTracker(port_repeat_window_seconds=10)
    a = _pkt(ts=1000.0, dst_ip="9.9.9.9", dst_port=22)
    a["tcp_flags"] = "S"
    tracker.update(a)

    b = _pkt(ts=1000.1, dst_ip="9.9.9.9", dst_port=23)  # different port
    b["tcp_flags"] = "S"
    result = tracker.update(b)
    assert result["port_repeat_count"] == 1  # separate counter per (src,dst,port)


def test_icmp_flood_counted_correctly():
    tracker = FlowTracker(icmp_window_seconds=5)
    for i in range(5):
        feats = _pkt(ts=1000.0 + i * 0.1, protocol="ICMP", dst_port=None)
        result = tracker.update(feats)
    assert result["icmp_count"] == 5


def test_non_icmp_traffic_has_zero_icmp_count():
    tracker = FlowTracker(icmp_window_seconds=5)
    result = tracker.update(_pkt(ts=1000.0, protocol="TCP"))
    assert result["icmp_count"] == 0


def test_icmp_count_respects_window():
    tracker = FlowTracker(icmp_window_seconds=5)
    tracker.update(_pkt(ts=1000.0, protocol="ICMP", dst_port=None))
    result = tracker.update(_pkt(ts=1010.0, protocol="ICMP", dst_port=None))  # 10s later, window is 5s
    assert result["icmp_count"] == 1
