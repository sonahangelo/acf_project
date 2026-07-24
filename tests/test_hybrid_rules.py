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
    cfg = {}
    triggered, reason = check_hybrid_rules(feats, model, [0]*12, cfg)
    assert triggered
    assert "port_scan" in reason


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
