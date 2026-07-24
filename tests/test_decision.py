import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from decision import decide, MIN_FLOW_PACKETS_FOR_DECISION


def test_whitelisted_ip_always_allowed_even_if_anomalous():
    action = decide(label=-1, score=-0.5, src_ip="127.0.0.1", whitelist={"127.0.0.1"})
    assert action == "ALLOW"


def test_normal_label_is_allowed():
    action = decide(label=1, score=0.1, src_ip="10.0.0.5", whitelist=set())
    assert action == "ALLOW"


def test_anomalous_label_with_enough_flow_data_is_blocked():
    action = decide(label=-1, score=-0.2, src_ip="10.0.0.5", whitelist=set(),
                     flow_packet_count=MIN_FLOW_PACKETS_FOR_DECISION)
    assert action == "BLOCK"


def test_anomalous_label_on_first_packet_of_flow_is_allowed():
    # Regression test: judging a brand-new flow's first packet produced
    # false positives (rate features were meaningless with only 1 packet).
    action = decide(label=-1, score=-0.2, src_ip="10.0.0.5", whitelist=set(),
                     flow_packet_count=1)
    assert action == "ALLOW"


def test_missing_flow_packet_count_still_blocks_on_anomaly():
    # Backwards-compatible: if flow_packet_count isn't passed, don't crash,
    # and don't silently suppress detection.
    action = decide(label=-1, score=-0.2, src_ip="10.0.0.5", whitelist=set())
    assert action == "BLOCK"
