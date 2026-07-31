import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threat_intel import ThreatIntel


def test_threat_intel_matches_exact_source_ip():
    intel = ThreatIntel(["203.0.113.10"])
    triggered, reason = intel.check_flow({"src_ip": "203.0.113.10", "dst_ip": "8.8.8.8"})
    assert triggered
    assert "threat_intel" in reason


def test_threat_intel_matches_source_cidr():
    intel = ThreatIntel(["198.51.100.0/24"])
    triggered, reason = intel.check_flow({"src_ip": "198.51.100.42", "dst_ip": "8.8.8.8"})
    assert triggered
    assert "198.51.100.0/24" in reason


def test_threat_intel_does_not_block_on_destination_match():
    intel = ThreatIntel(["198.51.100.0/24"])
    triggered, reason = intel.check_flow({"src_ip": "8.8.8.8", "dst_ip": "198.51.100.42"})
    assert not triggered
    assert reason is None


def test_threat_intel_ignores_invalid_indicators_and_ips():
    intel = ThreatIntel(["not-an-indicator"])
    triggered, reason = intel.check_flow({"src_ip": "not-an-ip", "dst_ip": "8.8.8.8"})
    assert not triggered
    assert reason is None
