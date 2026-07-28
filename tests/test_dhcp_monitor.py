import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dhcp_monitor import DhcpServerTracker


def test_first_server_establishes_baseline_not_flagged():
    tracker = DhcpServerTracker()
    is_rogue = tracker.check("192.168.1.1")
    assert not is_rogue


def test_same_server_repeated_not_flagged():
    tracker = DhcpServerTracker()
    tracker.check("192.168.1.1")
    is_rogue = tracker.check("192.168.1.1")
    assert not is_rogue


def test_second_different_server_flagged_as_rogue():
    tracker = DhcpServerTracker()
    tracker.check("192.168.1.1")
    is_rogue = tracker.check("10.0.0.99")
    assert is_rogue


def test_third_new_server_also_flagged():
    tracker = DhcpServerTracker()
    tracker.check("192.168.1.1")
    tracker.check("10.0.0.99")
    is_rogue = tracker.check("172.16.0.50")
    assert is_rogue


def test_previously_flagged_rogue_server_not_reflagged():
    tracker = DhcpServerTracker()
    tracker.check("192.168.1.1")
    tracker.check("10.0.0.99")  # flagged once
    is_rogue = tracker.check("10.0.0.99")  # seen again -- already known now
    assert not is_rogue


def test_missing_server_ip_does_not_crash():
    tracker = DhcpServerTracker()
    is_rogue = tracker.check(None)
    assert not is_rogue
