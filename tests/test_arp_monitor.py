import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from arp_monitor import ArpBindingTracker


def test_first_binding_is_not_a_conflict():
    tracker = ArpBindingTracker()
    is_conflict, previous = tracker.check("192.168.1.1", "aa:bb:cc:dd:ee:ff")
    assert not is_conflict
    assert previous is None


def test_same_mac_repeated_is_not_a_conflict():
    tracker = ArpBindingTracker()
    tracker.check("192.168.1.1", "aa:bb:cc:dd:ee:ff")
    is_conflict, previous = tracker.check("192.168.1.1", "aa:bb:cc:dd:ee:ff")
    assert not is_conflict


def test_different_mac_for_known_ip_is_a_conflict():
    tracker = ArpBindingTracker()
    tracker.check("192.168.1.1", "aa:bb:cc:dd:ee:ff")
    is_conflict, previous = tracker.check("192.168.1.1", "11:22:33:44:55:66")
    assert is_conflict
    assert previous == "aa:bb:cc:dd:ee:ff"


def test_different_ips_do_not_conflict_with_each_other():
    tracker = ArpBindingTracker()
    tracker.check("192.168.1.1", "aa:bb:cc:dd:ee:ff")
    is_conflict, previous = tracker.check("192.168.1.2", "11:22:33:44:55:66")
    assert not is_conflict


def test_missing_ip_or_mac_does_not_crash():
    tracker = ArpBindingTracker()
    is_conflict, previous = tracker.check(None, "aa:bb:cc:dd:ee:ff")
    assert not is_conflict
    is_conflict, previous = tracker.check("192.168.1.1", None)
    assert not is_conflict
