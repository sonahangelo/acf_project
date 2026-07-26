import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ttl_monitor import TtlTracker


def test_first_sighting_has_no_baseline():
    tracker = TtlTracker()
    baseline, diff = tracker.check("1.2.3.4", 64)
    assert baseline is None
    assert diff == 0


def test_same_ttl_repeated_has_zero_diff():
    tracker = TtlTracker()
    tracker.check("1.2.3.4", 64)
    baseline, diff = tracker.check("1.2.3.4", 64)
    assert baseline == 64
    assert diff == 0


def test_different_ttl_reports_correct_diff():
    tracker = TtlTracker()
    tracker.check("1.2.3.4", 64)
    baseline, diff = tracker.check("1.2.3.4", 128)
    assert baseline == 64
    assert diff == 64


def test_small_ttl_variation_reports_small_diff():
    tracker = TtlTracker()
    tracker.check("1.2.3.4", 64)
    baseline, diff = tracker.check("1.2.3.4", 62)
    assert diff == 2


def test_different_ips_have_independent_baselines():
    tracker = TtlTracker()
    tracker.check("1.2.3.4", 64)
    baseline, diff = tracker.check("5.6.7.8", 128)
    assert baseline is None  # first sighting for THIS ip


def test_missing_ip_or_ttl_does_not_crash():
    tracker = TtlTracker()
    baseline, diff = tracker.check(None, 64)
    assert baseline is None
    baseline, diff = tracker.check("1.2.3.4", None)
    assert baseline is None
