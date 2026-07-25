import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dns_monitor import shannon_entropy, DnsTunnelTracker


def test_entropy_of_empty_string_is_zero():
    assert shannon_entropy("") == 0.0


def test_entropy_of_repeated_char_is_zero():
    assert shannon_entropy("aaaaaaaa") == 0.0


def test_entropy_of_random_looking_string_is_high():
    # Base32/64-like encoded data should have high entropy
    entropy = shannon_entropy("a8f3k2x9q7z1m4n6")
    assert entropy > 3.5


def test_entropy_of_common_word_is_lower():
    entropy = shannon_entropy("www")
    assert entropy < 2.0


def test_tracker_counts_distinct_subdomains():
    tracker = DnsTunnelTracker(window_seconds=10)
    tracker.record("1.2.3.4", "evil.com", "aaa111", 1000.0)
    tracker.record("1.2.3.4", "evil.com", "bbb222", 1000.5)
    count = tracker.record("1.2.3.4", "evil.com", "ccc333", 1001.0)
    assert count == 3


def test_tracker_does_not_double_count_same_subdomain():
    tracker = DnsTunnelTracker(window_seconds=10)
    tracker.record("1.2.3.4", "evil.com", "aaa111", 1000.0)
    count = tracker.record("1.2.3.4", "evil.com", "aaa111", 1000.5)
    assert count == 1


def test_tracker_separates_by_base_domain():
    tracker = DnsTunnelTracker(window_seconds=10)
    tracker.record("1.2.3.4", "evil.com", "aaa", 1000.0)
    count = tracker.record("1.2.3.4", "google.com", "bbb", 1000.5)
    assert count == 1  # separate counter per (src_ip, base_domain)


def test_tracker_respects_window():
    tracker = DnsTunnelTracker(window_seconds=5)
    tracker.record("1.2.3.4", "evil.com", "aaa", 1000.0)
    count = tracker.record("1.2.3.4", "evil.com", "bbb", 1010.0)  # 10s later, window is 5s
    assert count == 1  # old entry expired
