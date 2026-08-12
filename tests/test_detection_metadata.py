import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detection_metadata import categorize_reason, mitre_for_category, severity_for_alert


def test_metadata_maps_brute_force_to_high_mitre():
    category = categorize_reason("brute_force (port=22)")
    assert category == "brute_force"
    assert severity_for_alert("brute_force (port=22)", -0.1, "BLOCK") == "high"
    assert mitre_for_category(category)["technique"] == "T1110"


def test_metadata_maps_threat_intel_to_critical():
    assert severity_for_alert("threat_intel (source_ip=1.2.3.4)", 0, "BLOCK") == "critical"
