"""
threat_intel.py -- Local threat intelligence matcher.

The feed format is intentionally simple and auditable for classroom and
professional use: one indicator per line, with optional comments beginning
with #. Supported indicators are individual IP addresses and CIDR networks.
"""

from ipaddress import ip_address, ip_network


class ThreatIntel:
    def __init__(self, indicators=None):
        self.addresses = set()
        self.networks = []
        for indicator in indicators or []:
            self.add(indicator)

    @classmethod
    def from_config(cls, cfg):
        indicators = list(cfg.get("threat_intel_indicators", []) or [])
        for path in cfg.get("threat_intel_files", []) or []:
            indicators.extend(_load_indicator_file(path))
        return cls(indicators)

    def add(self, indicator):
        value = str(indicator).strip()
        if not value or value.startswith("#"):
            return
        value = value.split("#", 1)[0].strip()
        if not value:
            return
        try:
            if "/" in value:
                self.networks.append(ip_network(value, strict=False))
            else:
                self.addresses.add(ip_address(value))
        except ValueError:
            print(f"[threat_intel] Ignoring invalid indicator: {value}")

    def match_ip(self, ip):
        try:
            candidate = ip_address(ip)
        except ValueError:
            return None
        if candidate in self.addresses:
            return str(candidate)
        for network in self.networks:
            if candidate.version == network.version and candidate in network:
                return str(network)
        return None

    def check_flow(self, feats):
        src_ip = feats.get("src_ip")
        match = self.match_ip(src_ip) if src_ip else None
        if match:
            return True, f"threat_intel (source_ip={src_ip} matched indicator {match})"
        return False, None


def _load_indicator_file(path):
    try:
        with open(path, "r") as f:
            return [line.strip() for line in f]
    except FileNotFoundError:
        print(f"[threat_intel] Indicator file not found: {path}")
        return []
