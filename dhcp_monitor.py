"""
dhcp_monitor.py -- Rogue DHCP server detection

Tracks which IP(s) have been observed acting as a DHCP server (sending
DHCPOFFER or DHCPACK messages). Most home/small networks have exactly
one legitimate DHCP server (usually the router). If a second, different
IP suddenly starts responding as a DHCP server, that's the classic
signature of a rogue DHCP server -- often used for man-in-the-middle
attacks, since a malicious server can hand out a fake gateway or DNS
server to every new device that joins the network.

LIMITATION: legitimate networks with DHCP failover/redundancy (multiple
real DHCP servers by design) would trigger a one-time false positive
when the second legitimate server is first observed. Simple, honest
heuristic -- not aware of intentional multi-server setups.
"""


class DhcpServerTracker:
    def __init__(self):
        self._known_servers = set()

    def check(self, server_ip):
        """
        Returns True if this is a NEW server IP appearing after at least
        one other server IP was already established as the baseline.
        The very first server ever seen just establishes the baseline
        (not flagged) -- only a second, different server is suspicious.
        """
        if not server_ip:
            return False

        if server_ip in self._known_servers:
            return False

        is_rogue = len(self._known_servers) > 0
        self._known_servers.add(server_ip)
        return is_rogue
