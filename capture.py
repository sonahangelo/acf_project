"""
capture.py -- Packet Capture Module

Listens on a network interface and hands each captured packet to a
callback for feature extraction. Uses Scapy per the ACF spec.
"""

from scapy.all import sniff


def start_capture(interface, bpf_filter, on_packet, count=0):
    """
    Start sniffing packets.

    interface : str or None -- network interface to listen on (None = default)
    bpf_filter: str -- BPF filter string, e.g. "ip" or "tcp or udp"
    on_packet : callable -- function(pkt) called for every captured packet
    count     : int -- number of packets to capture (0 = infinite, run until Ctrl+C)
    """
    iface = interface.strip() if interface and interface.strip() else None
    print(f"[capture] Starting sniff on iface={iface or 'default'} "
          f"filter='{bpf_filter}' count={'infinite' if count == 0 else count}")
    sniff(iface=iface, filter=bpf_filter, prn=on_packet, store=False, count=count)


if __name__ == "__main__":
    # Quick standalone test: capture 5 packets and print summaries.
    start_capture(None, "ip", lambda pkt: print(pkt.summary()), count=5)
