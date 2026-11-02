import socket
import threading

import pytest
from scapy.all import ARP, Ether, IP, IPv6, UDP

from packet_forwarding import (
    decode_packet,
    encode_packet,
    make_auth_response,
    recv_exact,
)


def test_encode_and_decode_ipv4_packet():
    original = Ether() / IP(src="192.0.2.1", dst="192.0.2.2") / UDP(sport=1234, dport=53)

    framed = encode_packet(original)
    packet_type = framed[0]
    packet_size = int.from_bytes(framed[1:5], "big")
    decoded = decode_packet(packet_type, framed[5:5 + packet_size])

    assert decoded[IP].src == "192.0.2.1"
    assert decoded[UDP].dport == 53


def test_encode_and_decode_arp_packet():
    original = Ether() / ARP(psrc="192.0.2.1", pdst="192.0.2.2")

    framed = encode_packet(original)
    decoded = decode_packet(framed[0], framed[5:])

    assert decoded[ARP].psrc == "192.0.2.1"
    assert decoded[ARP].pdst == "192.0.2.2"


def test_encode_and_decode_ipv6_packet():
    original = Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(dport=53)

    framed = encode_packet(original)
    decoded = decode_packet(framed[0], framed[5:])

    assert decoded[IPv6].src == "2001:db8::1"
    assert decoded[UDP].dport == 53


def test_encode_ignores_non_ip_ethernet_packet():
    assert encode_packet(Ether()) is None


def test_decode_rejects_unknown_packet_type():
    with pytest.raises(ValueError, match="Unsupported forwarded packet type"):
        decode_packet(99, b"packet")


def test_recv_exact_reads_across_socket_chunks():
    receiver, sender = socket.socketpair()
    received = []

    def read_chunks():
        received.append(recv_exact(receiver, 6))

    reader = threading.Thread(target=read_chunks)
    reader.start()
    sender.sendall(b"abc")
    sender.sendall(b"def")
    reader.join(timeout=2)
    receiver.close()
    sender.close()

    assert received == [b"abcdef"]


def test_auth_response_is_deterministic_for_challenge():
    assert make_auth_response("test-token", b"challenge") == make_auth_response(
        "test-token", b"challenge"
    )
    assert make_auth_response("other-token", b"challenge") != make_auth_response(
        "test-token", b"challenge"
    )
