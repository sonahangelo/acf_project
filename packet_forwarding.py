"""Wire protocol shared by the Windows packet collector and ACF engine."""

import hashlib
import hmac
import struct

from scapy.all import ARP, IP, IPv6, raw

AUTH_SIZE = 32
AUTH_ACCEPTED = b"\x01"
AUTH_REJECTED = b"\x00"
HEADER = struct.Struct("!BI")
MAX_PACKET_SIZE = 65535

_PACKET_TYPES = {
    1: IP,
    2: IPv6,
    3: ARP,
}


def make_auth_response(token, challenge):
    return hmac.new(token.encode("utf-8"), challenge, hashlib.sha256).digest()


def encode_packet(packet):
    if packet.haslayer(ARP):
        packet_type = 3
        payload = raw(packet[ARP])
    elif packet.haslayer(IP):
        packet_type = 1
        payload = raw(packet[IP])
    elif packet.haslayer(IPv6):
        packet_type = 2
        payload = raw(packet[IPv6])
    else:
        return None

    if not payload or len(payload) > MAX_PACKET_SIZE:
        return None
    return HEADER.pack(packet_type, len(payload)) + payload


def decode_packet(packet_type, payload):
    packet_class = _PACKET_TYPES.get(packet_type)
    if packet_class is None:
        raise ValueError(f"Unsupported forwarded packet type: {packet_type}")
    if not payload or len(payload) > MAX_PACKET_SIZE:
        raise ValueError(f"Invalid forwarded packet length: {len(payload)}")
    return packet_class(payload)


def recv_exact(connection, size):
    chunks = bytearray()
    while len(chunks) < size:
        chunk = connection.recv(size - len(chunks))
        if not chunk:
            raise EOFError("Forwarded capture connection closed")
        chunks.extend(chunk)
    return bytes(chunks)
