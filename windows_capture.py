"""Forward Windows packets to the ACF engine running in WSL."""

import argparse
import os
import socket

from scapy.all import get_if_list, sniff

from packet_forwarding import (
    AUTH_ACCEPTED,
    AUTH_SIZE,
    encode_packet,
    make_auth_response,
    recv_exact,
)


def main():
    parser = argparse.ArgumentParser(
        description="Capture Windows interfaces with Npcap and forward packets to ACF in WSL."
    )
    parser.add_argument(
        "--interface",
        action="append",
        help="Scapy interface name or GUID; repeat to select multiple interfaces (default: all)",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("ACF_WINDOWS_CAPTURE_HOST", "127.0.0.1"),
        help="WSL capture listener host (default: ACF_WINDOWS_CAPTURE_HOST or 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("ACF_WINDOWS_CAPTURE_PORT", "5051")),
        help="WSL capture listener port (default: ACF_WINDOWS_CAPTURE_PORT or 5051)",
    )
    parser.add_argument(
        "--filter",
        default="",
        help="Optional BPF filter applied to Windows capture",
    )
    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")

    token = os.environ.get("ACF_WINDOWS_CAPTURE_TOKEN")
    if not token or len(token) < 32:
        parser.error("set ACF_WINDOWS_CAPTURE_TOKEN to the shared secret (at least 32 characters)")

    interfaces = args.interface or get_if_list()
    if not interfaces:
        parser.error("Scapy did not find any Windows capture interfaces")

    with socket.create_connection((args.host, args.port), timeout=10) as connection:
        challenge = recv_exact(connection, AUTH_SIZE)
        connection.sendall(make_auth_response(token, challenge))
        if recv_exact(connection, 1) != AUTH_ACCEPTED:
            parser.error("WSL rejected the capture token; verify both sides use the same token")
        connection.settimeout(None)

        print(
            f"[windows-capture] Forwarding interfaces={','.join(interfaces)} "
            f"to {args.host}:{args.port}"
        )

        def forward_packet(packet):
            framed_packet = encode_packet(packet)
            if framed_packet is not None:
                connection.sendall(framed_packet)

        sniff(
            iface=interfaces,
            filter=args.filter,
            prn=forward_packet,
            store=False,
        )


if __name__ == "__main__":
    main()
