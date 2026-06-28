"""Live packet capture helpers."""

from __future__ import annotations

import socket
import sys
from collections.abc import Iterator

from .constants import ETH_P_ALL


def create_raw_socket() -> socket.socket:
    try:
        return socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
    except PermissionError as exc:
        print(f"Não foi possível criar o socket: {exc}", file=sys.stderr)
        print(
            "Captura ao vivo exige privilégio de root (ou CAP_NET_RAW). "
            "Use --pcap captura.pcap para analisar sem root.",
            file=sys.stderr,
        )
        sys.exit(1)


def live_packets() -> Iterator[bytes]:
    raw_socket = create_raw_socket()
    while True:
        packet, _address = raw_socket.recvfrom(65565)
        yield packet

