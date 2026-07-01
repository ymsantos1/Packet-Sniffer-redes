"""PCAP reader and link-layer normalization."""

from __future__ import annotations

import struct
from collections.abc import Iterator
from pathlib import Path

from .constants import (
    MAX_PCAP_PACKET_SIZE,
    PCAP_LINKTYPE_ETHERNET,
    PCAP_LINKTYPE_LINUX_SLL,
    PCAP_LINKTYPE_LINUX_SLL2,
    SLL2_HEADER_LENGTH,
    SLL_HEADER_LENGTH,
)


def read_pcap(path: Path) -> Iterator[bytes]:
    """Yield normalized Ethernet frames from a supported PCAP file."""
    with path.open("rb") as pcap_file:
        magic = pcap_file.read(4)
        if magic == b"\xd4\xc3\xb2\xa1":
            endian = "<"
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian = ">"
        else:
            raise ValueError("Arquivo PCAP não suportado: magic number inválido.")

        global_header = pcap_file.read(20)
        if len(global_header) != 20:
            raise ValueError("Arquivo PCAP não suportado: cabeçalho global truncado.")

        *_unused, linktype = struct.unpack(f"{endian}HHIIII", global_header)
        if linktype not in {
            PCAP_LINKTYPE_ETHERNET,
            PCAP_LINKTYPE_LINUX_SLL,
            PCAP_LINKTYPE_LINUX_SLL2,
        }:
            raise ValueError(f"Arquivo PCAP não suportado: linktype {linktype}.")

        while True:
            packet_header = pcap_file.read(16)
            if not packet_header:
                return
            if len(packet_header) != 16:
                raise ValueError("Arquivo PCAP não suportado: cabeçalho de pacote truncado.")

            _ts_sec, _ts_usec, captured_length, _original_length = struct.unpack(
                f"{endian}IIII", packet_header
            )
            if captured_length > MAX_PCAP_PACKET_SIZE:
                raise ValueError("Arquivo PCAP não suportado: pacote grande demais.")

            packet = pcap_file.read(captured_length)
            if len(packet) != captured_length:
                raise ValueError("Arquivo PCAP não suportado: pacote truncado.")

            yield normalize_pcap_packet(packet, linktype)


def normalize_pcap_packet(packet: bytes, linktype: int) -> bytes:
    """Convert supported PCAP link-layer packets to Ethernet frames."""
    if linktype == PCAP_LINKTYPE_ETHERNET:
        return packet
    if linktype == PCAP_LINKTYPE_LINUX_SLL:
        return linux_sll_to_ethernet(packet)
    if linktype == PCAP_LINKTYPE_LINUX_SLL2:
        return linux_sll2_to_ethernet(packet)
    raise ValueError(f"Arquivo PCAP não suportado: linktype {linktype}.")


def linux_sll_to_ethernet(packet: bytes) -> bytes:
    """Convert Linux SLL cooked capture bytes to pseudo-Ethernet."""
    if len(packet) < SLL_HEADER_LENGTH:
        raise ValueError("Arquivo PCAP não suportado: cabeçalho Linux SLL truncado.")

    _packet_type, _hardware_type, address_length = struct.unpack("!HHH", packet[:6])
    address = packet[6:14]
    (eth_type,) = struct.unpack("!H", packet[14:SLL_HEADER_LENGTH])
    return pseudo_ethernet_frame(packet[SLL_HEADER_LENGTH:], eth_type, address, address_length)


def linux_sll2_to_ethernet(packet: bytes) -> bytes:
    """Convert Linux SLL2 cooked capture bytes to pseudo-Ethernet."""
    if len(packet) < SLL2_HEADER_LENGTH:
        raise ValueError("Arquivo PCAP não suportado: cabeçalho Linux SLL2 truncado.")

    eth_type, _reserved, _interface_index, _hardware_type, _packet_type, address_length = (
        struct.unpack("!HHIHBB", packet[:12])
    )
    address = packet[12:20]
    return pseudo_ethernet_frame(packet[SLL2_HEADER_LENGTH:], eth_type, address, address_length)


def pseudo_ethernet_frame(
    payload: bytes, eth_type: int, address: bytes, address_length: int
) -> bytes:
    """Build pseudo-Ethernet frame from cooked capture metadata."""
    destination = b"\x00" * 6
    source = address[: min(address_length, 6)].ljust(6, b"\x00")
    return destination + source + struct.pack("!H", eth_type) + payload
