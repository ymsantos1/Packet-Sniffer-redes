"""Binary protocol parsers."""

from __future__ import annotations

import socket
import struct

from .constants import (
    ARP_HEADER_LENGTH,
    ETH_HEADER_LENGTH,
    ICMP_HEADER_LENGTH,
    IPV4_HEADER_MIN_LENGTH,
    IPV6_HEADER_LENGTH,
    TCP_HEADER_MIN_LENGTH,
    UDP_HEADER_LENGTH,
)


def eth_addr(address: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in address)


def parse_ethernet_header(packet: bytes) -> tuple[str, str, int]:
    destination, source, eth_type = struct.unpack("!6s6sH", packet[:ETH_HEADER_LENGTH])
    return eth_addr(destination), eth_addr(source), eth_type


def parse_ipv4_header(packet: bytes, offset: int) -> tuple[int, int, int, int, int, str, str]:
    header = packet[offset : offset + IPV4_HEADER_MIN_LENGTH]
    unpacked = struct.unpack("!BBHHHBBH4s4s", header)

    version_ihl = unpacked[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    header_length = ihl * 4

    ttl = unpacked[5]
    protocol = unpacked[6]
    source = socket.inet_ntoa(unpacked[8])
    destination = socket.inet_ntoa(unpacked[9])

    return version, ihl, header_length, ttl, protocol, source, destination


def parse_ipv6_header(packet: bytes, offset: int) -> tuple[int, int, int, int, int, int, str, str]:
    header = packet[offset : offset + IPV6_HEADER_LENGTH]
    first_word, payload_length, next_header, hop_limit, source, destination = struct.unpack(
        "!IHBB16s16s", header
    )

    version = first_word >> 28
    traffic_class = (first_word >> 20) & 0xFF
    flow_label = first_word & 0xFFFFF

    return (
        version,
        traffic_class,
        flow_label,
        payload_length,
        next_header,
        hop_limit,
        socket.inet_ntop(socket.AF_INET6, source),
        socket.inet_ntop(socket.AF_INET6, destination),
    )


def parse_tcp_header(packet: bytes, offset: int) -> tuple[int, int, int, int, int]:
    header = packet[offset : offset + TCP_HEADER_MIN_LENGTH]
    unpacked = struct.unpack("!HHLLBBHHH", header)

    source_port = unpacked[0]
    destination_port = unpacked[1]
    sequence = unpacked[2]
    ack = unpacked[3]
    header_length = (unpacked[4] >> 4) * 4

    return source_port, destination_port, sequence, ack, header_length


def parse_udp_header(packet: bytes, offset: int) -> tuple[int, int, int, int]:
    header = packet[offset : offset + UDP_HEADER_LENGTH]
    return struct.unpack("!HHHH", header)


def parse_icmp_header(packet: bytes, offset: int) -> tuple[int, int, int]:
    header = packet[offset : offset + ICMP_HEADER_LENGTH]
    return struct.unpack("!BBH", header)


def parse_arp_header(packet: bytes, offset: int) -> tuple[int, int, int, int, int, str, str, str, str]:
    header = packet[offset : offset + ARP_HEADER_LENGTH]
    hardware_type, protocol_type, hlen, plen, opcode, sender_mac, sender_ip, target_mac, target_ip = (
        struct.unpack("!HHBBH6s4s6s4s", header)
    )
    return (
        hardware_type,
        protocol_type,
        hlen,
        plen,
        opcode,
        eth_addr(sender_mac),
        socket.inet_ntoa(sender_ip),
        eth_addr(target_mac),
        socket.inet_ntoa(target_ip),
    )

