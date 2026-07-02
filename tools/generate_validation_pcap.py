#!/usr/bin/env python3
"""Generate a tiny PCAP to validate Sniff-It protocol dispatchers."""

from __future__ import annotations

import socket
import struct
from pathlib import Path

# Ethernet frame type identifiers used in generated frames.
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_ARP = 0x0806

# IP protocol and IPv6 next-header identifiers used in generated packets.
IPPROTO_ICMP = 1
IPPROTO_UDP = 17
IPPROTO_ICMPV6 = 58


def mac(value: str) -> bytes:
    """Convert colon-separated MAC text to bytes."""
    return bytes.fromhex(value.replace(":", ""))


def ipv4(value: str) -> bytes:
    """Convert IPv4 text to packed network bytes."""
    return socket.inet_aton(value)


def ipv6(value: str) -> bytes:
    """Convert IPv6 text to packed network bytes."""
    return socket.inet_pton(socket.AF_INET6, value)


def ethernet(dst: str, src: str, eth_type: int, payload: bytes) -> bytes:
    """Build one Ethernet frame around payload bytes."""
    return mac(dst) + mac(src) + struct.pack("!H", eth_type) + payload


def ipv4_packet(protocol: int, src: str, dst: str, payload: bytes) -> bytes:
    """Build minimal IPv4 packet with checksum left zero for parser tests."""
    version_ihl = 0x45
    total_length = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        0,
        total_length,
        1,
        0,
        64,
        protocol,
        0,
        ipv4(src),
        ipv4(dst),
    )
    return header + payload


def ipv6_packet(next_header: int, src: str, dst: str, payload: bytes) -> bytes:
    """Build minimal IPv6 packet with one base header."""
    first_word = 6 << 28
    header = struct.pack(
        "!IHBB16s16s",
        first_word,
        len(payload),
        next_header,
        64,
        ipv6(src),
        ipv6(dst),
    )
    return header + payload


def udp_packet(src_port: int, dst_port: int, payload: bytes = b"test") -> bytes:
    """Build UDP segment with checksum left zero for parser tests."""
    length = 8 + len(payload)
    return struct.pack("!HHHH", src_port, dst_port, length, 0) + payload


def icmp_packet(icmp_type: int, code: int = 0) -> bytes:
    """Build ICMP or ICMPv6 header with checksum left zero."""
    return struct.pack("!BBH", icmp_type, code, 0)


def arp_packet(
    opcode: int,
    sender_mac: str,
    sender_ip: str,
    target_mac: str,
    target_ip: str,
) -> bytes:
    """Build Ethernet/IPv4 ARP packet payload."""
    return struct.pack(
        "!HHBBH6s4s6s4s",
        1,
        ETHERTYPE_IPV4,
        6,
        4,
        opcode,
        mac(sender_mac),
        ipv4(sender_ip),
        mac(target_mac),
        ipv4(target_ip),
    )


def write_pcap(path: Path, frames: list[bytes]) -> None:
    """Write frames to little-endian Ethernet PCAP fixture file."""
    with path.open("wb") as pcap:
        pcap.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, frame in enumerate(frames, start=1):
            pcap.write(struct.pack("<IIII", index, 0, len(frame), len(frame)))
            pcap.write(frame)


def main() -> None:
    """Regenerate validation PCAP fixture with IPv4, IPv6, UDP, ICMP, and ARP."""
    frames = [
        ethernet(
            "66:77:88:99:aa:bb",
            "00:11:22:33:44:55",
            ETHERTYPE_IPV4,
            ipv4_packet(IPPROTO_ICMP, "192.0.2.10", "192.0.2.1", icmp_packet(8)),
        ),
        ethernet(
            "66:77:88:99:aa:bb",
            "00:11:22:33:44:55",
            ETHERTYPE_IPV6,
            ipv6_packet(IPPROTO_ICMPV6, "2001:db8::10", "2001:db8::1", icmp_packet(128)),
        ),
        ethernet(
            "66:77:88:99:aa:bb",
            "00:11:22:33:44:55",
            ETHERTYPE_IPV6,
            ipv6_packet(
                IPPROTO_UDP,
                "2001:db8::10",
                "2001:db8::53",
                udp_packet(5353, 53),
            ),
        ),
        ethernet(
            "ff:ff:ff:ff:ff:ff",
            "00:11:22:33:44:55",
            ETHERTYPE_ARP,
            arp_packet(2, "00:11:22:33:44:55", "192.0.2.1", "66:77:88:99:aa:bb", "192.0.2.10"),
        ),
        ethernet(
            "ff:ff:ff:ff:ff:ff",
            "aa:bb:cc:dd:ee:ff",
            ETHERTYPE_ARP,
            arp_packet(2, "aa:bb:cc:dd:ee:ff", "192.0.2.1", "66:77:88:99:aa:bb", "192.0.2.10"),
        ),
        ethernet(
            "ff:ff:ff:ff:ff:ff",
            "aa:bb:cc:dd:ee:ff",
            ETHERTYPE_ARP,
            arp_packet(1, "aa:bb:cc:dd:ee:ff", "192.0.2.20", "00:00:00:00:00:00", "192.0.2.20"),
        ),
        ethernet(
            "ff:ff:ff:ff:ff:ff",
            "aa:bb:cc:dd:ee:ff",
            ETHERTYPE_ARP,
            arp_packet(1, "aa:bb:cc:dd:ee:ff", "192.0.2.20", "00:00:00:00:00:00", "192.0.2.20"),
        ),
        ethernet(
            "ff:ff:ff:ff:ff:ff",
            "aa:bb:cc:dd:ee:ff",
            ETHERTYPE_ARP,
            arp_packet(1, "aa:bb:cc:dd:ee:ff", "192.0.2.20", "00:00:00:00:00:00", "192.0.2.20"),
        ),
    ]
    write_pcap(Path("validation-ipv6-icmp-arp.pcap"), frames)


if __name__ == "__main__":
    main()
