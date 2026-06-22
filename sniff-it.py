#!/usr/bin/env python3
"""Tiny Linux packet sniffer/parser for Ethernet IPv4/TCP packets."""

import argparse
import errno
import socket
import struct
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import TextIO


# Linux protocol value used with AF_PACKET to receive every Ethernet frame.
ETH_P_ALL = 0x0003

# Ethernet type value for IPv4 payloads.
ETHERTYPE_IPV4 = 0x0800

# Fixed Ethernet header size: destination MAC, source MAC, EtherType.
ETH_HEADER_LENGTH = 14

# Minimum IPv4 header size without options.
IP_HEADER_MIN_LENGTH = 20

# Minimum TCP header size without options.
TCP_HEADER_MIN_LENGTH = 20

# IPv4 "protocol" field value for TCP.
IPPROTO_TCP = 6

# Classic PCAP link-layer type for Ethernet captures.
PCAP_LINKTYPE_ETHERNET = 1

# Sanity limit to avoid trying to load malformed huge packet records.
MAX_PCAP_PACKET_SIZE = 10_000_000


def eth_addr(address: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in address)


def create_raw_socket() -> socket.socket:
    try:
        return socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
    except PermissionError as exc:
        print(f"Socket could not be created: {exc}", file=sys.stderr)
        print(
            "Live raw capture is blocked for normal users on Linux. "
            "Use --pcap capture.pcap for no-root analysis.",
            file=sys.stderr,
        )
        sys.exit(1)
    except OSError as exc:
        if exc.errno == errno.EPERM:
            print(f"Socket could not be created: {exc}", file=sys.stderr)
            print(
                "Live raw capture is blocked for normal users on Linux. "
                "Use --pcap capture.pcap for no-root analysis.",
                file=sys.stderr,
            )
            sys.exit(1)

        print(f"Socket could not be created: {exc}", file=sys.stderr)
        sys.exit(1)


def read_pcap(path: Path) -> Iterator[bytes]:
    with path.open("rb") as pcap_file:
        magic = pcap_file.read(4)
        if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            endian = ">"
        elif magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            endian = "<"
        else:
            raise ValueError("Unsupported PCAP file: invalid magic number")

        global_header = pcap_file.read(20)
        if len(global_header) != 20:
            raise ValueError("Unsupported PCAP file: truncated global header")

        _major, _minor, _zone, _sigfigs, _snaplen, linktype = struct.unpack(
            f"{endian}HHIIII", global_header
        )
        if linktype != PCAP_LINKTYPE_ETHERNET:
            raise ValueError(
                "Unsupported PCAP file: only Ethernet linktype is supported"
            )

        while True:
            packet_header = pcap_file.read(16)
            if not packet_header:
                return
            if len(packet_header) != 16:
                raise ValueError("Unsupported PCAP file: truncated packet header")

            _ts_sec, _ts_usec, captured_length, _original_length = struct.unpack(
                f"{endian}IIII", packet_header
            )
            if captured_length > MAX_PCAP_PACKET_SIZE:
                raise ValueError("Unsupported PCAP file: packet too large")

            packet = pcap_file.read(captured_length)
            if len(packet) != captured_length:
                raise ValueError("Unsupported PCAP file: truncated packet data")

            yield packet


def parse_ethernet_header(packet: bytes) -> tuple[str, str, int]:
    eth_header = packet[:ETH_HEADER_LENGTH]
    destination, source, protocol = struct.unpack("!6s6sH", eth_header)
    return eth_addr(destination), eth_addr(source), protocol


def parse_ip_header(packet: bytes, offset: int) -> tuple[int, int, int, int, str, str]:
    ip_header = packet[offset : offset + IP_HEADER_MIN_LENGTH]
    unpacked = struct.unpack("!BBHHHBBH4s4s", ip_header)

    version_ihl = unpacked[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    header_length = ihl * 4

    ttl = unpacked[5]
    protocol = unpacked[6]
    source = socket.inet_ntoa(unpacked[8])
    destination = socket.inet_ntoa(unpacked[9])

    return version, ihl, header_length, ttl, protocol, source, destination


def parse_tcp_header(packet: bytes, offset: int) -> tuple[int, int, int, int, int]:
    tcp_header = packet[offset : offset + TCP_HEADER_MIN_LENGTH]
    unpacked = struct.unpack("!HHLLBBHHH", tcp_header)

    source_port = unpacked[0]
    destination_port = unpacked[1]
    sequence = unpacked[2]
    ack = unpacked[3]
    tcp_header_length = (unpacked[4] >> 4) * 4

    return source_port, destination_port, sequence, ack, tcp_header_length


def format_packet(packet: bytes, count: int, show_payload: bool) -> list[str]:
    if len(packet) < ETH_HEADER_LENGTH + IP_HEADER_MIN_LENGTH:
        return [f"Packet {count} skipped: too short for Ethernet + IPv4."]

    destination_mac, source_mac, eth_protocol = parse_ethernet_header(packet)
    if eth_protocol != ETHERTYPE_IPV4:
        return [f"Packet {count} skipped: EtherType 0x{eth_protocol:04x}."]

    ip_offset = ETH_HEADER_LENGTH
    version, ihl, ip_header_length, ttl, protocol, source_ip, destination_ip = (
        parse_ip_header(packet, ip_offset)
    )
    if version != 4:
        return [f"Packet {count} skipped: not IPv4."]
    if ip_header_length < IP_HEADER_MIN_LENGTH:
        return [f"Packet {count} skipped: invalid IPv4 header length."]
    if len(packet) < ip_offset + ip_header_length:
        return [f"Packet {count} skipped: truncated IPv4 header."]

    lines = [
        f"Packet {count}",
        "############### Layer 2 Information ############",
        f"Destination MAC: {destination_mac}",
        f"Source MAC: {source_mac}",
        f"EtherType: 0x{eth_protocol:04x}",
        "########## IP Header Info ##############",
        f"Version: {version}",
        f"IP Header Length: {ihl}",
        f"TTL: {ttl}",
        f"Protocol: {protocol}",
        f"Source Address: {source_ip}",
        f"Destination Address: {destination_ip}",
    ]

    if protocol != IPPROTO_TCP:
        lines.append("Skipped transport parser: not TCP.")
        return lines

    tcp_offset = ip_offset + ip_header_length
    if len(packet) < tcp_offset + TCP_HEADER_MIN_LENGTH:
        lines.append("Skipped TCP parser: truncated TCP header.")
        return lines

    source_port, destination_port, sequence, ack, tcp_header_length = parse_tcp_header(
        packet, tcp_offset
    )
    if tcp_header_length < TCP_HEADER_MIN_LENGTH:
        lines.append("Skipped TCP payload: invalid TCP header length.")
        return lines
    if len(packet) < tcp_offset + tcp_header_length:
        lines.append("Skipped TCP payload: truncated TCP header.")
        return lines

    lines.extend(
        [
            "########### TCP Header Info ############",
            f"Source Port: {source_port}",
            f"Destination Port: {destination_port}",
            f"Sequence Number: {sequence}",
            f"Acknowledgement: {ack}",
            f"TCP Header Length: {tcp_header_length // 4}",
        ]
    )

    data = packet[tcp_offset + tcp_header_length :]
    lines.append(f"Payload Bytes: {len(data)}")
    if show_payload:
        lines.append(f"Payload Hex: {data.hex()}")

    return lines


def emit(lines: list[str], log_file: TextIO | None) -> None:
    if not lines:
        return

    text = "\n".join(lines)
    print(text)
    print()

    if log_file is not None:
        log_file.write(text)
        log_file.write("\n\n")


def live_packets() -> Iterator[bytes]:
    raw_socket = create_raw_socket()
    while True:
        packet, _address = raw_socket.recvfrom(65565)
        yield packet


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Parse Ethernet/IPv4/TCP packets. Use --pcap for no-root analysis."
        )
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--pcap",
        type=Path,
        help="Read packets from a PCAP file without root privileges.",
    )
    mode.add_argument(
        "--live",
        action="store_true",
        help="Capture live packets with raw socket. Requires Linux privilege.",
    )
    parser.add_argument(
        "--max-packets",
        type=int,
        default=10,
        help="Stop after N packets. Use 0 for no limit. Default: 10.",
    )
    parser.add_argument(
        "--show-payload",
        action="store_true",
        help="Print TCP payload bytes in hex. Hidden by default.",
    )
    parser.add_argument(
        "--log",
        type=Path,
        help="Write output to a log file.",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    packet_limit = None if args.max_packets == 0 else args.max_packets
    if args.max_packets < 0:
        raise SystemExit("--max-packets must be >= 0")

    packets = live_packets() if args.live else read_pcap(args.pcap)
    log_file = args.log.open("a", encoding="utf-8") if args.log else None

    try:
        for count, packet in enumerate(packets, start=1):
            emit(format_packet(packet, count, args.show_payload), log_file)
            if packet_limit is not None and count >= packet_limit:
                break
    except KeyboardInterrupt:
        print("\nStopped.")
    except (OSError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
    finally:
        if log_file is not None:
            log_file.close()


if __name__ == "__main__":
    main()
