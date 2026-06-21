#!/usr/bin/env python3
"""Tiny Linux packet sniffer for IPv4/TCP packets."""

import errno
import socket
import struct
import sys


ETH_P_ALL = 0x0003
ETH_HEADER_LENGTH = 14
IP_HEADER_MIN_LENGTH = 20
TCP_HEADER_MIN_LENGTH = 20
IPPROTO_TCP = 6


def eth_addr(address: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in address)


def create_raw_socket() -> socket.socket:
    try:
        return socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
    except PermissionError as exc:
        print(f"Socket could not be created: {exc}", file=sys.stderr)
        print(
            "Raw packet capture needs root or CAP_NET_RAW. Try: "
            "sudo uv run sniff-it.py",
            file=sys.stderr,
        )
        sys.exit(1)
    except OSError as exc:
        if exc.errno == errno.EPERM:
            print(f"Socket could not be created: {exc}", file=sys.stderr)
            print(
                "Raw packet capture needs root or CAP_NET_RAW. Try: "
                "sudo uv run sniff-it.py",
                file=sys.stderr,
            )
            sys.exit(1)

        print(f"Socket could not be created: {exc}", file=sys.stderr)
        sys.exit(1)


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


def print_packet(packet: bytes, count: int) -> None:
    if len(packet) < ETH_HEADER_LENGTH + IP_HEADER_MIN_LENGTH:
        return

    destination_mac, source_mac, eth_protocol = parse_ethernet_header(packet)
    if eth_protocol != 0x0800:
        return

    print("############### Layer 2 Information ############")
    print(f"Destination MAC: {destination_mac}")
    print(f"Source MAC: {source_mac}")
    print(f"Protocol: {eth_protocol}")
    print("-------------------------------------------------\n")

    ip_offset = ETH_HEADER_LENGTH
    version, ihl, ip_header_length, ttl, protocol, source_ip, destination_ip = (
        parse_ip_header(packet, ip_offset)
    )

    print("########## IP Header Info ##############")
    print(f"Version: {version}")
    print(f"IP Header Length: {ihl}")
    print(f"TTL: {ttl}")
    print(f"Protocol: {protocol}")
    print(f"Source Address: {source_ip}")
    print(f"Destination Address: {destination_ip}")
    print("----------------------------------------\n")

    if protocol != IPPROTO_TCP:
        print(f"Packet {count} skipped: not TCP.\n")
        return

    tcp_offset = ip_offset + ip_header_length
    if len(packet) < tcp_offset + TCP_HEADER_MIN_LENGTH:
        return

    source_port, destination_port, sequence, ack, tcp_header_length = parse_tcp_header(
        packet, tcp_offset
    )

    print("########### TCP Header Info ############")
    print(f"Source Port: {source_port}")
    print(f"Destination Port: {destination_port}")
    print(f"Sequence Number: {sequence}")
    print(f"Acknowledgement: {ack}")
    print(f"TCP Header Length: {tcp_header_length // 4}")
    print("----------------------------------------\n")

    data_offset = tcp_offset + tcp_header_length
    data = packet[data_offset:]

    print("############## DATA ##################")
    print(f"Data: {data.hex()}")
    print("--------------------------------------\n")
    print(f"Packet {count} is done!\n")


def main() -> None:
    raw_socket = create_raw_socket()
    count = 0

    print("Getting packets...\n")
    while True:
        packet, _address = raw_socket.recvfrom(65565)
        count += 1
        print_packet(packet, count)


if __name__ == "__main__":
    main()
