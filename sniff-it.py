#!/usr/bin/env python3
"""Sniff-It: analisador de pacotes Ethernet/IPv4/IPv6/ARP."""

import argparse
import socket
import struct
import sys
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import TextIO

import arp_detector

# Protocolo usado com AF_PACKET para receber todos os quadros Ethernet.
ETH_P_ALL = 0x0003

# EtherTypes tratados.
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_ARP = 0x0806

# Protocolos IPv4 / Next Header IPv6 tratados.
IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_ICMPV6 = 58

ETH_HEADER_LENGTH = 14
IPV4_HEADER_MIN_LENGTH = 20
IPV6_HEADER_LENGTH = 40
TCP_HEADER_MIN_LENGTH = 20
UDP_HEADER_LENGTH = 8
ICMP_HEADER_LENGTH = 4
ARP_HEADER_LENGTH = 28

PCAP_LINKTYPE_ETHERNET = 1
MAX_PCAP_PACKET_SIZE = 10_000_000


def eth_addr(address: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in address)


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


def read_pcap(path: Path) -> Iterator[bytes]:
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
        if linktype != PCAP_LINKTYPE_ETHERNET:
            raise ValueError("Arquivo PCAP não suportado: linktype diferente de Ethernet.")

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

            yield packet


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


def format_tcp_lines(packet: bytes, offset: int) -> list[str]:
    if len(packet) < offset + TCP_HEADER_MIN_LENGTH:
        return ["Cabeçalho TCP truncado."]

    source_port, destination_port, sequence, ack, header_length = parse_tcp_header(packet, offset)
    lines = [
        "########## TCP ##########",
        f"Porta Origem: {source_port}",
        f"Porta Destino: {destination_port}",
        f"Número de Sequência: {sequence}",
        f"Número de Confirmação (ACK): {ack}",
        f"Tamanho do Cabeçalho TCP: {header_length} bytes",
    ]
    if header_length < TCP_HEADER_MIN_LENGTH or len(packet) < offset + header_length:
        lines.append("Cabeçalho TCP inválido ou truncado.")
    return lines


def format_udp_lines(packet: bytes, offset: int) -> list[str]:
    if len(packet) < offset + UDP_HEADER_LENGTH:
        return ["Cabeçalho UDP truncado."]

    source_port, destination_port, length, checksum = parse_udp_header(packet, offset)
    return [
        "########## UDP ##########",
        f"Porta Origem: {source_port}",
        f"Porta Destino: {destination_port}",
        f"Tamanho: {length}",
        f"Checksum: 0x{checksum:04x}",
    ]


def format_icmp_lines(packet: bytes, offset: int, label: str) -> list[str]:
    if len(packet) < offset + ICMP_HEADER_LENGTH:
        return [f"Cabeçalho {label} truncado."]

    icmp_type, code, checksum = parse_icmp_header(packet, offset)
    return [
        f"########## {label} ##########",
        f"Tipo: {icmp_type}",
        f"Código: {code}",
        f"Checksum: 0x{checksum:04x}",
    ]


def format_ipv4_lines(packet: bytes, offset: int) -> list[str]:
    if len(packet) < offset + IPV4_HEADER_MIN_LENGTH:
        return ["Pacote IPv4 truncado."]

    version, ihl, header_length, ttl, protocol, source_ip, destination_ip = parse_ipv4_header(
        packet, offset
    )
    lines = [
        "############### IPv4 ###############",
        f"Versão: {version}",
        f"Tamanho do Cabeçalho: {ihl} ({header_length} bytes)",
        f"TTL: {ttl}",
        f"Protocolo: {protocol}",
        f"IP Origem: {source_ip}",
        f"IP Destino: {destination_ip}",
    ]
    if version != 4:
        lines.append("Versão IPv4 inesperada.")
        return lines
    if header_length < IPV4_HEADER_MIN_LENGTH or len(packet) < offset + header_length:
        lines.append("Cabeçalho IPv4 inválido ou truncado.")
        return lines

    transport_offset = offset + header_length
    if protocol == IPPROTO_TCP:
        lines.extend(format_tcp_lines(packet, transport_offset))
    elif protocol == IPPROTO_UDP:
        lines.extend(format_udp_lines(packet, transport_offset))
    elif protocol == IPPROTO_ICMP:
        lines.extend(format_icmp_lines(packet, transport_offset, "ICMP"))
    else:
        lines.append(f"Protocolo IPv4 {protocol} não tratado.")
    return lines


def format_ipv6_lines(packet: bytes, offset: int) -> list[str]:
    if len(packet) < offset + IPV6_HEADER_LENGTH:
        return ["Pacote IPv6 truncado."]

    version, traffic_class, flow_label, payload_length, next_header, hop_limit, source_ip, destination_ip = (
        parse_ipv6_header(packet, offset)
    )
    lines = [
        "############### IPv6 ###############",
        f"Versão: {version}",
        f"Traffic Class: {traffic_class}",
        f"Flow Label: {flow_label}",
        f"Payload Length: {payload_length}",
        f"Next Header: {next_header}",
        f"Hop Limit: {hop_limit}",
        f"IP Origem: {source_ip}",
        f"IP Destino: {destination_ip}",
    ]
    if version != 6:
        lines.append("Versão IPv6 inesperada.")
        return lines

    transport_offset = offset + IPV6_HEADER_LENGTH
    if next_header == IPPROTO_TCP:
        lines.extend(format_tcp_lines(packet, transport_offset))
    elif next_header == IPPROTO_UDP:
        lines.extend(format_udp_lines(packet, transport_offset))
    elif next_header == IPPROTO_ICMPV6:
        lines.extend(format_icmp_lines(packet, transport_offset, "ICMPv6"))
    else:
        lines.append(f"Next Header {next_header} não tratado.")
    return lines


def format_arp_lines(packet: bytes, offset: int, detector: "arp_detector.ArpDetector") -> list[str]:
    if len(packet) < offset + ARP_HEADER_LENGTH:
        return ["Pacote ARP truncado."]

    hardware_type, protocol_type, hlen, plen, opcode, sender_mac, sender_ip, target_mac, target_ip = (
        parse_arp_header(packet, offset)
    )
    opcode_name = {1: "request", 2: "reply"}.get(opcode, "desconhecido")
    lines = [
        "############### ARP ###############",
        f"Hardware Type: {hardware_type}",
        f"Protocol Type: 0x{protocol_type:04x}",
        f"HLEN: {hlen}",
        f"PLEN: {plen}",
        f"Opcode: {opcode} ({opcode_name})",
        f"Sender MAC: {sender_mac}",
        f"Sender IP: {sender_ip}",
        f"Target MAC: {target_mac}",
        f"Target IP: {target_ip}",
    ]

    if hlen != 6 or plen != 4:
        lines.append("ARP com HLEN/PLEN fora do padrão Ethernet/IPv4 — detecção de spoofing não aplicada.")
        return lines

    for alert in detector.process(sender_mac, sender_ip, target_mac, target_ip, opcode):
        timestamp = datetime.now().isoformat(timespec="seconds")
        lines.append(f"[ALERTA {timestamp}] {alert}")
    return lines


def format_packet(packet: bytes, count: int, detector: "arp_detector.ArpDetector") -> list[str]:
    if len(packet) < ETH_HEADER_LENGTH:
        return [f"Pacote {count} descartado: menor que o cabeçalho Ethernet."]

    destination_mac, source_mac, eth_type = parse_ethernet_header(packet)
    lines = [
        f"Pacote {count}",
        "############### Ethernet ###############",
        f"MAC Destino: {destination_mac}",
        f"MAC Origem: {source_mac}",
        f"EtherType: 0x{eth_type:04x}",
    ]

    payload_offset = ETH_HEADER_LENGTH
    if eth_type == ETHERTYPE_IPV4:
        lines.extend(format_ipv4_lines(packet, payload_offset))
    elif eth_type == ETHERTYPE_IPV6:
        lines.extend(format_ipv6_lines(packet, payload_offset))
    elif eth_type == ETHERTYPE_ARP:
        lines.extend(format_arp_lines(packet, payload_offset, detector))
    else:
        lines.append(f"EtherType 0x{eth_type:04x} não tratado.")

    return lines


def emit(lines: list[str], log_file: TextIO) -> None:
    if not lines:
        return

    text = "\n".join(lines)
    print(text)
    print()

    log_file.write(text)
    log_file.write("\n\n")


def live_packets() -> Iterator[bytes]:
    raw_socket = create_raw_socket()
    while True:
        packet, _address = raw_socket.recvfrom(65565)
        yield packet


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Sniff-It: analisador de pacotes Ethernet/IPv4/IPv6/ARP, com detecção de ARP spoofing."
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--live",
        action="store_true",
        help="Captura pacotes ao vivo via raw socket. Requer privilégio de root no Linux.",
    )
    mode.add_argument(
        "--pcap",
        type=Path,
        help="Lê pacotes de um arquivo .pcap, sem precisar de privilégio root.",
    )
    parser.add_argument(
        "--log",
        type=Path,
        default=Path("sniff-it.log"),
        help="Arquivo onde toda a saída também é gravada. Default: sniff-it.log",
    )
    parser.add_argument(
        "--max-packets",
        type=int,
        default=0,
        help="Para depois de N pacotes. 0 = sem limite (default).",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.max_packets < 0:
        raise SystemExit("--max-packets deve ser >= 0")
    packet_limit = None if args.max_packets == 0 else args.max_packets

    packets = live_packets() if args.live else read_pcap(args.pcap)
    detector = arp_detector.ArpDetector()

    with args.log.open("a", encoding="utf-8") as log_file:
        try:
            for count, packet in enumerate(packets, start=1):
                emit(format_packet(packet, count, detector), log_file)
                if packet_limit is not None and count >= packet_limit:
                    break
        except KeyboardInterrupt:
            print("\nInterrompido pelo usuário.")
        except (OSError, ValueError) as exc:
            raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    main()
