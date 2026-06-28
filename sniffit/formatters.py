"""Human-readable packet formatting."""

from __future__ import annotations

from datetime import datetime

import arp_detector

from .constants import (
    ARP_HEADER_LENGTH,
    ETH_HEADER_LENGTH,
    ETHERTYPE_ARP,
    ETHERTYPE_IPV4,
    ETHERTYPE_IPV6,
    ICMP_HEADER_LENGTH,
    IPPROTO_ICMP,
    IPPROTO_ICMPV6,
    IPPROTO_TCP,
    IPPROTO_UDP,
    IPV4_HEADER_MIN_LENGTH,
    IPV6_HEADER_LENGTH,
    TCP_HEADER_MIN_LENGTH,
    UDP_HEADER_LENGTH,
)
from .parsers import (
    parse_arp_header,
    parse_ethernet_header,
    parse_icmp_header,
    parse_ipv4_header,
    parse_ipv6_header,
    parse_tcp_header,
    parse_udp_header,
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


def format_arp_lines(packet: bytes, offset: int, detector: arp_detector.ArpDetector) -> list[str]:
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


def format_packet(packet: bytes, count: int, detector: arp_detector.ArpDetector) -> list[str]:
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

