"""Command-line interface for Sniff-It."""

from __future__ import annotations

import argparse
from pathlib import Path

from tools.arp_detector import ArpDetector

from .capture import live_packets
from .formatters import format_packet
from .output import emit
from .pcap import read_pcap


def build_parser() -> argparse.ArgumentParser:
    """Build command-line parser for live capture and PCAP analysis modes."""
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
    """Run Sniff-It from parsed CLI arguments."""
    args = build_parser().parse_args()
    if args.max_packets < 0:
        raise SystemExit("--max-packets deve ser >= 0")
    packet_limit = None if args.max_packets == 0 else args.max_packets

    packets = live_packets() if args.live else read_pcap(args.pcap)
    detector = ArpDetector()

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
