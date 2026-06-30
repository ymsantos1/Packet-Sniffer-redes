import unittest
from pathlib import Path

import arp_detector
from sniffit.formatters import format_packet
from sniffit.pcap import read_pcap


FIXTURE = Path("validation-ipv6-icmp-arp.pcap")


class PcapAndFormatterTests(unittest.TestCase):
    def test_reads_validation_pcap(self):
        packets = list(read_pcap(FIXTURE))

        self.assertEqual(len(packets), 8)
        self.assertTrue(all(isinstance(packet, bytes) for packet in packets))

    def test_formats_ipv4_icmp_packet(self):
        packet = next(read_pcap(FIXTURE))
        lines = format_packet(packet, 1, arp_detector.ArpDetector())
        text = "\n".join(lines)

        self.assertIn("EtherType: 0x0800", text)
        self.assertIn("############### IPv4 ###############", text)
        self.assertIn("Protocolo: 1", text)
        self.assertIn("########## ICMP ##########", text)
        self.assertIn("Tipo: 8", text)

    def test_formats_ipv6_udp_packet(self):
        packet = list(read_pcap(FIXTURE))[2]
        lines = format_packet(packet, 3, arp_detector.ArpDetector())
        text = "\n".join(lines)

        self.assertIn("EtherType: 0x86dd", text)
        self.assertIn("############### IPv6 ###############", text)
        self.assertIn("Next Header: 17", text)
        self.assertIn("########## UDP ##########", text)
        self.assertIn("Porta Destino: 53", text)

    def test_formats_arp_alerts_from_fixture_sequence(self):
        detector = arp_detector.ArpDetector()
        packets = list(read_pcap(FIXTURE))
        all_lines = []

        for index, packet in enumerate(packets, start=1):
            all_lines.extend(format_packet(packet, index, detector))

        text = "\n".join(all_lines)
        self.assertIn("Conflito de associação IP-MAC", text)
        self.assertIn("ARP não solicitado (gratuitous) repetido", text)
        self.assertIn("reivindicando múltiplos IPs", text)

    def test_short_ethernet_frame_is_discarded(self):
        self.assertEqual(
            format_packet(b"\x00\x01", 1, arp_detector.ArpDetector()),
            ["Pacote 1 descartado: menor que o cabeçalho Ethernet."],
        )


if __name__ == "__main__":
    unittest.main()
