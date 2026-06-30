import unittest

from sniffit.parsers import (
    parse_arp_header,
    parse_ethernet_header,
    parse_icmp_header,
    parse_ipv4_header,
    parse_ipv6_header,
    parse_tcp_header,
    parse_udp_header,
)
from tools.generate_validation_pcap import (
    ETHERTYPE_ARP,
    ETHERTYPE_IPV4,
    ETHERTYPE_IPV6,
    IPPROTO_ICMP,
    IPPROTO_ICMPV6,
    IPPROTO_UDP,
    arp_packet,
    ethernet,
    icmp_packet,
    ipv4_packet,
    ipv6_packet,
    udp_packet,
)


class ParserTests(unittest.TestCase):
    def test_parse_ethernet_header(self):
        frame = ethernet(
            "66:77:88:99:aa:bb",
            "00:11:22:33:44:55",
            ETHERTYPE_IPV4,
            b"payload",
        )

        self.assertEqual(
            parse_ethernet_header(frame),
            ("66:77:88:99:aa:bb", "00:11:22:33:44:55", ETHERTYPE_IPV4),
        )

    def test_parse_ipv4_and_icmp_headers(self):
        payload = icmp_packet(8)
        frame = ethernet(
            "66:77:88:99:aa:bb",
            "00:11:22:33:44:55",
            ETHERTYPE_IPV4,
            ipv4_packet(IPPROTO_ICMP, "192.0.2.10", "192.0.2.1", payload),
        )

        self.assertEqual(
            parse_ipv4_header(frame, 14),
            (4, 5, 20, 64, IPPROTO_ICMP, "192.0.2.10", "192.0.2.1"),
        )
        self.assertEqual(parse_icmp_header(frame, 34), (8, 0, 0))

    def test_parse_ipv6_and_udp_headers(self):
        payload = udp_packet(5353, 53)
        frame = ethernet(
            "66:77:88:99:aa:bb",
            "00:11:22:33:44:55",
            ETHERTYPE_IPV6,
            ipv6_packet(IPPROTO_UDP, "2001:db8::10", "2001:db8::53", payload),
        )

        self.assertEqual(
            parse_ipv6_header(frame, 14),
            (6, 0, 0, 12, IPPROTO_UDP, 64, "2001:db8::10", "2001:db8::53"),
        )
        self.assertEqual(parse_udp_header(frame, 54), (5353, 53, 12, 0))

    def test_parse_ipv6_and_icmpv6_headers(self):
        payload = icmp_packet(128)
        frame = ethernet(
            "66:77:88:99:aa:bb",
            "00:11:22:33:44:55",
            ETHERTYPE_IPV6,
            ipv6_packet(IPPROTO_ICMPV6, "2001:db8::10", "2001:db8::1", payload),
        )

        self.assertEqual(
            parse_ipv6_header(frame, 14),
            (6, 0, 0, 4, IPPROTO_ICMPV6, 64, "2001:db8::10", "2001:db8::1"),
        )
        self.assertEqual(parse_icmp_header(frame, 54), (128, 0, 0))

    def test_parse_tcp_header(self):
        tcp_header = bytes.fromhex(
            "3039005000000001000000025010200000000000"
        )
        frame = ethernet(
            "66:77:88:99:aa:bb",
            "00:11:22:33:44:55",
            ETHERTYPE_IPV4,
            ipv4_packet(6, "192.0.2.10", "192.0.2.1", tcp_header),
        )

        self.assertEqual(parse_tcp_header(frame, 34), (12345, 80, 1, 2, 20))

    def test_parse_arp_header(self):
        frame = ethernet(
            "ff:ff:ff:ff:ff:ff",
            "00:11:22:33:44:55",
            ETHERTYPE_ARP,
            arp_packet(
                2,
                "00:11:22:33:44:55",
                "192.0.2.1",
                "66:77:88:99:aa:bb",
                "192.0.2.10",
            ),
        )

        self.assertEqual(
            parse_arp_header(frame, 14),
            (
                1,
                ETHERTYPE_IPV4,
                6,
                4,
                2,
                "00:11:22:33:44:55",
                "192.0.2.1",
                "66:77:88:99:aa:bb",
                "192.0.2.10",
            ),
        )


if __name__ == "__main__":
    unittest.main()
