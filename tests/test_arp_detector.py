import unittest

from tools.arp_detector import ArpDetector


class ArpDetectorTests(unittest.TestCase):
    def test_records_ip_mac_observations(self):
        detector = ArpDetector()

        alerts = detector.process(
            sender_mac="00:11:22:33:44:55",
            sender_ip="192.0.2.1",
            target_mac="66:77:88:99:aa:bb",
            target_ip="192.0.2.10",
            opcode=2,
        )
        alerts += detector.process(
            sender_mac="00:11:22:33:44:55",
            sender_ip="192.0.2.1",
            target_mac="66:77:88:99:aa:bb",
            target_ip="192.0.2.10",
            opcode=2,
        )

        self.assertEqual(alerts, [])
        self.assertEqual(detector.ip_to_mac["192.0.2.1"]["mac"], "00:11:22:33:44:55")
        self.assertEqual(detector.ip_to_mac["192.0.2.1"]["count"], 2)

    def test_alerts_on_ip_mac_conflict(self):
        detector = ArpDetector()
        detector.process(
            sender_mac="00:11:22:33:44:55",
            sender_ip="192.0.2.1",
            target_mac="66:77:88:99:aa:bb",
            target_ip="192.0.2.10",
            opcode=2,
        )

        alerts = detector.process(
            sender_mac="aa:bb:cc:dd:ee:ff",
            sender_ip="192.0.2.1",
            target_mac="66:77:88:99:aa:bb",
            target_ip="192.0.2.10",
            opcode=2,
        )

        self.assertEqual(len(alerts), 1)
        self.assertIn("Conflito de associação IP-MAC", alerts[0])
        self.assertIn("00:11:22:33:44:55", alerts[0])
        self.assertIn("aa:bb:cc:dd:ee:ff", alerts[0])

    def test_alerts_on_repeated_gratuitous_arp(self):
        detector = ArpDetector(gratuitous_window_seconds=10, gratuitous_threshold=3)

        alerts = []
        for _ in range(3):
            alerts.extend(
                detector.process(
                    sender_mac="aa:bb:cc:dd:ee:ff",
                    sender_ip="192.0.2.20",
                    target_mac="00:00:00:00:00:00",
                    target_ip="192.0.2.20",
                    opcode=1,
                )
            )

        self.assertTrue(any("ARP não solicitado" in alert for alert in alerts))

    def test_alerts_on_one_mac_claiming_many_ips(self):
        detector = ArpDetector()
        detector.process(
            sender_mac="aa:bb:cc:dd:ee:ff",
            sender_ip="192.0.2.1",
            target_mac="66:77:88:99:aa:bb",
            target_ip="192.0.2.10",
            opcode=2,
        )

        alerts = detector.process(
            sender_mac="aa:bb:cc:dd:ee:ff",
            sender_ip="192.0.2.20",
            target_mac="00:00:00:00:00:00",
            target_ip="192.0.2.20",
            opcode=1,
        )

        self.assertTrue(any("reivindicando múltiplos IPs" in alert for alert in alerts))


if __name__ == "__main__":
    unittest.main()
