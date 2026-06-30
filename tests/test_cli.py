import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class CliTests(unittest.TestCase):
    def test_help_lists_supported_modes(self):
        result = subprocess.run(
            [sys.executable, "sniff-it.py", "--help"],
            check=True,
            capture_output=True,
            text=True,
        )

        self.assertIn("--live", result.stdout)
        self.assertIn("--pcap", result.stdout)
        self.assertIn("--log", result.stdout)
        self.assertIn("--max-packets", result.stdout)

    def test_pcap_mode_writes_log_and_respects_packet_limit(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "sniff-it-test.log"

            result = subprocess.run(
                [
                    sys.executable,
                    "sniff-it.py",
                    "--pcap",
                    "validation-ipv6-icmp-arp.pcap",
                    "--max-packets",
                    "2",
                    "--log",
                    str(log_path),
                ],
                check=True,
                capture_output=True,
                text=True,
            )

            log_text = log_path.read_text(encoding="utf-8")
            self.assertIn("Pacote 1", result.stdout)
            self.assertIn("Pacote 2", result.stdout)
            self.assertNotIn("Pacote 3", result.stdout)
            self.assertIn("Pacote 1", log_text)
            self.assertIn("Pacote 2", log_text)
            self.assertNotIn("Pacote 3", log_text)


if __name__ == "__main__":
    unittest.main()
