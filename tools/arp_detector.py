"""ARP spoofing detector based on observed IP/MAC associations."""

from __future__ import annotations

import time
from collections import defaultdict, deque

# Time window used to count repeated gratuitous ARP packets for one IP.
GRATUITOUS_WINDOW_SECONDS = 10

# Minimum repeated gratuitous ARP observations needed before raising an alert.
GRATUITOUS_THRESHOLD = 3


class ArpDetector:
    """Keep ARP state and report suspicious IP/MAC behavior."""

    def __init__(
        self,
        gratuitous_window_seconds: float = GRATUITOUS_WINDOW_SECONDS,
        gratuitous_threshold: int = GRATUITOUS_THRESHOLD,
    ) -> None:
        """Create detector with configurable gratuitous ARP limits."""
        self.ip_to_mac: dict[str, dict[str, float | int | str]] = {}
        self.mac_to_ips: dict[str, set[str]] = defaultdict(set)
        self.gratuitous_history: dict[str, deque[float]] = defaultdict(deque)
        self.gratuitous_window_seconds = gratuitous_window_seconds
        self.gratuitous_threshold = gratuitous_threshold

    def process(
        self,
        sender_mac: str,
        sender_ip: str,
        target_mac: str,
        target_ip: str,
        opcode: int,
    ) -> list[str]:
        """Inspect one parsed ARP packet and return anomaly alert messages."""
        alerts = []
        now = time.time()

        previous = self.ip_to_mac.get(sender_ip)
        if previous is not None and previous["mac"] != sender_mac:
            alerts.append(
                f"Conflito de associação IP-MAC: IP {sender_ip} estava associado ao MAC "
                f"{previous['mac']} e agora foi visto com o MAC {sender_mac}."
            )

        if sender_ip == target_ip:
            history = self.gratuitous_history[sender_ip]
            history.append(now)
            while history and now - history[0] > self.gratuitous_window_seconds:
                history.popleft()
            if len(history) >= self.gratuitous_threshold:
                alerts.append(
                    f"ARP não solicitado (gratuitous) repetido: {len(history)} ocorrências de "
                    f"{sender_ip}/{sender_mac} em {self.gratuitous_window_seconds:.0f}s "
                    f"(opcode {opcode})."
                )

        other_ips = self.mac_to_ips.get(sender_mac, set()) - {sender_ip}
        if other_ips:
            alerts.append(
                f"MAC {sender_mac} reivindicando múltiplos IPs: {sender_ip} agora, "
                f"antes visto com {', '.join(sorted(other_ips))}."
            )

        self._update(sender_ip, sender_mac, now)
        return alerts

    def _update(self, ip: str, mac: str, now: float) -> None:
        """Record latest IP/MAC observation and refresh reverse lookup state."""
        entry = self.ip_to_mac.get(ip)
        if entry is None or entry["mac"] != mac:
            self.ip_to_mac[ip] = {"mac": mac, "first_seen": now, "last_seen": now, "count": 1}
        else:
            entry["last_seen"] = now
            entry["count"] += 1
        self.mac_to_ips[mac].add(ip)
