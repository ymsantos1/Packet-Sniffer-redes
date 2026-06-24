"""Detector de ARP spoofing: tabela IP-MAC e regras de anomalia."""

import time
from collections import defaultdict, deque

GRATUITOUS_WINDOW_SECONDS = 10
GRATUITOUS_THRESHOLD = 3


class ArpDetector:
    def __init__(
        self,
        gratuitous_window_seconds: float = GRATUITOUS_WINDOW_SECONDS,
        gratuitous_threshold: int = GRATUITOUS_THRESHOLD,
    ) -> None:
        self.ip_to_mac: dict[str, dict] = {}
        self.mac_to_ips: dict[str, set] = defaultdict(set)
        self.gratuitous_history: dict[str, deque] = defaultdict(deque)
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
        entry = self.ip_to_mac.get(ip)
        if entry is None or entry["mac"] != mac:
            self.ip_to_mac[ip] = {"mac": mac, "first_seen": now, "last_seen": now, "count": 1}
        else:
            entry["last_seen"] = now
            entry["count"] += 1
        self.mac_to_ips[mac].add(ip)
