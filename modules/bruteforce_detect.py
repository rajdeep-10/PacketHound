from scapy.all import sniff, TCP, IP
from collections import defaultdict
import time
import threading
from colorama import Fore, init

init(autoreset=True)

class BruteForceDetector:
    MONITORED_PORTS = {
        21:   "FTP",
        22:   "SSH",
        23:   "Telnet",
        3389: "RDP",
        3306: "MySQL",
        5900: "VNC",
    }

    def __init__(self, threshold=8, window_seconds=15, cooldown_seconds=30):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        self.tracker = defaultdict(lambda: {"count": 0, "first_seen": None, "last_alerted": None})
        self.alerts = []
        self.lock = threading.Lock()

    def process_packet(self, packet):
        if not packet.haslayer(TCP) or not packet.haslayer(IP):
            return

        tcp_layer = packet[TCP]
        ip_layer  = packet[IP]

        if tcp_layer.flags != "S":
            return

        dst_port = tcp_layer.dport

        if dst_port not in self.MONITORED_PORTS:
            return

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst  # <-- ADDED: Capture target IP
        key = (src_ip, dst_port)
        now = time.time()

        with self.lock:
            entry = self.tracker[key]

            if entry["first_seen"] is None:
                entry["first_seen"] = now
            elif now - entry["first_seen"] > self.window_seconds:
                entry["count"] = 0
                entry["first_seen"] = now

            entry["count"] += 1

            if entry["count"] >= self.threshold:
                already_cooling_down = (
                    entry["last_alerted"] is not None and
                    now - entry["last_alerted"] < self.cooldown_seconds
                )

                if not already_cooling_down:
                    self.raise_alert(src_ip, dst_ip, dst_port, entry["count"], now) # <-- ADDED dst_ip
                    entry["last_alerted"] = now

                entry["count"] = 0
                entry["first_seen"] = now

    def raise_alert(self, src_ip, target_ip, port, attempt_count, timestamp): # <-- ADDED target_ip
        service = self.MONITORED_PORTS.get(port, "Unknown")

        alert = {
            "type": "BRUTE_FORCE",
            "severity": "HIGH",
            "source_ip": src_ip,
            "target_ip": target_ip,  # <-- ADDED target_ip
            "target_port": port,
            "target_service": service,
            "attempt_count": attempt_count,
            "window_seconds": self.window_seconds,
            "readable_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
        }
        self.alerts.append(alert)

        print(f"\n{Fore.RED}{'='*60}")
        print(f"{Fore.RED}[ALERT] POSSIBLE BRUTE-FORCE ATTACK DETECTED")
        print(f"{Fore.RED}{'='*60}")
        print(f"{Fore.YELLOW}  Source IP:     {src_ip}")
        print(f"{Fore.YELLOW}  Target IP:     {target_ip}") # <-- ADDED
        print(f"{Fore.YELLOW}  Target service: {service} (port {port})")
        print(f"{Fore.YELLOW}  Attempts:      {attempt_count} connections in {self.window_seconds}s")
        print(f"{Fore.YELLOW}  Time:          {alert['readable_time']}")
        print(f"{Fore.CYAN}  (Further alerts for this IP/port suppressed for {self.cooldown_seconds}s)")
        print(f"{Fore.RED}{'='*60}\n")

    def start_live(self, interface=None):
        print(f"{Fore.BLUE}[*] Starting brute-force login detection...")
        print(f"{Fore.BLUE}[*] Monitoring ports: {list(self.MONITORED_PORTS.keys())} ({', '.join(self.MONITORED_PORTS.values())})")
        print(f"{Fore.BLUE}[*] Threshold: {self.threshold} attempts in {self.window_seconds}s = alert")
        print(f"{Fore.BLUE}[*] Listening on interface: {interface or 'default'}")
        print(f"{Fore.BLUE}[*] Press Ctrl+C to stop\n")

        try:
            sniff(
                filter="tcp",
                prn=self.process_packet,
                iface=interface,
                store=False
            )
        except PermissionError:
            print(f"{Fore.RED}[-] Permission denied. Run with sudo.")
        except KeyboardInterrupt:
            print(f"\n{Fore.CYAN}[*] Stopped. Total alerts raised: {len(self.alerts)}")


if __name__ == "__main__":
    detector = BruteForceDetector(threshold=8, window_seconds=15, cooldown_seconds=30)
    detector.start_live()
