from scapy.all import sniff, TCP, IP
from collections import defaultdict
import time
import threading
from colorama import Fore, init

init(autoreset=True)

class PortScanDetector:
    def __init__(self, threshold=15, window_seconds=10, cooldown_seconds=30):
        self.threshold = threshold
        self.window_seconds = window_seconds

        # cooldown_seconds: after alerting on an IP, how long we stay
        # quiet about it before allowing a fresh alert. This is what
        # stops one scan from generating 6 duplicate alerts.
        self.cooldown_seconds = cooldown_seconds

        self.tracker = defaultdict(lambda: {
            "ports": set(),
            "first_seen": None,
            "last_alerted": None     # NEW — tracks when we last alerted this IP
        })

        self.alerts = []
        self.lock = threading.Lock()

    def process_packet(self, packet):
        if not packet.haslayer(TCP) or not packet.haslayer(IP):
            return

        tcp_layer = packet[TCP]
        ip_layer  = packet[IP]

        if tcp_layer.flags != "S":
            return

        src_ip = ip_layer.src
        dst_port = tcp_layer.dport
        now = time.time()

        with self.lock:
            entry = self.tracker[src_ip]

            if entry["first_seen"] is None:
                entry["first_seen"] = now
            elif now - entry["first_seen"] > self.window_seconds:
                entry["ports"] = set()
                entry["first_seen"] = now

            entry["ports"].add(dst_port)

            if len(entry["ports"]) >= self.threshold:
                # COOLDOWN CHECK — only alert if we've never alerted
                # this IP before, OR the cooldown period has passed
                already_cooling_down = (
                    entry["last_alerted"] is not None and
                    now - entry["last_alerted"] < self.cooldown_seconds
                )

                if not already_cooling_down:
                    self.raise_alert(src_ip, entry["ports"], now)
                    entry["last_alerted"] = now

                # We still reset the port counter so we're tracking
                # fresh activity, but we DON'T alert again until
                # cooldown expires — this is the key change
                entry["ports"] = set()
                entry["first_seen"] = now

    def raise_alert(self, src_ip, ports, timestamp):
        alert = {
            "type": "PORT_SCAN",
            "severity": "HIGH",
            "source_ip": src_ip,
            "port_count": len(ports),
            "ports_sample": sorted(list(ports))[:10],
            "timestamp": timestamp,
            "readable_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
        }
        self.alerts.append(alert)

        print(f"\n{Fore.RED}{'='*60}")
        print(f"{Fore.RED}[ALERT] PORT SCAN DETECTED")
        print(f"{Fore.RED}{'='*60}")
        print(f"{Fore.YELLOW}  Source IP:    {src_ip}")
        print(f"{Fore.YELLOW}  Ports probed: {len(ports)} unique ports in {self.window_seconds}s window")
        print(f"{Fore.YELLOW}  Sample ports: {alert['ports_sample']}")
        print(f"{Fore.YELLOW}  Time:         {alert['readable_time']}")
        print(f"{Fore.CYAN}  (Further alerts for this IP suppressed for {self.cooldown_seconds}s)")
        print(f"{Fore.RED}{'='*60}\n")

    def start_live(self, interface=None):
        print(f"{Fore.BLUE}[*] Starting live port scan detection...")
        print(f"{Fore.BLUE}[*] Threshold: {self.threshold} ports in {self.window_seconds}s = alert")
        print(f"{Fore.BLUE}[*] Cooldown: {self.cooldown_seconds}s between repeat alerts per IP")
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
            print(f"{Fore.RED}[-] Permission denied. Run with sudo — packet sniffing requires root.")
        except KeyboardInterrupt:
            print(f"\n{Fore.CYAN}[*] Stopped. Total alerts raised: {len(self.alerts)}")


if __name__ == "__main__":
    detector = PortScanDetector(threshold=15, window_seconds=10, cooldown_seconds=30)
    detector.start_live()
