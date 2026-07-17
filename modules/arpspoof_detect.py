from scapy.all import sniff, ARP
from colorama import Fore, init
import time

init(autoreset=True)

class ArpSpoofDetector:
    def __init__(self):
        self.ip_to_mac = {}
        self.alerts = []

    def process_packet(self, packet):
        if not packet.haslayer(ARP):
            return

        arp_layer = packet[ARP]

        if arp_layer.op != 2:
            return

        claimed_ip  = arp_layer.psrc
        claimed_mac = arp_layer.hwsrc

        if claimed_ip not in self.ip_to_mac:
            self.ip_to_mac[claimed_ip] = claimed_mac
            return

        known_mac = self.ip_to_mac[claimed_ip]

        if known_mac != claimed_mac:
            self.raise_alert(claimed_ip, known_mac, claimed_mac, time.time())
            self.ip_to_mac[claimed_ip] = claimed_mac

    def raise_alert(self, ip, old_mac, new_mac, timestamp):
        alert = {
            "type": "ARP_SPOOF",
            "severity": "CRITICAL",
            "target_ip": ip,
            "trusted_mac": old_mac,
            "suspicious_mac": new_mac,
            "timestamp": timestamp,
            "readable_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
        }
        self.alerts.append(alert)

        print(f"\n{Fore.RED}{'='*60}")
        print(f"{Fore.RED}[ALERT] POSSIBLE ARP SPOOFING DETECTED")
        print(f"{Fore.RED}{'='*60}")
        print(f"{Fore.YELLOW}  Target IP:       {ip}")
        print(f"{Fore.YELLOW}  Previously seen: {old_mac}")
        print(f"{Fore.YELLOW}  Now claimed by:  {new_mac}  <- SUSPICIOUS")
        print(f"{Fore.YELLOW}  Time:            {alert['readable_time']}")
        print(f"{Fore.CYAN}  This can indicate a Man-in-the-Middle attack in progress")
        print(f"{Fore.RED}{'='*60}\n")

    def start_live(self, interface=None):
        print(f"{Fore.BLUE}[*] Starting ARP spoof detection...")
        print(f"{Fore.BLUE}[*] Listening on interface: {interface or 'default'}")
        print(f"{Fore.BLUE}[*] Building trusted IP-to-MAC table from live traffic")
        print(f"{Fore.BLUE}[*] Press Ctrl+C to stop\n")

        try:
            sniff(
                filter="arp",
                prn=self.process_packet,
                iface=interface,
                store=False
            )
        except PermissionError:
            print(f"{Fore.RED}[-] Permission denied. Run with sudo.")
        except KeyboardInterrupt:
            print(f"\n{Fore.CYAN}[*] Stopped. Total alerts raised: {len(self.alerts)}")


if __name__ == "__main__":
    detector = ArpSpoofDetector()
    detector.start_live()
