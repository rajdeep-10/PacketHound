import argparse
import threading
from flask import Flask, render_template, jsonify
from modules.portscan_detect import PortScanDetector
from modules.arpspoof_detect import ArpSpoofDetector
from modules.bruteforce_detect import BruteForceDetector

app = Flask(__name__)

# Initialize detectors
detectors = {
    "Port Scan": PortScanDetector(),
    "ARP Spoof": ArpSpoofDetector(),
    "Brute Force": BruteForceDetector()
}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/alerts')
def get_alerts():
    combined = []
    for name, detector in detectors.items():
        for alert in detector.alerts:
            # Safely handle alerts whether they are dicts or strings
            if isinstance(alert, dict):
                if 'detector' not in alert:
                    alert['detector'] = name
                combined.append(alert)
            else:
                combined.append({"detector": name, "message": str(alert)})
    
    # Sort by timestamp if it exists, otherwise just reverse for newest first
    combined.sort(key=lambda x: x.get('timestamp', 0), reverse=True)
    return jsonify(combined)

def start_detectors(interface):
    for name, detector in detectors.items():
        # Run start_live in a background daemon thread
        thread = threading.Thread(target=detector.start_live, args=(interface,))
        thread.daemon = True
        thread.start()
        print(f"[*] {name} detector started on {interface}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="PacketHound Dashboard")
    parser.add_argument('-i', '--interface', required=True, help='Network interface to sniff (e.g., eth0)')
    args = parser.parse_args()
    
    print(f"[*] Starting PacketHound on interface {args.interface}...")
    start_detectors(args.interface)
    
    print("[*] Dashboard running at http://127.0.0.1:5000")
    # use_reloader=False prevents Flask from starting the detectors twice
    app.run(debug=True, use_reloader=False)
