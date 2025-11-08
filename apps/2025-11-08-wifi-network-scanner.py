import subprocess
import re
import platform
import json
import base64
import socket
import threading
import queue
import time
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

class WiFiScanner:
    def __init__(self):
        self.networks = []
        self.scan_queue = queue.Queue()
        self.system = platform.system()

    def scan_networks(self) -> List[Dict[str, str]]:
        if self.system == 'Windows':
            return self._scan_windows()
        elif self.system == 'Darwin':
            return self._scan_macos()
        elif self.system == 'Linux':
            return self._scan_linux()
        else:
            raise OSError("Unsupported operating system")

    def _scan_windows(self) -> List[Dict[str, str]]:
        try:
            output = subprocess.check_output(['netsh', 'wlan', 'show', 'networks', 'mode=Bssid'], 
                                             universal_newlines=True)
            networks = []
            current_network = {}
            for line in output.split('\n'):
                if 'SSID' in line:
                    if current_network:
                        networks.append(current_network)
                    current_network = {'ssid': line.split(':')[1].strip()}
                elif 'Signal' in line:
                    current_network['signal'] = line.split(':')[1].strip()
                elif 'Authentication' in line:
                    current_network['security'] = line.split(':')[1].strip()
            if current_network:
                networks.append(current_network)
            return networks
        except Exception as e:
            print(f"Windows scan error: {e}")
            return []

    def _scan_macos(self) -> List[Dict[str, str]]:
        try:
            output = subprocess.check_output(['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-s'], 
                                             universal_newlines=True)
            networks = []
            for line in output.split('\n')[1:]:
                parts = line.split()
                if len(parts) >= 6:
                    network = {
                        'ssid': parts[0],
                        'bssid': parts[1],
                        'signal': parts[2],
                        'security': parts[3]
                    }
                    networks.append(network)
            return networks
        except Exception as e:
            print(f"MacOS scan error: {e}")
            return []

    def _scan_linux(self) -> List[Dict[str, str]]:
        try:
            output = subprocess.check_output(['iwlist', 'wlan0', 'scan'], 
                                             universal_newlines=True)
            networks = []
            current_network = {}
            for line in output.split('\n'):
                if 'ESSID' in line:
                    current_network['ssid'] = line.split(':')[1].strip('"')
                elif 'Signal level' in line:
                    current_network['signal'] = line.split('=')[1].split()[0]
                elif 'Encryption key' in line:
                    current_network['security'] = 'Encrypted' if line.split(':')[1].strip() == 'on' else 'Open'
                
                if len(current_network) == 3:
                    networks.append(current_network)
                    current_network = {}
            return networks
        except Exception as e:
            print(f"Linux scan error: {e}")
            return []

    def advanced_network_details(self, network: Dict[str, str]) -> Dict[str, str]:
        try:
            # Simulate advanced network probing
            socket.setdefaulttimeout(1)
            ip = socket.gethostbyname(network['ssid'])
            return {
                **network,
                'ip': ip,
                'ping_time': self._ping_network(ip)
            }
        except Exception:
            return network

    def _ping_network(self, ip: str) -> str:
        try:
            start = time.time()
            socket.create_connection((ip, 80), timeout=1)
            return f"{(time.time() - start) * 1000:.2f}ms"
        except Exception:
            return "Timeout"

    def parallel_scan(self) -> List[Dict[str, str]]:
        networks = self.scan_networks()
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(self.advanced_network_details, network) for network in networks]
            return [future.result() for future in as_completed(futures)]

def main():
    scanner = WiFiScanner()
    networks = scanner.parallel_scan()
    
    print("\n--- WiFi Network Scanner ---")
    for network in networks:
        print(f"SSID: {network.get('ssid', 'Unknown')}")
        print(f"Signal Strength: {network.get('signal', 'N/A')}")
        print(f"Security: {network.get('security', 'Unknown')}")
        print(f"IP: {network.get('ip', 'N/A')}")
        print(f"Ping: {network.get('ping_time', 'N/A')}")
        print("---")

if __name__ == "__main__":
    main()