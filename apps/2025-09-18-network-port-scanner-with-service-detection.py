import socket
import concurrent.futures
import threading
import argparse
import sys
import re
import time
from typing import List, Dict, Optional, Tuple

class NetworkPortScanner:
    def __init__(self, target: str, port_range: Tuple[int, int] = (1, 1024), 
                 timeout: float = 1.0, max_threads: int = 100):
        self.target = target
        self.start_port, self.end_port = port_range
        self.timeout = timeout
        self.max_threads = max_threads
        self.open_ports: List[Dict[str, Any]] = []
        self.lock = threading.Lock()

    def scan_port(self, port: int) -> Optional[Dict[str, Any]]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                banner = self._grab_banner(self.target, port)
                port_info = {
                    'port': port,
                    'status': 'Open',
                    'service': self._detect_service(port),
                    'banner': banner
                }
                
                with self.lock:
                    self.open_ports.append(port_info)
                
                return port_info
            
            sock.close()
        except Exception as e:
            pass
        
        return None

    def _grab_banner(self, host: str, port: int) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((host, port))
                
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner
        except Exception:
            return "No banner retrieved"

    def _detect_service(self, port: int) -> str:
        common_services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP', 
            443: 'HTTPS', 3306: 'MySQL', 3389: 'RDP', 
            5432: 'PostgreSQL', 8080: 'HTTP Proxy'
        }
        return common_services.get(port, 'Unknown')

    def scan(self) -> List[Dict[str, Any]]:
        print(f"Scanning {self.target} from port {self.start_port} to {self.end_port}")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [
                executor.submit(self.scan_port, port) 
                for port in range(self.start_port, self.end_port + 1)
            ]
            
            concurrent.futures.wait(futures)
        
        return sorted(self.open_ports, key=lambda x: x['port'])

def print_scan_results(results: List[Dict[str, Any]]):
    if not results:
        print("No open ports found.")
        return

    print("\n{:<10} {:<15} {:<20} {:<50}".format('Port', 'Status', 'Service', 'Banner'))
    print("-" * 95)
    
    for result in results:
        print("{:<10} {:<15} {:<20} {:<50}".format(
            result['port'], 
            result['status'], 
            result['service'], 
            result['banner'][:50]
        ))

def main():
    parser = argparse.ArgumentParser(description='Network Port Scanner')
    parser.add_argument('target', help='Target IP or hostname to scan')
    parser.add_argument('-p', '--ports', 
                        help='Port range (e.g. 1-100)', 
                        default='1-1024')
    parser.add_argument('-t', '--timeout', 
                        type=float, 
                        default=1.0, 
                        help='Connection timeout')
    parser.add_argument('--threads', 
                        type=int, 
                        default=100, 
                        help='Maximum concurrent threads')

    args = parser.parse_args()

    try:
        start_port, end_port = map(int, args.ports.split('-'))
    except ValueError:
        print("Invalid port range. Use format like 1-1024")
        sys.exit(1)

    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"Could not resolve hostname: {args.target}")
        sys.exit(1)

    start_time = time.time()
    scanner = NetworkPortScanner(
        target_ip, 
        port_range=(start_port, end_port), 
        timeout=args.timeout,
        max_threads=args.threads
    )
    
    results = scanner.scan()
    end_time = time.time()

    print_scan_results(results)
    print(f"\nScan completed in {end_time - start_time:.2f} seconds")
    print(f"Total open ports found: {len(results)}")

if __name__ == '__main__':
    main()