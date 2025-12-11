```python
import socket
import sys
import time
import argparse
import threading
from datetime import datetime
from collections import defaultdict
import ipaddress


class PortScannerConfig:
    """Configuration class for port scanner settings."""
    
    def __init__(self):
        self.timeout = 1.0
        self.max_threads = 50
        self.verbose = False
        self.output_file = None
        self.common_ports_only = False
        self.port_range_start = 1
        self.port_range_end = 65535
        
    def set_timeout(self, timeout):
        """Set the socket timeout value."""
        if timeout <= 0:
            raise ValueError("Timeout must be positive")
        self.timeout = timeout
        return self
    
    def set_max_threads(self, threads):
        """Set the maximum number of concurrent threads."""
        if threads <= 0:
            raise ValueError("Thread count must be positive")
        self.max_threads = threads
        return self
    
    def set_verbose(self, verbose):
        """Enable or disable verbose output."""
        self.verbose = verbose
        return self
    
    def set_output_file(self, filename):
        """Set output file for results."""
        self.output_file = filename
        return self
    
    def set_common_ports_only(self, common_only):
        """Scan only common ports."""
        self.common_ports_only = common_only
        return self
    
    def set_port_range(self, start, end):
        """Set custom port range."""
        if start < 1 or end > 65535 or start > end:
            raise ValueError("Invalid port range")
        self.port_range_start = start
        self.port_range_end = end
        return self


class PortScanner:
    """Main port scanner class using socket library."""
    
    COMMON_PORTS = [
        20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 
        993, 995, 3306, 3389, 5432, 5900, 8080, 8443, 9200, 27017
    ]
    
    PORT_DESCRIPTIONS = {
        20: "FTP-DATA",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        465: "SMTPS",
        587: "SMTP",
        993: "IMAPS",
        995: "POP3S",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt",
        9200: "Elasticsearch",
        27017: "MongoDB"
    }
    
    def __init__(self, target, config=None):
        """Initialize the port scanner with target and configuration."""
        self.target = target
        self.config = config if config else PortScannerConfig()
        self.results = defaultdict(list)
        self.scan_start_time = None
        self.scan_end_time = None
        self.lock = threading.Lock()
        self.ports_to_scan = []
        self.scanned_count = 0
        
    def validate_target(self):
        """Validate the target IP address."""
        try:
            ipaddress.ip_address(self.target)
            return True
        except ValueError:
            try:
                socket.gethostbyname(self.target)
                return True
            except socket.gaierror:
                return False
    
    def prepare_ports(self):
        """Prepare the list of ports to scan."""
        if self.config.common_ports_only:
            self.ports_to_scan = self.COMMON_PORTS
        else:
            self.ports_to_scan = list(range(
                self.config.port_range_start,
                self.config.port_range_end + 1
            ))
        
        if self.config.verbose:
            print(f"[*] Prepared {len(self.ports_to_scan)} ports for scanning")
    
    def scan_port(self, port):
        """Scan a single port on the target."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)
            
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            with self.lock:
                self.scanned_count += 1
                
                if result == 0:
                    status = "open"
                    service = self.PORT_DESCRIPTIONS.get(port, "Unknown")
                    self.results["open"].append((port, service))
                    
                    if self.config.verbose:
                        print(f"[+] Port {port} is OPEN ({service})")
                else:
                    status = "closed"
                    self.results["closed"].append(port)
                    
                    if self.config.verbose:
                        print(f"[-] Port {port} is CLOSED")
                
                progress = (self.scanned_count / len(self.ports_to_scan)) * 100
                if self.scanned_count % 100 == 0:
                    print(f"[*] Progress: {progress:.1f}% ({self.scanned_count}/{len(self.ports_to_scan)})")
        
        except socket.timeout:
            with self.lock:
                self.scanned_count += 1
                self.results["filtered"].append(port)
                
                if self.config.verbose:
                    print(f"[?] Port {port} is FILTERED (timeout)")
        
        except Exception as e:
            with self.lock:
                self.scanned_count += 1
                self.results["error"].append((port, str(e)))
                
                if self.config.verbose:
                    print(f"[!] Error scanning port {port}: {e}")
    
    def run_scan(self):
        """Execute the port scan using threading."""
        if not self.validate_target():
            print(f"[!] Error: Invalid target '{self.target}'")
            return False
        
        self.prepare_ports()
        self.scan_start_time = datetime.now()
        
        print(f"\n[*] Starting port scan on {self.target}")
        print(f"[*] Scan started at {self.scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[*] Timeout: {self.config.timeout}s, Max threads: {self.config.max_threads}")
        print(f"[*] Scanning {len(self.ports_to_scan)} ports\n")
        
        threads = []
        
        for port in self.ports_to_scan:
            while len(threading.enumerate()) > self.config.max_threads:
                time.sleep(0.01)
            
            thread = threading.Thread(target=self.scan_port, args=(port,))
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        for thread in threads:
            thread.join()
        
        self.scan_end_time = datetime.now()
        return True
    
    def get_results(self):
        """Return the scan results."""
        return dict(self.results)
    
    def print_results(self):
        """Print formatted scan results."""
        print("\n" + "="*60)
        print("SCAN RESULTS")
        print("="*60)
        
        open_ports = self.results.get("open", [])
        closed_ports = self.results.get("closed", [])
        filtered_ports = self.results.get("filtered", [])
        error_ports = self.results.get("error", [])
        
        print(f"\n[+] OPEN PORTS ({len(open_ports)}):")
        if open_ports:
            for port, service in sorted(open_ports):
                print(f"    Port {port:5d} - {service}")
        else:
            print("    None found")
        
        print(f"\n[-] CLOSED PORTS ({len(closed_ports)}):")
        if closed_ports and self.config.verbose:
            for port in sorted(closed_ports)[:10]:
                print(f"    Port {port}")
            if len(closed_ports) > 10:
                print(f"    ... and {len(closed_ports) - 10} more")
        else:
            print(f"    {len(closed_ports)} ports closed (not shown)")
        
        print(f"\n[?] FILTERED PORTS ({len(filtered_ports)}):")
        if filtered_ports and self.config.verbose:
            for port in sorted(filtered_ports)[:10]:
                print(f"    Port {port}")
            if len(filtered_ports) > 10:
                print(f"    ... and {len(filtered_ports) - 10} more")
        else:
            print(f"    {len(filtered_ports)} ports filtered (not shown)")
        
        if error_ports:
            print(f"\n[!] ERROR PORTS ({len(error_ports)}):")
            for port, error in error_ports[:5]:
                print(f"    Port {port}: {error}")
        
        duration = self.scan_end_time - self.scan_start_time
        print(f"\n[*] Scan completed in {duration.total_seconds():.2f} seconds")
        print(f"[*] Scan ended at {self.scan_end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60 + "\n")
    
    def save_results(self, filename):
        """Save scan results to a file."""
        try:
            with open(filename, 'w') as f:
                f.write(f"Port Scan Results for {self.target}\n")
                f.write(f"Scan started: {self.scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Scan ended: {self.scan_end_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("="*60 + "\n\n")
                
                open_ports = self.results.get("open", [])
                f.write(f"OPEN PORTS ({len(open_ports)}):\n")
                for port, service in sorted(open_ports):
                    f.write(f"  Port {port} - {service}\n")
                
                f.write(f"\nCLOSED PORTS ({len(self.results.get('closed', []))})\n")
                f.write(f"FILTERED PORTS ({len(self.results.get('filtered', []))})\n")
                
                duration = self.scan_end_time - self.scan_start_time
                f.write(f"\nScan duration: {duration.total_seconds():.2f} seconds\n")
            
            print(f"[+] Results saved to {filename}")
        except IOError as e:
            print(f"[!] Error saving results: {e}")


class ScannerStatistics:
    """Class to calculate and display scan statistics."""
    
    def __init__(self, scanner):
        self.scanner = scanner
    
    def calculate_statistics(self):
        """Calculate various statistics from scan results."""
        results = self.scanner.get_results()
        
        total_ports = len(self.scanner.ports_to_scan)
        open_count = len(results.get("open", []))
        closed_count = len(results.get("closed", []))
        filtered_count = len(results.get("filtered", []))
        error_count = len(results.get("error", []))
        
        duration = (self.scanner.scan_end_time - self.scanner.scan_start_time).total_seconds()
        ports_per_second = total_ports / duration if duration > 0 else 0
        
        stats = {
            "total_ports": total_ports,
            "open_ports": open_count,
            "closed_ports": closed_count,
            "filtered_ports": filtered_count,
            "error_ports": error_count,
            "duration_seconds": duration,
            "ports_per_second": ports_per_second,
            "open_percentage": (open_count / total_ports * 100) if total_ports > 0 else 0
        }
        
        return stats
    
    def print_statistics(self):
        """Print detailed statistics."""
        stats = self.calculate_statistics()
        
        print("\n" + "="*60)
        print("SCAN STATISTICS")
        print("="*60)
        print(f"Total ports scanned: {stats['total_ports']}")
        print(f"Open ports: {stats['open_ports']} ({stats['open_percentage']:.2f}%)")
        print(f"Closed ports: {stats['closed_ports']}")
        print(f"Filtered ports: {stats['filtered_ports']}")
        print(f"Error ports: {stats['error_ports']}")
        print(f"Scan duration: {stats['duration_seconds']:.2f} seconds")
        print(f"Scan rate: {stats['ports_per_second']:.2f} ports/second")
        print("="*60 + "\n")


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Network Port Scanner - Scan target for open TCP ports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python script.py 192.168.1.1
  python script.py 192.168.1.1 -p 1-1000
  python script.py 192.168.1.1 -c -t 2 -m 100
  python script.py 192.168.1.1 -o results.txt -v
        """
    )
    
    parser.add_argument(
        "target",
        help="Target IP address or hostname to scan"
    )
    
    parser.add_argument(
        "-p", "--ports",
        help="Port range to scan (e.g., 1-1000, default: 1-65535)",
        default=None
    )
    
    parser.add_argument(
        "-c", "--common",
        action="store_true",
        help="Scan only common ports"
    )
    
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=1.0,
        help="Socket timeout in seconds (default: 1.0)"
    )
    
    parser.add_argument(
        "-m", "--max-threads",
        type=int,
        default=50,
        help="Maximum concurrent threads (default: 50)"
    )
    
    parser.add_argument(
        "-o", "--output",
        help="Save results to file"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "-s", "--stats",
        action="store_true",
        help="Display detailed statistics"
    )
    
    return parser.parse_args()


def parse_port_range(port_string):
    """Parse port range string (e.g., '1-1000')."""
    try:
        if '-' in port_string:
            start, en