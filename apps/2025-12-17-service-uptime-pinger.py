```python
import socket
import subprocess
import sys
import time
import json
import threading
import logging
from datetime import datetime
from typing import Dict, List, Tuple, Optional
import platform
import statistics

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('service_uptime.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class ServiceUptimeMonitor:
    """
    A comprehensive service uptime monitoring system that checks services
    via HTTP, ICMP, and TCP protocols.
    """

    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize the service uptime monitor.
        
        Args:
            config_file: Path to JSON configuration file with services to monitor
        """
        self.services = []
        self.results = {}
        self.historical_data = {}
        self.lock = threading.Lock()
        self.running = False
        
        if config_file:
            self.load_config(config_file)
        
        logger.info("ServiceUptimeMonitor initialized")

    def load_config(self, config_file: str) -> None:
        """
        Load service configuration from a JSON file.
        
        Args:
            config_file: Path to the configuration file
        """
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                self.services = config.get('services', [])
                logger.info(f"Loaded {len(self.services)} services from config")
        except FileNotFoundError:
            logger.error(f"Configuration file not found: {config_file}")
            raise
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON in configuration file: {config_file}")
            raise

    def add_service(self, name: str, protocol: str, host: str, 
                   port: int = None, path: str = None, timeout: int = 5) -> None:
        """
        Add a service to monitor.
        
        Args:
            name: Service name
            protocol: Protocol type (http, https, icmp, tcp)
            host: Hostname or IP address
            port: Port number (required for tcp, optional for http/https)
            path: URL path (for http/https)
            timeout: Connection timeout in seconds
        """
        service = {
            'name': name,
            'protocol': protocol.lower(),
            'host': host,
            'port': port,
            'path': path or '/',
            'timeout': timeout
        }
        self.services.append(service)
        self.historical_data[name] = []
        logger.info(f"Added service: {name} ({protocol}://{host}:{port})")

    def check_http_service(self, service: Dict) -> Tuple[bool, str, float]:
        """
        Check HTTP/HTTPS service availability.
        
        Args:
            service: Service configuration dictionary
            
        Returns:
            Tuple of (is_available, status_message, response_time)
        """
        try:
            import urllib.request
            import urllib.error
            
            protocol = service['protocol']
            host = service['host']
            port = service.get('port', 443 if protocol == 'https' else 80)
            path = service.get('path', '/')
            timeout = service.get('timeout', 5)
            
            url = f"{protocol}://{host}:{port}{path}"
            
            start_time = time.time()
            
            try:
                request = urllib.request.Request(url)
                response = urllib.request.urlopen(request, timeout=timeout)
                response_time = time.time() - start_time
                
                if response.status == 200:
                    logger.debug(f"HTTP check passed for {service['name']}: {response.status}")
                    return True, f"HTTP {response.status} OK", response_time
                else:
                    logger.warning(f"HTTP check failed for {service['name']}: {response.status}")
                    return False, f"HTTP {response.status}", response_time
                    
            except urllib.error.HTTPError as e:
                response_time = time.time() - start_time
                logger.warning(f"HTTP error for {service['name']}: {e.code}")
                return False, f"HTTP {e.code}", response_time
            except urllib.error.URLError as e:
                response_time = time.time() - start_time
                logger.error(f"URL error for {service['name']}: {str(e)}")
                return False, f"URL Error: {str(e)}", response_time
                
        except Exception as e:
            logger.error(f"Unexpected error checking HTTP service {service['name']}: {str(e)}")
            return False, f"Error: {str(e)}", 0

    def check_icmp_service(self, service: Dict) -> Tuple[bool, str, float]:
        """
        Check ICMP ping availability.
        
        Args:
            service: Service configuration dictionary
            
        Returns:
            Tuple of (is_available, status_message, response_time)
        """
        try:
            host = service['host']
            timeout = service.get('timeout', 5)
            
            if platform.system().lower() == 'windows':
                command = ['ping', '-n', '1', '-w', str(timeout * 1000), host]
            else:
                command = ['ping', '-c', '1', '-W', str(timeout * 1000), host]
            
            start_time = time.time()
            
            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    timeout=timeout + 2,
                    text=True
                )
                response_time = time.time() - start_time
                
                if result.returncode == 0:
                    logger.debug(f"ICMP check passed for {service['name']}")
                    return True, "ICMP Ping OK", response_time
                else:
                    logger.warning(f"ICMP check failed for {service['name']}")
                    return False, "ICMP Ping Failed", response_time
                    
            except subprocess.TimeoutExpired:
                response_time = time.time() - start_time
                logger.warning(f"ICMP timeout for {service['name']}")
                return False, "ICMP Timeout", response_time
                
        except Exception as e:
            logger.error(f"Error checking ICMP service {service['name']}: {str(e)}")
            return False, f"Error: {str(e)}", 0

    def check_tcp_service(self, service: Dict) -> Tuple[bool, str, float]:
        """
        Check TCP port connectivity.
        
        Args:
            service: Service configuration dictionary
            
        Returns:
            Tuple of (is_available, status_message, response_time)
        """
        try:
            host = service['host']
            port = service.get('port', 80)
            timeout = service.get('timeout', 5)
            
            start_time = time.time()
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            try:
                result = sock.connect_ex((host, port))
                response_time = time.time() - start_time
                
                if result == 0:
                    logger.debug(f"TCP check passed for {service['name']} on port {port}")
                    return True, f"TCP Port {port} Open", response_time
                else:
                    logger.warning(f"TCP check failed for {service['name']} on port {port}")
                    return False, f"TCP Port {port} Closed", response_time
                    
            finally:
                sock.close()
                
        except socket.gaierror as e:
            logger.error(f"Hostname resolution error for {service['name']}: {str(e)}")
            return False, f"DNS Error: {str(e)}", 0
        except socket.timeout:
            logger.warning(f"TCP timeout for {service['name']}")
            return False, "TCP Timeout", 0
        except Exception as e:
            logger.error(f"Error checking TCP service {service['name']}: {str(e)}")
            return False, f"Error: {str(e)}", 0

    def check_service(self, service: Dict) -> Dict:
        """
        Check a service based on its protocol.
        
        Args:
            service: Service configuration dictionary
            
        Returns:
            Dictionary with check results
        """
        protocol = service['protocol'].lower()
        timestamp = datetime.now().isoformat()
        
        logger.info(f"Checking service: {service['name']} ({protocol})")
        
        if protocol in ['http', 'https']:
            is_available, status, response_time = self.check_http_service(service)
        elif protocol == 'icmp':
            is_available, status, response_time = self.check_icmp_service(service)
        elif protocol == 'tcp':
            is_available, status, response_time = self.check_tcp_service(service)
        else:
            logger.error(f"Unknown protocol: {protocol}")
            is_available, status, response_time = False, f"Unknown protocol: {protocol}", 0
        
        result = {
            'service_name': service['name'],
            'protocol': protocol,
            'host': service['host'],
            'port': service.get('port'),
            'timestamp': timestamp,
            'is_available': is_available,
            'status': status,
            'response_time': response_time
        }
        
        with self.lock:
            self.results[service['name']] = result
            self.historical_data[service['name']].append(result)
        
        return result

    def check_all_services(self) -> List[Dict]:
        """
        Check all configured services.
        
        Returns:
            List of check results
        """
        logger.info(f"Starting check of {len(self.services)} services")
        results = []
        
        for service in self.services:
            result = self.check_service(service)
            results.append(result)
        
        logger.info(f"Completed check of {len(self.services)} services")
        return results

    def check_services_threaded(self, num_threads: int = 5) -> List[Dict]:
        """
        Check all services using multiple threads for parallel execution.
        
        Args:
            num_threads: Number of worker threads
            
        Returns:
            List of check results
        """
        logger.info(f"Starting threaded check with {num_threads} threads")
        
        threads = []
        results = []
        
        def worker():
            while True:
                with self.lock:
                    if not self.services:
                        break
                    service = self.services.pop(0)
                
                result = self.check_service(service)
                results.append(result)
        
        services_copy = self.services.copy()
        self.services = services_copy
        
        for _ in range(min(num_threads, len(self.services))):
            thread = threading.Thread(target=worker, daemon=True)
            thread.start()
            threads.append(thread)
        
        for thread in threads:
            thread.join()
        
        return results

    def get_service_statistics(self, service_name: str, window_size: int = 100) -> Dict:
        """
        Calculate statistics for a service based on historical data.
        
        Args:
            service_name: Name of the service
            window_size: Number of recent checks to consider
            
        Returns:
            Dictionary with statistics
        """
        if service_name not in self.historical_data:
            logger.warning(f"No historical data for service: {service_name}")
            return {}
        
        history = self.historical_data[service_name][-window_size:]
        
        if not history:
            return {}
        
        response_times = [h['response_time'] for h in history if h['response_time'] > 0]
        availability_count = sum(1 for h in history if h['is_available'])
        
        stats = {
            'service_name': service_name,
            'total_checks': len(history),
            'available_count': availability_count,
            'unavailable_count': len(history) - availability_count,
            'availability_percentage': (availability_count / len(history)) * 100 if history else 0,
            'min_response_time': min(response_times) if response_times else 0,
            'max_response_time': max(response_times) if response_times else 0,
            'avg_response_time': statistics.mean(response_times) if response_times else 0,
            'median_response_time': statistics.median(response_times) if response_times else 0,
        }
        
        if len(response_times) > 1:
            stats['std_dev_response_time'] = statistics.stdev(response_times)
        else:
            stats['std_dev_response_time'] = 0
        
        return stats

    def get_all_statistics(self, window_size: int = 100) -> List[Dict]:
        """
        Get statistics for all services.
        
        Args:
            window_size: Number of recent checks to consider
            
        Returns:
            List of statistics dictionaries
        """
        stats_list = []
        
        for service in self.services:
            stats = self.get_service_statistics(service['name'], window_size)
            if stats:
                stats_list.append(stats)
        
        return stats_list

    def generate_report(self) -> str:
        """
        Generate a comprehensive status report.
        
        Returns:
            Formatted report string
        """
        report = []
        report.append("=" * 80)
        report.append(f"SERVICE UPTIME MONITOR REPORT - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("=" * 80)
        report.append("")
        
        if not self.results:
            report.append("No service checks have been performed yet.")
            return "\n".join(report)
        
        available_count = sum(1 for r in self.results.values() if r['is_available'])
        total_count = len(self.results)
        
        report.append(f"SUMMARY:")
        report.append(f"  Total Services: {total_count}")
        report.append(f"  Available: {available_count}")
        report.append(f"  Unavailable: {total_count - available_count}")
        report.append(f"  Overall Availability: {(available_count/total_count)*100:.2f}%")
        report.append("")
        
        report.append("DETAILED RESULTS:")
        report.append("-" * 80)
        
        for service_name, result in sorted(self.results.items()):
            status_icon = "✓" if result['is_available'] else "✗"
            report.append(f"{status_icon} {result['service_name']}")
            report.append(f"    Protocol: {result['protocol'].upper()}")
            report.append(f"    Host: {result['host']}")
            if result['port']:
                report.append(f"    Port: {result['port']}")
            report.append(f"    Status: {result['status']}")
            report.append(f"    Response Time: {result['response_time']:.3f}s")
            report.append(f"    Timestamp: {result['timestamp']}")
            report.append("")
        
        report.append("STATISTICS:")
        report.append("-" * 80