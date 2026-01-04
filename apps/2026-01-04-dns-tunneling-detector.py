import collections
import datetime
import json
import math
import os
import random
import re
import time
from collections import deque

# --- Configuration Section ---
# This dictionary holds all configurable parameters for the DNS tunneling detector.
# Adjust these values based on your network's typical traffic patterns and desired sensitivity.
DETECTOR_CONFIG = {
    "log_file_path": "simulated_dns_logs.jsonl",
    "simulated_log_entries": 5000,
    "tunnel_scenario_frequency": 0.02,  # Probability of generating a 'tunneled' entry (2%)
    "max_normal_hostname_length": 63, # RFC standard max length for a label, full name can be 255.
                                     # We'll use this for per-label anomaly detection.
    "max_total_hostname_length": 255, # Max total length for a domain name.
    "hostname_length_std_dev_threshold": 3.0, # How many standard deviations from average for length anomaly.
    "min_hostname_entropy_threshold": 3.5, # Below this, consider hostname low entropy (e.g., "aaaaa.com")
    "max_hostname_entropy_threshold": 4.5, # Above this, consider hostname high entropy (e.g., "randomchars.com")
                                          # DNS tunnels often use high entropy for data encoding.
    "request_frequency_window_seconds": 60, # Time window for checking request frequency (e.g., 60 seconds)
    "request_frequency_per_ip_threshold": 100, # Max requests from a single IP within the window.
    "request_frequency_per_domain_threshold": 150, # Max requests for a single domain within the window.
    "min_subdomains_for_anomaly": 5, # Minimum number of subdomains before flagging (e.g., a.b.c.d.example.com)
    "unusual_ttl_lower_bound": 30,  # TTLs below this might be suspicious (very short-lived DNS entries)
    "unusual_ttl_upper_bound": 86400 * 7, # TTLs above this (e.g., 7 days) are common, but very long ones might also be odd.
    "alert_cooldown_seconds_per_ip": 300, # Cooldown period before alerting again for the same IP.
    "alert_cooldown_seconds_per_domain": 600, # Cooldown period before alerting again for the same domain.
    "report_summary_at_end": True, # Whether to print a summary of all detected anomalies.
    "log_level": "INFO", # DEBUG, INFO, WARNING, ERROR - controls verbosity of internal logging.
}

# --- Standard DNS Constants ---
# A set of commonly observed DNS query types. Anything outside this could be suspicious.
STANDARD_DNS_QUERY_TYPES = {
    "A", "AAAA", "NS", "MD", "MF", "CNAME", "SOA", "MB", "MG", "MR", "NULL", "WKS",
    "PTR", "HINFO", "MINFO", "MX", "TXT", "RP", "AFSDB", "X25", "ISDN", "RT", "NSAP",
    "NSAP-PTR", "SIG", "KEY", "PX", "GPOS", "AAAA", "LOC", "NXT", "EID", "NIMLOC",
    "SRV", "ATMA", "NAPTR", "KX", "CERT", "A6", "DNAME", "SINK", "OPT", "APL", "DS",
    "SSHFP", "IPSECKEY", "RRSIG", "NSEC", "DKIM", "DHCID", "NSEC3", "NSEC3PARAM",
    "TLSA", "SMIMEA", "HIP", "CDS", "CDNSKEY", "OPENPGPKEY", "CSYNC", "ZONEMD",
    "SVCB", "HTTPS", "EUI48", "EUI64", "TKEY", "TSIG", "ANY", "URI", "CAA", "DNSKEY",
    "AXFR", "IXFR", "MAILA", "MAILB", "MB", "MG", "MR", "MW", "UINFO", "UID", "WINS",
    "WINS-R", "URI", "SPF", "AVC", "DMARC", "PTR", # PTR is common, often for reverse lookups
}

# --- Helper Functions ---

def _log_message(level, message, **kwargs):
    """Internal logging helper with different verbosity levels."""
    levels = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3}
    if levels.get(DETECTOR_CONFIG["log_level"], 1) <= levels.get(level, 1):
        extra_info = " ".join(f"{k}={v}" for k, v in kwargs.items())
        print(f"[{datetime.datetime.now().isoformat()}] [{level:<7}] {message} {extra_info}".strip())

def calculate_shannon_entropy(data):
    """
    Calculate the Shannon entropy of a string.
    High entropy can indicate random data, often used in DNS tunneling for data exfiltration.
    """
    if not data:
        return 0.0

    entropy = 0.0
    # Create a frequency map of characters
    char_counts = collections.Counter(data)
    total_chars = len(data)

    for char_count in char_counts.values():
        probability = char_count / total_chars
        entropy -= probability * math.log2(probability)
    return entropy

def is_valid_ipv4(ip_address):
    """Basic validation for an IPv4 address string."""
    pattern = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
    match = pattern.match(ip_address)
    if not match:
        return False
    for part in match.groups():
        if not 0 <= int(part) <= 255:
            return False
    return True

def parse_dns_log_entry(log_line):
    """
    Parses a single line from the simulated JSONL log file into a dictionary.
    Includes robust error handling for malformed lines.
    """
    try:
        entry = json.loads(log_line)
        # Validate essential fields
        if not all(k in entry for k in ["timestamp", "src_ip", "query_type", "query_name", "ttl"]):
            _log_message("WARNING", "Skipping malformed log entry: missing essential fields.", line=log_line[:100])
            return None

        # Convert timestamp to datetime object for easier comparison
        entry["timestamp"] = datetime.datetime.fromisoformat(entry["timestamp"].replace('Z', '+00:00'))

        # Ensure IP addresses are valid (optional, but good for robustness)
        if not is_valid_ipv4(entry.get("src_ip", "")):
            _log_message("WARNING", "Skipping log entry with invalid source IP.", src_ip=entry.get("src_ip"), line=log_line[:100])
            return None
        
        # Ensure query_name is a string and not empty
        if not isinstance(entry.get("query_name"), str) or not entry["query_name"]:
            _log_message("WARNING", "Skipping log entry with invalid or empty query name.", query_name=entry.get("query_name"), line=log_line[:100])
            return None

        # Normalize query_type to uppercase for consistent comparison
        entry["query_type"] = entry["query_type"].upper()

        return entry
    except json.JSONDecodeError:
        _log_message("ERROR", "Failed to decode JSON log entry.", line=log_line[:100])
        return None
    except ValueError as e:
        _log_message("ERROR", f"Error parsing log entry value: {e}", line=log_line[:100])
        return None
    except Exception as e:
        _log_message("ERROR", f"An unexpected error occurred parsing log entry: {e}", line=log_line[:100])
        return None

# --- Simulated Log Generation ---

def generate_simulated_dns_log(filename, num_entries, tunnel_frequency):
    """
    Generates a simulated DNS log file with a mix of normal and suspicious entries.
    This function aims to create a realistic-looking dataset for testing the detector.
    """
    _log_message("INFO", f"Generating simulated DNS log file: {filename} with {num_entries} entries...")

    # Predefined lists for normal traffic simulation
    common_domains = [
        "google.com", "facebook.com", "microsoft.com", "apple.com", "amazon.com",
        "wikipedia.org", "youtube.com", "twitter.com", "instagram.com", "linkedin.com",
        "example.com", "test.com", "blog.com", "news.com", "docs.com",
    ]
    subdomains = ["www", "mail", "api", "cdn", "blog", "dev", "status"]
    query_types = list(STANDARD_DNS_QUERY_TYPES) # Use standard types for normal traffic
    internal_ips = ["192.168.1." + str(i) for i in range(100, 200)]
    external_dns_servers = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"]

    # Generate legitimate IP responses for common domains
    domain_to_ip = {
        "google.com": ["142.250.190.14", "172.217.160.142"],
        "facebook.com": ["157.240.23.35", "31.13.79.35"],
        "microsoft.com": ["20.50.208.109", "40.78.7.67"],
        "apple.com": ["17.253.116.206", "17.253.116.202"],
        "amazon.com": ["205.251.242.103", "52.94.40.10"],
        "wikipedia.org": ["208.80.154.224"],
        "youtube.com": ["142.250.190.78"],
        "twitter.com": ["104.244.42.1"],
        "instagram.com": ["157.240.23.174"],
        "linkedin.com": ["108.174.10.10"],
        "example.com": ["93.184.216.34"],
        "test.com": ["185.199.108.153"],
        "blog.com": ["104.26.10.150"],
        "news.com": ["104.18.5.176"],
        "docs.com": ["13.107.42.14"]
    }

    # Tracking for tunneling scenarios
    tunnel_ips = {} # {ip: last_tunnel_time}
    tunnel_domains = {} # {domain: last_tunnel_time}

    with open(filename, 'w') as f:
        for i in range(num_entries):
            current_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=num_entries - i)
            src_ip = random.choice(internal_ips)
            dst_ip = random.choice(external_dns_servers)
            query_type = random.choice(query_types)
            ttl = random.randint(60, 86400) # Common TTL range (1 min to 24 hours)
            response_ip = []
            query_name = ""

            # Introduce different types of tunneling anomalies
            is_tunnel_scenario = random.random() < tunnel_frequency

            if is_tunnel_scenario:
                scenario_type = random.choice(["long_hostname", "high_entropy", "high_frequency", "non_standard_type", "many_subdomains", "low_ttl"])
                
                # Assign a consistent "malicious" source IP and domain for this scenario
                if src_ip not in tunnel_ips or (current_time - tunnel_ips[src_ip]).total_seconds() > DETECTOR_CONFIG["alert_cooldown_seconds_per_ip"] * 2:
                    tunnel_ips[src_ip] = current_time # Mark this IP as potentially malicious
                
                mal_domain_base = f"mal{random.randint(100, 999)}.example.net"
                if mal_domain_base not in tunnel_domains or (current_time - tunnel_domains[mal_domain_base]).total_seconds() > DETECTOR_CONFIG["alert_cooldown_seconds_per_domain"] * 2:
                    tunnel_domains[mal_domain_base] = current_time # Mark this domain as potentially malicious
                
                # Generate specific anomaly based on scenario_type
                if scenario_type == "long_hostname":
                    # Generate a very long hostname, often used to encode data
                    random_data = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=random.randint(30, 60)))
                    query_name = f"{random_data}.{mal_domain_base}"
                    ttl = random.randint(30, 300) # Tunnels often use shorter TTLs for faster updates
                    _log_message("DEBUG", "Generated long_hostname scenario", query_name=query_name)

                elif scenario_type == "high_entropy":
                    # Generate a high entropy subdomain
                    random_data = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=random.randint(15, 25)))
                    query_name = f"{random_data}.{random.choice(['data', 'c2'])}.{mal_domain_base}"
                    ttl = random.randint(30, 300)
                    _log_message("DEBUG", "Generated high_entropy scenario", query_name=query_name)

                elif scenario_type == "high_frequency":
                    # Simulate rapid fire requests from a specific IP for a specific domain
                    # We will reuse an IP and a domain frequently over a short period.
                    query_name = f"freq_data{random.randint(1,10)}.{mal_domain_base}"
                    src_ip = list(tunnel_ips.keys())[0] if tunnel_ips else random.choice(internal_ips) # Force reuse IP
                    ttl = random.randint(30, 120)
                    _log_message("DEBUG", "Generated high_frequency scenario", src_ip=src_ip, query_name=query_name)
                    # To ensure high frequency for detection, we can add a few more entries right after this one.
                    for _ in range(random.randint(5, 15)): # Inject multiple requests quickly
                        current_time_burst = current_time + datetime.timedelta(milliseconds=random.randint(10, 500))
                        f.write(json.dumps({
                            "timestamp": current_time_burst.isoformat().replace('+00:00', 'Z'),
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "query_type": "A",
                            "query_name": f"burst{random.randint(100,999)}.{query_name}", # Unique query names per burst
                            "response_ip": random.choice(domain_to_ip.get("example.com", ["1.2.3.4"])), # Placeholder
                            "ttl": random.randint(30, 120)
                        }) + "\n")

                elif scenario_type == "non_standard_type":
                    # Use an obscure or non-existent query type
                    query_type = random.choice(["AXFR_TUNNEL", "XFR_C2", "CUSTOM_Q", "INVALID_TYPE"])
                    query_name = f"secret.{mal_domain_base}"
                    ttl = random.randint(30, 600)
                    _log_message("DEBUG", "Generated non_standard_type scenario", query_type=query_type, query_name=query_name)

                elif scenario_type == "many_subdomains":
                    # Create a domain with an excessive number of subdomains
                    num_parts = random.randint(DETECTOR_CONFIG["min_subdomains_for_anomaly"] + 1, 15)
                    sub_parts = ['.'.join(random.choices('abcdefg', k=random.randint(3, 8))) for _ in range(num_parts)]
                    query_name = f"{'.'.join(sub_parts)}.{mal_domain_base}"
                    ttl = random.randint(60, 300)
                    _log_message("DEBUG", "Generated many_subdomains scenario", query_name=query_name)
                
                elif scenario_type == "low_ttl":
                    # Extremely low TTL values can be used to rapidly change records for tunneling
                    query_name = f"fastc2.{mal_domain_base}"
                    ttl = random.randint(1, DETECTOR_CONFIG["unusual_ttl_lower_bound"] - 1)
                    _log_message("DEBUG", "Generated low_ttl scenario", query_name=query_name, ttl=ttl)

                # For tunneling entries, response_ip might be null or a generic IP
                response_ip = random.choice(domain_to_ip.get(mal_domain_base.split('.')[-2:])) if query_type in ["A", "AAAA"] else []
                if not response_ip:
                    response_ip = [f"10.0.{random.randint(0,255)}.{random.randint(0,255)}"] if query_type in ["A", "AAAA"] else []
            else:
                # Normal traffic
                base_domain = random.choice(common_domains)
                subdomain_part = random.choice(subdomains + [""]) # Include no subdomain occasionally
                query_name = f"{subdomain_part}.{base_domain}" if subdomain_part else base_domain
                query_name = query_name.strip('.') # Clean up any accidental leading/trailing dots

                if query_type in ["A", "AAAA"]:
                    response_ip = domain_to_ip.get(base_domain, [f"1.2.3.{random.randint(1,254)}"])
                elif query_type == "MX":
                    response_ip = ["mail.example.com"]
                else:
                    response_ip = [] # No specific IP for non-A/AAAA records

            # Ensure query_name doesn't exceed total length limit (RFC 1035 specifies 255 octets)
            if len(query_name) > DETECTOR_CONFIG["max_total_hostname_length"]:
                query_name = query_name[:DETECTOR_CONFIG["max_total_hostname_length"] - len(mal_domain_base) - 1] + "." + mal_domain_base


            log_entry = {
                "timestamp": current_time.isoformat().replace('+00:00', 'Z'),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "query_type": query_type,
                "query_name": query_name,
                "response_ip": response_ip,
                "ttl": ttl
            }
            f.write(json.dumps(log_entry) + "\n")
    _log_message("INFO", f"Simulated DNS log generation complete. Total entries: {num_entries}")


# --- Main Detector Class ---

class DnsTunnelingDetector:
    """
    A comprehensive class for detecting DNS tunneling based on various heuristics
    derived from DNS log analysis.
    """

    def __init__(self, config):
        """
        Initializes the DNS tunneling detector with provided configuration and
        sets up internal state variables for tracking metrics.
        """
        self.config = config
        self.anomalies_detected = [] # Stores all detected anomalies
        self.last_alert_time_ip = {} # Tracks last alert time per IP for cooldown
        self.last_alert_time_domain = {} # Tracks last alert time per domain for cooldown

        # --- State for Hostname Length & Entropy ---
        # Stores hostname lengths for statistical analysis (e.g., mean, std dev)
        # Using a deque to keep a sliding window of recent hostname lengths for dynamic baseline.
        self.hostname_lengths_history = deque(maxlen=10000) # Recent 10,000 hostnames
        self.current_hostname_len_sum = 0
        self.current_hostname_len_sum_sq = 0
        self.hostname_avg_length = 0.0
        self.hostname_std_dev_length = 0.0

        # --- State for Request Frequency ---
        # Stores (timestamp, count) for each IP and domain within the sliding window
        # deque of (timestamp, count) tuples for efficient windowing.
        self.ip_request_history = collections.defaultdict(lambda: deque()) # {ip: deque([(timestamp, count), ...])}
        self.domain_request_history = collections.defaultdict(lambda: deque()) # {domain: deque([(timestamp, count), ...])}

        # --- State for Query Types ---
        self.query_type_counts = collections.defaultdict(int) # Global count of each query type

        # --- State for TTL Analysis ---
        # No specific history needed for TTL, just checking against static bounds for now.

        _log_message("INFO", "DNS Tunneling Detector initialized with config:", config=self.config)

    def _update_hostname_stats(self, hostname):
        """
        Updates the running statistics for hostname length (average and standard deviation).
        Uses a fixed-size deque to maintain a window of recent hostnames.
        """
        length = len(hostname)

        # Remove oldest entry if deque is full
        if len(self.hostname_lengths_history) == self.hostname_lengths_history.maxlen:
            old_length = self.hostname_lengths_history.popleft()
            self.current_hostname_len_sum -= old_length
            self.current_hostname_len_sum_sq -= (old_length ** 2)
        
        # Add new entry
        self.hostname_lengths_history.append(length)
        self.current_hostname_len_sum += length
        self.current_hostname_len_sum_sq += (length ** 2)

        n = len(self.hostname_lengths_history)
        if n > 0:
            self.hostname_avg_length = self.current_hostname_len_sum / n
            if n > 1:
                variance = (self.current_hostname_len_sum_sq - (self.current_hostname_len_sum ** 2) / n) / (n - 1)
                self.hostname_std_dev_length = math.sqrt(max(0, variance)) # Ensure non-negative for sqrt
            else:
                self.hostname_std_dev_length = 0.0
        else:
            self.hostname_avg_length = 0.0
            self.hostname_std_dev_length = 0.0
        
        _log_message("DEBUG", f"Hostname stats updated: Avg={self.hostname_avg_length:.2f}, StdDev={self.hostname_std_dev_length:.2f}, Count={n}")


    def _check_hostname_length(self, hostname, entry_timestamp, src_ip, query_type):
        """
        Checks for unusually long hostnames, a common indicator of DNS tunneling.
        Compares against both fixed maximums and a dynamic statistical baseline.
        """
        current_length = len(hostname)
        anomaly_detected = False
        reason = []

        # Check against absolute maximums
        if current_length > self.config["max_total_hostname_length"]:
            reason.append(f"Excessive total length ({current_length} > {self.config['max_total_hostname_length']})")
            anomaly_detected = True
        
        # Check individual labels (parts between dots)
        labels = hostname.split('.')
        for label in labels:
            if len(label) > self.config["max_normal_hostname_length"]:
                reason.append(f"Excessive label length ('{label}' len {len(label)} > {self.config['max_normal_hostname_length']})")
                anomaly_detected = True
                break
        
        # Check against statistical baseline if enough data points exist
        if len(self.hostname_lengths_history) > 50 and self.hostname_std_dev_length > 0:
            deviation = (current_length - self.hostname_avg_length) / self.hostname_std_dev_length
            if deviation > self.config["hostname_length_std_dev_threshold"]:
                reason.append(f"Statistically anomalous length (current={current_length:.0f}, avg={self.hostname_avg_length:.0f}, std_dev={self.hostname_std_dev_length:.2f}, deviation={deviation:.2f} > {self.config['hostname_length_std_dev_threshold']})")
                anomaly_detected = True
        
        if anomaly_detected:
            self._report_anomaly(
                "Hostname Length Anomaly",
                f"Hostname '{hostname}' has unusually long segments or total length. {' '.join(reason)}",
                entry_timestamp, src_ip, hostname, query_type, severity="HIGH"
            )

    def _check_hostname_entropy(self, hostname, entry_timestamp, src_ip, query_type):
        """
        Calculates Shannon entropy for the hostname and its subdomains.
        High entropy can indicate randomly generated data, a hallmark of data exfiltration
        via DNS tunneling. Low entropy might indicate specific patterns.
        """
        domain_parts = hostname.split('.')
        # Exclude Top-Level Domain (TLD) and potentially the Second-Level Domain (SLD) if it's common (e.g., example.com)
        # For simplicity, we'll check the full hostname and then subdomains if present.
        
        full_entropy = calculate_shannon_entropy(hostname)
        
        anomaly_detected = False
        reason = []

        if full_entropy > self.config["max_hostname_entropy_threshold"]:
            reason.append(f"High entropy ({full_entropy:.2f} > {self.config['max_hostname_entropy_threshold']})")
            anomaly_detected = True
        elif full_entropy < self.config["min_hostname_entropy_threshold"] and len(hostname) > 10: # Only flag low entropy for longer hostnames
            reason.append(f"Low entropy ({full_entropy:.2f} < {self.config['min_hostname_entropy_threshold']})")
            anomaly_detected = True

        # Also check entropy of specific subdomains, which are often used for encoding.
        if len(domain_parts) > 2: # Check only if there are subdomains to analyze
            # Focus on the most 'left-hand' part which often contains encoded data
            subdomain_to_check = domain_parts[0]
            if len(subdomain_to_check) > 5: # Only check if subdomain is long enough to be meaningful
                subdomain_entropy = calculate_shannon_entropy(subdomain_to_check)
                if subdomain_entropy > self.config["max_hostname_entropy_threshold"]:
                    reason.append(f"High entropy in subdomain '{subdomain_to_check}' ({subdomain_entropy:.2f} > {self.config['max_hostname_entropy_threshold']})")
                    anomaly_detected = True
                elif subdomain_entropy < self.config["min_hostname_entropy_threshold"]:
                    reason.append(f"Low entropy in subdomain '{subdomain_to_check}' ({subdomain_entropy:.2f} < {self.config['min_hostname_entropy_threshold']})")
                    anomaly_detected = True


        if anomaly_detected:
            self._report_anomaly(
                "Hostname Entropy Anomaly",
                f"Hostname '{hostname}' exhibits unusual entropy. {' '.join(reason)}",
                entry_timestamp, src_ip, hostname, query_type, severity="MEDIUM"
            )


    def _update_request_frequency(self, ip_address, domain, timestamp):
        """
        Updates the request history for a given IP and domain, maintaining a sliding window.
        """
        # Update IP request history
        ip_history = self.ip_request_history[ip_address]
        ip_history.append(timestamp)
        # Remove old entries outside the window
        while ip_history and (timestamp - ip_history[0]).total_seconds() > self.config["request_frequency_window_seconds"]:
            ip_history.popleft()

        # Update domain request history
        domain_history = self.domain_request_history[domain]
        domain_history.append(timestamp)
        # Remove old entries outside the window
        while domain_history and (timestamp - domain_history[0]).total_seconds() > self.config["request_frequency_window_seconds"]:
            domain_history.popleft()
        
        _log_message("DEBUG", "Frequency history updated", ip=ip_address, domain=domain, ip_count=len(ip_history), domain_count=len(domain_history))


    def _check_request_frequency(self, ip_address, domain, entry_timestamp, query_type):
        """
        Checks for abnormally high request frequencies from an IP or to a domain.
        """
        # Check IP frequency
        ip_count = len(self.ip_request_history[ip_address])
        if ip_count > self.config["request_frequency_per_ip_threshold"]:
            self._report_anomaly(
                "IP Request Frequency Anomaly",
                f"IP '{ip_address}' made {ip_count} requests in {self.config['request_frequency_window_seconds']}s (Threshold: {self.config['request_frequency_per_ip_threshold']})",
                entry_timestamp, ip_address, domain, query_type, severity="HIGH",
                cooldown_key=ip_address, cooldown_type="ip"
            )

        # Check Domain frequency
        domain_count = len(self.domain_request_history[domain])
        if domain_count > self.config["request_frequency_per_domain_threshold"]:
            self._report_anomaly(
                "Domain Request Frequency Anomaly",
                f"Domain '{domain}' received {domain_count} requests in {self.config['request_frequency_window_seconds']}s (Threshold: {self.config['request_frequency_per_domain_threshold']})",
                entry_timestamp, ip_address, domain, query_type, severity="MEDIUM",
                cooldown_key=domain, cooldown_type="domain"
            )


    def _check_query_type(self, query_type, entry_timestamp, src_ip, hostname):
        """
        Checks if the DNS query type is standard or known.
        Non-standard types are often used in DNS tunneling to bypass filters.
        """
        self.query_type_counts[query_type] += 1 # Update global count for general statistics
        
        if query_type not in STANDARD_DNS_QUERY_TYPES:
            self._report_anomaly(
                "Non-Standard Query Type Anomaly",
                f"Unusual DNS query type '{query_type}' detected for hostname '{hostname}'",
                entry_timestamp, src_ip, hostname, query_type, severity="HIGH"
            )

    def _check_num_subdomains(self, hostname, entry_timestamp, src_ip, query_type):
        """
        Checks for an unusually high number of subdomains, which can be used
        to encode more data in a DNS tunnel.
        """
        # Basic split by dot, remove empty strings from consecutive dots or leading/trailing
        parts = [p for p in hostname.split('.') if p] 
        num_subdomains = len(parts) - 1 # example.com -> parts ['example', 'com'], num_subdomains = 1
                                       # a.b.example.com -> parts ['a', 'b', 'example', 'com'], num_subdomains = 3

        if num_subdomains >= self.config["min_subdomains_for_anomaly"]:
            self._report_anomaly(
                "Excessive Subdomain Count Anomaly",
                f"Hostname '{hostname}' has {num_subdomains} subdomains (Threshold: {self.config['min_subdomains_for_anomaly']}). Potential data encoding.",
                entry_timestamp, src_ip, hostname, query_type, severity="MEDIUM"
            )

    def _check_unusual_ttl(self, ttl, entry_timestamp, src_ip, hostname, query_type):
        """
        Checks for unusually low or high TTL values. Very low TTLs can enable rapid
        changes in C2 infrastructure.
        """
        if ttl < self.config["unusual_ttl_lower_bound"]:
            self._report_anomaly(
                "Unusually Low TTL Anomaly",
                f"DNS query for '{hostname}' has a very low TTL ({ttl}s). May indicate dynamic C2.",
                entry_timestamp, src_ip, hostname, query_type, severity="MEDIUM"
            )
        elif ttl > self.config["unusual_ttl_upper_bound"]:
             self._report_anomaly(
                "Unusually High TTL Anomaly",
                f"DNS query for '{hostname}' has a very high TTL ({ttl}s). Less common, but could indicate static C2 or attempt to evade detection (less frequent queries).",
                entry_timestamp, src_ip, hostname, query_type, severity="LOW"
            )


    def _report_anomaly(self, anomaly_type, message, timestamp, src_ip, hostname, query_type, severity="INFO", cooldown_key=None, cooldown_type=None):
        """
        Records an anomaly, applying a cooldown period to prevent excessive alerts
        for recurring issues from the same source.
        """
        current_time = datetime.datetime.now(datetime.timezone.utc)
        alert_suppressed = False

        if cooldown_key and cooldown_type:
            cooldown_period = datetime.timedelta(seconds=self.config[f"alert_cooldown_seconds_per_{cooldown_type}"])
            
            if cooldown_type == "ip":
                last_alert = self.last_alert_time_ip.get(cooldown_key)
                if last_alert and (current_time - last_alert) < cooldown_period:
                    alert_suppressed = True
                else:
                    self.last_alert_time_ip[cooldown_key] = current_time
            
            elif cooldown_type == "domain":
                last_alert = self.last_alert_time_domain.get(cooldown_key)
                if last_alert and (current_time - last_alert) < cooldown_period:
                    alert_suppressed = True
                else:
                    self.last_alert_time_domain[cooldown_key] = current_time

        if not alert_suppressed:
            anomaly_record = {
                "timestamp": timestamp.isoformat(),
                "detection_time": current_time.isoformat(),
                "anomaly_type": anomaly_type,
                "src_ip": src_ip,
                "query_name": hostname,
                "query_type": query_type,
                "message": message,
                "severity": severity
            }
            self.anomalies_detected.append(anomaly_record)
            _log_message("WARNING", f"!!! ANOMALY DETECTED [{severity}] !!! {message}",
                         timestamp=timestamp.isoformat(), src_ip=src_ip, hostname=hostname, query_type=query_type, anomaly_type=anomaly_type)
        else:
            _log_message("DEBUG", f"Anomaly alert suppressed due to cooldown for {cooldown_type}: {cooldown_key}",
                         anomaly_type=anomaly_type, message=message[:50])


    def analyze_dns_entry(self, log_entry):
        """
        Processes a single DNS log entry, applying all configured detection heuristics.
        This is the core logic for real-time or batch analysis.
        """
        if not log_entry:
            _log_message("DEBUG", "Skipping empty log entry.")
            return

        timestamp = log_entry["timestamp"]
        src_ip = log_entry["src_ip"]
        query_type = log_entry["query_type"]
        query_name = log_entry["query_name"].lower() # Normalize to lowercase for consistent analysis
        ttl = log_entry["ttl"]

        _log_message("DEBUG", "Analyzing entry", timestamp=timestamp.isoformat(), src_ip=src_ip, query_name=query_name, query_type=query_type)

        # 1. Hostname Length and Label Length Checks
        self._update_hostname_stats(query_name) # Always update stats for baseline
        self._check_hostname_length(query_name, timestamp, src_ip, query_type)

        # 2. Hostname Entropy Check
        self._check_hostname_entropy(query_name, timestamp, src_ip, query_type)

        # 3. Request Frequency Checks (per IP and per Domain)
        self._update_request_frequency(src_ip, query_name, timestamp) # Update history before checking
        self._check_request_frequency(src_ip, query_name, timestamp, query_type)

        # 4. Non-Standard Query Type Check
        self._check_query_type(query_type, timestamp, src_ip, query_name)

        # 5. Excessive Subdomain Count Check
        self._check_num_subdomains(query_name, timestamp, src_ip, query_type)

        # 6. Unusual TTL Check
        self._check_unusual_ttl(ttl, timestamp, src_ip, query_name, query_type)

    def report_summary(self):
        """
        Prints a summary of all detected anomalies and overall statistics.
        """
        _log_message("INFO", "\n--- DNS Tunneling Detection Summary ---")
        if not self.anomalies_detected:
            _log_message("INFO", "No DNS tunneling anomalies were detected.")
            return

        _log_message("INFO", f"Total anomalies detected: {len(self.anomalies_detected)}")
        
        # Group anomalies by type
        anomaly_type_counts = collections.Counter(a["anomaly_type"] for a in self.anomalies_detected)
        _log_message("INFO", "\nAnomaly Type Counts:")
        for anomaly_type, count in anomaly_type_counts.most_common():
            _log_message("INFO", f"- {anomaly_type}: {count}")

        _log_message("INFO", "\nTop 10 IPs with anomalies:")
        ip_anomaly_counts = collections.Counter(a["src_ip"] for a in self.anomalies_detected)
        for ip, count in ip_anomaly_counts.most_common(10):
            _log_message("INFO", f"- {ip}: {count} anomalies")

        _log_message("INFO", "\nTop 10 Query Names with anomalies:")
        domain_anomaly_counts = collections.Counter(a["query_name"] for a in self.anomalies_detected)
        for domain, count in domain_anomaly_counts.most_common(10):
            _log_message("INFO", f"- {domain}: {count} anomalies")

        _log_message("INFO", "\nRecent Anomalies (last 5, if any):")
        for anomaly in self.anomalies_detected[-5:]:
            _log_message("INFO", f"  [{anomaly['severity']}] {anomaly['anomaly_type']} from {anomaly['src_ip']} for {anomaly['query_name']} at {anomaly['timestamp']}",
                         message=anomaly['message'])

        _log_message("INFO", "\n--- End of Summary ---")

    def reset_state(self):
        """
        Resets the internal state of the detector. Useful if processing multiple
        log files or time batches independently.
        """
        _log_message("INFO", "Resetting detector state...")
        self.anomalies_detected = []
        self.last_alert_time_ip = {}
        self.last_alert_time_domain = {}
        self.hostname_lengths_history.clear()
        self.current_hostname_len_sum = 0
        self.current_hostname_len_sum_sq = 0
        self.hostname_avg_length = 0.0
        self.hostname_std_dev_length = 0.0
        self.ip_request_history.clear()
        self.domain_request_history.clear()
        self.query_type_counts.clear()
        _log_message("INFO", "Detector state reset successfully.")

# --- Main Execution Block ---

def main():
    """
    Main function to orchestrate the log generation, detection, and reporting.
    """
    _log_message("INFO", "Starting DNS Tunneling Detector Script...")

    # Configure the detector (can be overridden by command-line args or environment vars)
    detector_config = DETECTOR_CONFIG
    
    # 1. Generate a simulated log file for demonstration
    try:
        generate_simulated_dns_log(
            detector_config["log_file_path"],
            detector_config["simulated_log_entries"],
            detector_config["tunnel_scenario_frequency"]
        )
        _log_message("INFO", f"Simulated log file '{detector_config['log_file_path']}' created.")
    except IOError as e:
        _log_message("ERROR", f"Failed to generate simulated log file: {e}. Exiting.", path=detector_config['log_file_path'])
        return
    except Exception as e:
        _log_message("ERROR", f"An unexpected error occurred during log generation: {e}. Exiting.")
        return

    # 2. Initialize the DNS Tunneling Detector
    detector = DnsTunnelingDetector(detector_config)

    # 3. Process the simulated log file
    _log_message("INFO", f"Starting analysis of log file: {detector_config['log_file_path']}")
    processed_entries = 0
    start_time = time.time()

    try:
        with open(detector_config["log_file_path"], 'r') as f:
            for line_num, line in enumerate(f, 1):
                log_entry = parse_dns_log_entry(line)
                if log_entry:
                    detector.analyze_dns_entry(log_entry)
                    processed_entries += 1
                
                # Provide progress updates for large files
                if processed_entries > 0 and processed_entries % 1000 == 0:
                    _log_message("INFO", f"Processed {processed_entries} entries...")
    except FileNotFoundError:
        _log_message("ERROR", f"Log file not found: {detector_config['log_file_path']}. Please ensure it exists.", path=detector_config['log_file_path'])
        return
    except IOError as e:
        _log_message("ERROR", f"Error reading log file '{detector_config['log_file_path']}': {e}. Exiting.", path=detector_config['log_file_path'])
        return
    except Exception as e:
        _log_message("ERROR", f"An unexpected error occurred during log file processing: {e}", line_number=line_num, line=line.strip())
        return

    end_time = time.time()
    _log_message("INFO", f"Finished analyzing {processed_entries} entries in {end_time - start_time:.2f} seconds.")

    # 4. Report a summary of all detected anomalies
    if detector_config["report_summary_at_end"]:
        detector.report_summary()

    # 5. Clean up the simulated log file
    try:
        os.remove(detector_config["log_file_path"])
        _log_message("INFO", f"Cleaned up simulated log file: {detector_config['log_file_path']}")
    except OSError as e:
        _log_message("WARNING", f"Could not remove simulated log file '{detector_config['log_file_path']}': {e}", path=detector_config['log_file_path'])
    
    _log_message("INFO", "DNS Tunneling Detector Script finished.")

if __name__ == "__main__":
    main()