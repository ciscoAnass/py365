import sys
import argparse
import re
import ipaddress
import enum
import shlex
import json
from typing import List, Optional, Union, Set, Dict, Any

# --- Configuration and Utility Globals/Functions ---

# shlex.split for robust argument parsing, especially for comments with spaces
shlex_split = shlex.split

# Global debug flag (can be set via command line in a real application)
_DEBUG_MODE = False

def _log_info(message: str):
    """Logs an informational message to stderr."""
    print(f"[INFO] {message}", file=sys.stderr)

def _log_warning(message: str):
    """Logs a warning message to stderr."""
    print(f"[WARNING] {message}", file=sys.stderr)

def _log_error(message: str):
    """Logs an error message to stderr."""
    print(f"[ERROR] {message}", file=sys.stderr)

def _log_debug(message: str):
    """Logs a debug message to stderr if _DEBUG_MODE is True."""
    if _DEBUG_MODE:
        print(f"[DEBUG] {message}", file=sys.stderr)


# --- Enumerations ---

class RiskLevel(enum.Enum):
    """Enumeration for different levels of security risk."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    def __str__(self):
        return self.value

class ProtocolType(enum.Enum):
    """Enumeration for common network protocols."""
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ALL = "all"
    OTHER = "other" # For less common or custom protocols

    @classmethod
    def from_str(cls, s: str):
        """Converts a string to a ProtocolType enum member."""
        s_lower = s.lower()
        if s_lower == "tcp":
            return cls.TCP
        elif s_lower == "udp":
            return cls.UDP
        elif s_lower == "icmp":
            return cls.ICMP
        elif s_lower == "all" or s_lower == "0": # '0' often means all protocols in iptables
            return cls.ALL
        else:
            return cls.OTHER


class TargetAction(enum.Enum):
    """Enumeration for iptables rule targets/actions."""
    ACCEPT = "ACCEPT"
    DROP = "DROP"
    REJECT = "REJECT"
    RETURN = "RETURN"
    JUMP = "JUMP" # Jumps to another chain (e.g., JUMP LOG, JUMP USER_CHAIN)
    OTHER = "OTHER" # For custom targets or user-defined chains (when used as a jump target)

    @classmethod
    def from_str(cls, s: str):
        """Converts a string to a TargetAction enum member."""
        s_upper = s.upper()
        if s_upper == "ACCEPT":
            return cls.ACCEPT
        elif s_upper == "DROP":
            return cls.DROP
        elif s_upper == "REJECT":
            return cls.REJECT
        elif s_upper == "RETURN":
            return cls.RETURN
        elif s_upper in ["LOG", "DNAT", "SNAT", "MASQUERADE", "REDIRECT", "TPROXY"]: # Common built-in extensions
            return cls.JUMP # These are technically extensions/jumps
        elif s_upper in ["INPUT", "OUTPUT", "FORWARD", "PREROUTING", "POSTROUTING", "SECURITY", "MANGLE", "NAT", "RAW", "FILTER"]:
            # These are built-in chains, if a rule targets one of these, it's a jump, not a final action
            return cls.JUMP
        else:
            return cls.OTHER # Could be a user-defined chain to jump to


# --- Data Models ---

class FirewallRule:
    """
    Represents a parsed iptables firewall rule or a chain's default policy.
    This class is designed to hold all relevant attributes extracted from an iptables-save line,
    making it easier to apply policy checks.
    """
    def __init__(self,
                 original_line: str,
                 is_default_policy: bool = False,
                 chain: Optional[str] = None,
                 target: Optional[TargetAction] = None,
                 protocol: Optional[ProtocolType] = None,
                 source: Optional[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = None,
                 destination: Optional[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = None,
                 source_ports: Optional[Set[Union[int, str]]] = None,
                 destination_ports: Optional[Set[Union[int, str]]] = None,
                 in_interface: Optional[str] = None,
                 out_interface: Optional[str] = None,
                 state: Optional[Set[str]] = None, # e.g., {'NEW', 'ESTABLISHED'}
                 comment: Optional[str] = None,
                 match_modules: Optional[Dict[str, Any]] = None, # Stores data from -m modules
                 policy_bytes: Optional[int] = None, # For default policies like :INPUT ACCEPT [0:0]
                 policy_packets: Optional[int] = None, # For default policies
                 jump_target_chain: Optional[str] = None # Stores the name of the chain to jump to if target is JUMP
                 ):
        self.original_line = original_line
        self.is_default_policy = is_default_policy
        self.chain = chain
        self.target = target
        self.protocol = protocol
        self.source = source
        self.destination = destination
        self.source_ports = source_ports if source_ports is not None else set()
        self.destination_ports = destination_ports if destination_ports is not None else set()
        self.in_interface = in_interface
        self.out_interface = out_interface
        self.state = state if state is not None else set()
        self.comment = comment
        self.match_modules = match_modules if match_modules is not None else {}
        self.policy_bytes = policy_bytes
        self.policy_packets = policy_packets
        self.jump_target_chain = jump_target_chain

    def __str__(self):
        """Provides a human-readable representation of the rule."""
        if self.is_default_policy:
            return (f"[DEFAULT POLICY] Chain: {self.chain}, Policy: {self.target.value}, "
                    f"Bytes: {self.policy_bytes}, Packets: {self.policy_packets}")
        else:
            parts = [f"Chain: {self.chain}", f"Target: {self.target.value}"]
            if self.protocol:
                parts.append(f"Proto: {self.protocol.value}")
            if self.source:
                parts.append(f"Src: {self.source}")
            if self.destination:
                parts.append(f"Dst: {self.destination}")
            if self.source_ports:
                parts.append(f"SPort: {','.join(map(str, sorted(list(self.source_ports))))}")
            if self.destination_ports:
                parts.append(f"DPort: {','.join(map(str, sorted(list(self.destination_ports))))}")
            if self.in_interface:
                parts.append(f"In: {self.in_interface}")
            if self.out_interface:
                parts.append(f"Out: {self.out_interface}")
            if self.state:
                parts.append(f"State: {','.join(self.state)}")
            if self.comment:
                parts.append(f"Comment: '{self.comment}'")
            if self.jump_target_chain:
                parts.append(f"Jump To: {self.jump_target_chain}")
            if self.match_modules:
                match_str = ", ".join([f"{m}:{v}" for m, v in self.match_modules.items()])
                parts.append(f"Matches: {{{match_str}}}")
            return f"[{' | '.join(parts)}]"


class PolicyConfiguration:
    """
    Defines the security policy parameters against which firewall rules are validated.
    This class can be initialized with defaults or loaded from a JSON configuration.
    """
    def __init__(self,
                 sensitive_tcp_ports: Optional[Set[int]] = None,
                 sensitive_udp_ports: Optional[Set[int]] = None,
                 internet_sources: Optional[List[str]] = None, # List of CIDR strings
                 allow_any_any_is_risky: bool = True,
                 expose_sensitive_ports_is_risky: bool = True,
                 default_allow_policy_is_risky: bool = True,
                 unrestricted_output_is_risky: bool = True,
                 unrestricted_forward_is_risky: bool = True,
                 log_info_findings: bool = False,
                 warn_on_non_numeric_ports: bool = True
                 ):
        self.sensitive_tcp_ports = sensitive_tcp_ports if sensitive_tcp_ports is not None else self._get_default_sensitive_tcp_ports()
        self.sensitive_udp_ports = sensitive_udp_ports if sensitive_udp_ports is not None else self._get_default_sensitive_udp_ports()
        
        # Parse internet_sources into ipaddress.IpNetwork objects for efficient checking
        self.internet_sources_networks: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
        for src in (internet_sources if internet_sources is not None else self._get_default_internet_sources()):
            try:
                self.internet_sources_networks.append(ipaddress.ip_network(src, strict=False))
            except ValueError:
                _log_error(f"Invalid internet source definition in policy: '{src}' -- skipping.")
        
        self.allow_any_any_is_risky = allow_any_any_is_risky
        self.expose_sensitive_ports_is_risky = expose_sensitive_ports_is_risky
        self.default_allow_policy_is_risky = default_allow_policy_is_risky
        self.unrestricted_output_is_risky = unrestricted_output_is_risky
        self.unrestricted_forward_is_risky = unrestricted_forward_is_risky
        self.log_info_findings = log_info_findings
        self.warn_on_non_numeric_ports = warn_on_non_numeric_ports

    def _get_default_sensitive_tcp_ports(self) -> Set[int]:
        """Returns a default set of TCP ports commonly considered sensitive."""
        return {
            20, 21,  # FTP
            22,      # SSH
            23,      # Telnet
            25,      # SMTP
            53,      # DNS (TCP for zone transfers/large responses)
            80,      # HTTP (often managed by other layers, but still exposed)
            110,     # POP3
            135,     # MS RPC
            139, 445, # NetBIOS, SMB (Windows shares)
            143,     # IMAP
            3389,    # RDP (Remote Desktop Protocol)
            5900,    # VNC
            8000, 8080, 8443, # Common web proxies/alt HTTP(S) ports
            27017,   # MongoDB
            5432,    # PostgreSQL
            3306,    # MySQL
            1521,    # Oracle DB listener
            6379,    # Redis
            5000,    # UPnP, SIP
            5060, 5061 # SIP (Session Initiation Protocol)
        }

    def _get_default_sensitive_udp_ports(self) -> Set[int]:
        """Returns a default set of UDP ports commonly considered sensitive."""
        return {
            53,      # DNS
            67, 68,  # DHCP
            69,      # TFTP
            161, 162, # SNMP
            389,     # LDAP UDP
            137, 138, # NetBIOS UDP
            500,     # IKE (IPsec Key Exchange)
            1645, 1646, # RADIUS authentication/accounting
            3478, 3479, # STUN/TURN (VoIP/WebRTC NAT traversal)
        }

    def _get_default_internet_sources(self) -> List[str]:
        """Returns a default list of IP networks considered 'internet' or 'anywhere'."""
        return ["0.0.0.0/0", "::/0"]


class Finding:
    """
    Represents a security finding or violation identified by the validator.
    Each finding includes a risk level, message, type, and a reference to the rule.
    """
    def __init__(self,
                 risk_level: RiskLevel,
                 message: str,
                 finding_type: str,
                 rule: Optional[FirewallRule] = None,
                 details: Optional[Dict[str, Any]] = None
                 ):
        self.risk_level = risk_level
        self.message = message
        self.finding_type = finding_type
        self.rule = rule
        self.details = details if details is not None else {}

    def __str__(self):
        """Provides a human-readable string for the finding."""
        rule_info = ""
        if self.rule:
            rule_info = (f"\n  Chain: {self.rule.chain}"
                         f"\n  Original Rule: '{self.rule.original_line}'")
        
        details_info = ""
        if self.details:
            details_info = f"\n  Details: {json.dumps(self.details, indent=2)}" # Pretty print details

        return (f"[{self.risk_level.value}] {self.finding_type}:\n"
                f"  Message: {self.message}{details_info}{rule_info}")


# --- Utility Functions for Parsing and Checking ---

def _parse_ports(port_str: str, protocol: ProtocolType, policy: PolicyConfiguration) -> Set[Union[int, str]]:
    """
    Parses a port string (e.g., "22", "80:90", "1024-65535") into a set of individual ports.
    Handles single ports, ranges, and comma-separated lists.
    If a port is non-numeric (e.g., 'http'), it's kept as a string.
    """
    ports_set = set()
    if not port_str:
        return ports_set

    port_segments = port_str.split(',')
    for segment in port_segments:
        segment = segment.strip()
        if ':' in segment: # iptables format for range "start:end"
            try:
                start, end = map(int, segment.split(':'))
                if start > end: # Handle inverted ranges, though rare in iptables
                    start, end = end, start
                ports_set.update(range(start, end + 1))
            except ValueError:
                if policy.warn_on_non_numeric_ports:
                    _log_warning(f"Non-numeric port range segment '{segment}' for protocol {protocol.value}. Adding as string.")
                ports_set.add(segment)
        elif '-' in segment: # common alternative for range "start-end"
            try:
                start, end = map(int, segment.split('-'))
                if start > end: # Handle inverted ranges
                    start, end = end, start
                ports_set.update(range(start, end + 1))
            except ValueError:
                if policy.warn_on_non_numeric_ports:
                    _log_warning(f"Non-numeric port range segment '{segment}' for protocol {protocol.value}. Adding as string.")
                ports_set.add(segment)
        else:
            try:
                ports_set.add(int(segment))
            except ValueError:
                if policy.warn_on_non_numeric_ports:
                    _log_warning(f"Non-numeric port name '{segment}' for protocol {protocol.value}. Adding as string.")
                ports_set.add(segment) # Keep non-numeric port names (e.g., 'http', 'ssh') as strings
    return ports_set

def _is_internet_source(network: Union[ipaddress.IPv4Network, ipaddress.IPv6Network], policy: PolicyConfiguration) -> bool:
    """
    Checks if a given IP network represents an 'internet' source (any IP globally routable).
    This function considers private IP ranges to NOT be 'internet' sources unless explicitly
    part of an 'any' range like 0.0.0.0/0.
    """
    if network.is_unspecified or network.is_multicast or network.is_loopback:
        return False # '0.0.0.0/0' will be handled by policy.internet_sources_networks
    
    # Check if the network overlaps with any of the defined 'internet' networks in policy
    for internet_network in policy.internet_sources_networks:
        if network.overlaps(internet_network):
            return True
    return False

def _is_sensitive_port(ports: Set[Union[int, str]], protocol: ProtocolType, policy: PolicyConfiguration) -> bool:
    """
    Checks if any of the given ports are considered sensitive for the specified protocol.
    Handles both numeric and named ports.
    """
    if not ports:
        return False

    for port_val in ports:
        if isinstance(port_val, int):
            if protocol == ProtocolType.TCP and port_val in policy.sensitive_tcp_ports:
                _log_debug(f"Numeric sensitive TCP port found: {port_val}")
                return True
            if protocol == ProtocolType.UDP and port_val in policy.sensitive_udp_ports:
                _log_debug(f"Numeric sensitive UDP port found: {port_val}")
                return True
        else: # Port is a string (e.g., 'http', 'ssh')
            # For named ports, we'd ideally have a mapping or policy-defined sensitive names.
            # For simplicity, we check against common well-known sensitive service names.
            # This is a heuristic and might miss custom service names.
            lower_port_name = str(port_val).lower()
            if protocol == ProtocolType.TCP and lower_port_name in {'ssh', 'telnet', 'ftp', 'smtp', 'http', 'https', 'rdp', 'smb', 'vnc'}:
                 _log_debug(f"Named sensitive TCP port found: {port_val}")
                 return True
            if protocol == ProtocolType.UDP and lower_port_name in {'dns', 'dhcp', 'snmp', 'ike'}:
                 _log_debug(f"Named sensitive UDP port found: {port_val}")
                 return True

    return False

# --- Firewall Rule Parsing ---

def _parse_iptables_rule_line(line: str, policy_config: PolicyConfiguration) -> Optional[FirewallRule]:
    """
    Parses a single line from iptables-save output into a FirewallRule object.
    Handles both rule lines (-A) and default policy lines (:CHAIN).
    """
    _log_debug(f"Attempting to parse line: {line.strip()}")
    line = line.strip()
    if not line or line.startswith('#') or line.startswith('*') or line.startswith('COMMIT'):
        return None

    # Handle default policy lines: :INPUT ACCEPT [0:0]
    if line.startswith(':'):
        match = re.match(r'^:(\S+)\s+(\S+)\s+\[(\d+):(\d+)\]$', line)
        if match:
            chain, policy_action, policy_packets, policy_bytes = match.groups()
            return FirewallRule(
                original_line=line,
                is_default_policy=True,
                chain=chain,
                target=TargetAction.from_str(policy_action),
                policy_packets=int(policy_packets),
                policy_bytes=int(policy_bytes)
            )
        else:
            _log_warning(f"Could not parse default policy line format: {line}")
            return None

    # Handle rule lines: -A CHAIN ... -j TARGET
    if line.startswith('-A ') or line.startswith('-I '):
        parts = shlex_split(line) # Use shlex for robust splitting, handles quoted strings
        if not parts:
            _log_warning(f"Empty parts after shlex split for line: {line}")
            return None

        # Example iptables-save output format:
        # -A CHAIN -p proto -s source -d dest --dport port -j TARGET --comment "..."

        rule_kwargs: Dict[str, Any] = {
            'original_line': line,
            'is_default_policy': False,
            'match_modules': {}
        }

        # First argument is always -A or -I (append/insert)
        # Second argument is always the chain name
        if len(parts) < 2:
            _log_warning(f"Rule line too short to extract chain: {line}")
            return None

        rule_kwargs['chain'] = parts[1]
        
        current_protocol = ProtocolType.ALL # Default protocol for port parsing

        i = 2 # Start processing arguments after `-A CHAIN`
        while i < len(parts):
            arg = parts[i]

            if arg == '-p' and i + 1 < len(parts):
                current_protocol = ProtocolType.from_str(parts[i+1])
                rule_kwargs['protocol'] = current_protocol
                i += 2
            elif arg == '-s' and i + 1 < len(parts):
                try:
                    rule_kwargs['source'] = ipaddress.ip_network(parts[i+1], strict=False)
                except ValueError:
                    _log_warning(f"Invalid source IP/network '{parts[i+1]}' in line: {line}")
                i += 2
            elif arg == '-d' and i + 1 < len(parts):
                try:
                    rule_kwargs['destination'] = ipaddress.ip_network(parts[i+1], strict=False)
                except ValueError:
                    _log_warning(f"Invalid destination IP/network '{parts[i+1]}' in line: {line}")
                i += 2
            elif arg == '-i' and i + 1 < len(parts):
                rule_kwargs['in_interface'] = parts[i+1]
                i += 2
            elif arg == '-o' and i + 1 < len(parts):
                rule_kwargs['out_interface'] = parts[i+1]
                i += 2
            elif arg == '-j' and i + 1 < len(parts):
                target_str = parts[i+1]
                rule_kwargs['target'] = TargetAction.from_str(target_str)
                # If target is a JUMP, store the actual chain name or target extension
                if rule_kwargs['target'] == TargetAction.JUMP or rule_kwargs['target'] == TargetAction.OTHER:
                    rule_kwargs['jump_target_chain'] = target_str
                i += 2
            elif arg == '--sport' and i + 1 < len(parts):
                rule_kwargs['source_ports'].update(_parse_ports(parts[i+1], current_protocol, policy_config))
                i += 2
            elif arg == '--dport' and i + 1 < len(parts):
                rule_kwargs['destination_ports'].update(_parse_ports(parts[i+1], current_protocol, policy_config))
                i += 2
            elif arg == '-m' and i + 1 < len(parts): # Handle match modules like state, limit, comment etc.
                module_name = parts[i+1]
                rule_kwargs['match_modules'][module_name] = {}
                j = i + 2
                while j < len(parts) and not parts[j].startswith('-'):
                    # Parse module specific options (e.g., -m state --state NEW,ESTABLISHED)
                    if parts[j] == '--state' and j + 1 < len(parts):
                        rule_kwargs['state'].update(parts[j+1].split(','))
                        j += 2
                    elif parts[j] == '--comment' and j + 1 < len(parts):
                        # Comments within match modules usually override or add to rule-level comments
                        rule_kwargs['comment'] = parts[j+1].strip('"')
                        j += 2
                    else:
                        # Store other module parameters as key-value, or just the flag if no value
                        if j + 1 < len(parts) and not parts[j+1].startswith('-'):
                            rule_kwargs['match_modules'][module_name][parts[j].lstrip('-')] = parts[j+1]
                            j += 2
                        else:
                            rule_kwargs['match_modules'][module_name][parts[j].lstrip('-')] = True
                            j += 1
                i = j # Continue main loop parsing from where module options left off
            elif arg == '--comment' and i + 1 < len(parts):
                # Rule-level comment (often appears at the end)
                rule_kwargs['comment'] = parts[i+1].strip('"')
                i += 2
            else:
                # Unhandled argument, skip it but log
                _log_debug(f"Skipping unhandled argument '{arg}' at index {i} in line: {line}")
                i += 1
        
        # Ensure target is set, even if it wasn't explicitly -j TARGET (e.g., some iptables versions might omit -j ACCEPT)
        if 'target' not in rule_kwargs or rule_kwargs['target'] is None:
            _log_warning(f"Could not determine explicit target for rule: {line}. Assuming 'OTHER'.")
            rule_kwargs['target'] = TargetAction.OTHER


        # Default IP ranges if not specified: 'any' (0.0.0.0/0 or ::/0).
        # We explicitly set to IPv4 "any" here as default representation; _is_internet_source
        # will check against both IPv4 and IPv6 "any" networks defined in the policy.
        if 'source' not in rule_kwargs:
            rule_kwargs['source'] = ipaddress.ip_network("0.0.0.0/0", strict=False) 
        if 'destination' not in rule_kwargs:
            rule_kwargs['destination'] = ipaddress.ip_network("0.0.0.0/0", strict=False)

        return FirewallRule(**rule_kwargs)
    
    _log_warning(f"Could not parse rule line (unknown format or malformed): {line}")
    return None

def _parse_firewall_config(config_lines: List[str], policy_config: PolicyConfiguration) -> List[FirewallRule]:
    """
    Parses a list of iptables-save configuration lines into a list of FirewallRule objects.
    """
    parsed_rules: List[FirewallRule] = []
    _log_info(f"Parsing {len(config_lines)} lines of firewall configuration...")

    for line in config_lines:
        rule = _parse_iptables_rule_line(line, policy_config)
        if rule:
            parsed_rules.append(rule)
    
    _log_info(f"Successfully parsed {len(parsed_rules)} firewall rules/policies.")
    return parsed_rules

# --- Validation Logic Functions ---

def _check_default_policy(rule: FirewallRule, policy_config: PolicyConfiguration) -> Optional[Finding]:
    """
    Checks if a default chain policy is set to ACCEPT, which is generally considered risky.
    A default policy of ACCEPT means that if no specific rule matches, traffic is allowed.
    """
    if rule.is_default_policy and rule.target == TargetAction.ACCEPT:
        if policy_config.default_allow_policy_is_risky:
            return Finding(
                risk_level=RiskLevel.HIGH,
                message=f"Default policy for chain '{rule.chain}' is set to ACCEPT. This means "
                        "all traffic not explicitly denied will be accepted. Consider setting to DROP.",
                finding_type="DEFAULT_ALLOW_POLICY",
                rule=rule
            )
    return None

def _check_allow_any_any(rule: FirewallRule, policy_config: PolicyConfiguration) -> Optional[Finding]:
    """
    Checks for 'ALLOW ANY ANY' rules, i.e., rules that accept traffic from any source
    to any destination, without specific port or protocol restrictions. These are highly dangerous.
    """
    if rule.target == TargetAction.ACCEPT and policy_config.allow_any_any_is_risky:
        is_internet_src = _is_internet_source(rule.source, policy_config)
        is_internet_dst = _is_internet_source(rule.destination, policy_config)

        # Check for broad protocol (ALL) and no specific destination ports
        is_broad_protocol_and_ports = (rule.protocol == ProtocolType.ALL or rule.protocol is None) and \
                                      not rule.destination_ports and \
                                      not rule.source_ports

        if is_internet_src and is_internet_dst and is_broad_protocol_and_ports:
            return Finding(
                risk_level=RiskLevel.CRITICAL,
                message="Rule allows all traffic from ANY source to ANY destination (ALLOW ANY ANY). "
                        "This rule effectively bypasses all other firewall restrictions.",
                finding_type="ALLOW_ANY_ANY_RULE",
                rule=rule
            )
    return None

def _check_exposed_sensitive_ports(rule: FirewallRule, policy_config: PolicyConfiguration) -> Optional[Finding]:
    """
    Checks for rules that expose sensitive ports to the internet.
    This typically applies to INPUT and FORWARD chains.
    """
    if rule.target == TargetAction.ACCEPT and policy_config.expose_sensitive_ports_is_risky:
        # Sensitive port exposure typically concerns inbound connections or forwarded traffic
        if rule.chain not in ["INPUT", "FORWARD"]:
            _log_debug(f"Skipping sensitive port check for rule in chain '{rule.chain}' (not INPUT/FORWARD).")
            return None

        is_internet_src = _is_internet_source(rule.source, policy_config)
        
        if is_internet_src and rule.destination_ports:
            if _is_sensitive_port(rule.destination_ports, rule.protocol, policy_config):
                return Finding(
                    risk_level=RiskLevel.HIGH,
                    message=f"Sensitive port(s) {','.join(map(str, sorted(list(rule.destination_ports))))} "
                            f"for protocol {rule.protocol.value} exposed to internet from source {rule.source}. "
                            "This could lead to unauthorized access if services on these ports are vulnerable.",
                    finding_type="SENSITIVE_PORT_EXPOSURE",
                    rule=rule,
                    details={"ports": list(rule.destination_ports), "protocol": rule.protocol.value}
                )
    return None

def _check_unrestricted_output(rule: FirewallRule, policy_config: PolicyConfiguration) -> Optional[Finding]:
    """
    Checks for rules in the OUTPUT chain that allow unrestricted outbound traffic.
    While often allowed, overly permissive output rules can facilitate data exfiltration
    or malware communication.
    """
    if rule.chain == "OUTPUT" and rule.target == TargetAction.ACCEPT and policy_config.unrestricted_output_is_risky:
        is_internet_src = _is_internet_source(rule.source, policy_config)
        is_internet_dst = _is_internet_source(rule.destination, policy_config)
        
        # An output rule allowing any source (often local machine) to any destination is unrestricted
        if is_internet_src and is_internet_dst and \
           (rule.protocol == ProtocolType.ALL or rule.protocol is None) and \
           not rule.destination_ports and not rule.source_ports:
            return Finding(
                risk_level=RiskLevel.MEDIUM,
                message="Unrestricted outbound traffic rule detected in OUTPUT chain. "
                        "Allows any protocol/port to any destination. This could aid data exfiltration.",
                finding_type="UNRESTRICTED_OUTPUT",
                rule=rule
            )
    return None

def _check_unrestricted_forward(rule: FirewallRule, policy_config: PolicyConfiguration) -> Optional[Finding]:
    """
    Checks for rules in the FORWARD chain that allow unrestricted packet forwarding.
    This is extremely risky on hosts not intended to be routers or gateways, or without
    further strict filtering.
    """
    if rule.chain == "FORWARD" and rule.target == TargetAction.ACCEPT and policy_config.unrestricted_forward_is_risky:
        is_internet_src = _is_internet_source(rule.source, policy_config)
        is_internet_dst = _is_internet_source(rule.destination, policy_config)
        
        if is_internet_src and is_internet_dst and \
           (rule.protocol == ProtocolType.ALL or rule.protocol is None) and \
           not rule.destination_ports and not rule.source_ports:
            return Finding(
                risk_level=RiskLevel.CRITICAL,
                message="Unrestricted packet forwarding rule detected in FORWARD chain. "
                        "Allows any traffic from any source to any destination. "
                        "This turns the host into an open router, which is highly dangerous.",
                finding_type="UNRESTRICTED_FORWARD",
                rule=rule
            )
    return None

def _check_accept_invalid_state(rule: FirewallRule, policy_config: PolicyConfiguration) -> Optional[Finding]:
    """
    Checks for rules that accept packets marked with the 'INVALID' state.
    Allowing INVALID state packets can be a security risk, as these packets
    often indicate malformed or unexpected traffic.
    """
    # This check is independent of general policy toggles, as it's a specific pattern.
    # We can add a policy_config.allow_invalid_state_is_risky if needed.
    if rule.target == TargetAction.ACCEPT and "INVALID" in rule.state:
        return Finding(
            risk_level=RiskLevel.LOW,
            message="Rule accepts packets in 'INVALID' state. These packets are often malformed "
                    "or do not belong to an established connection, and accepting them can be risky.",
            finding_type="ACCEPT_INVALID_STATE",
            rule=rule
        )
    return None

def _check_jump_to_user_defined_chain(rule: FirewallRule, policy_config: PolicyConfiguration) -> Optional[Finding]:
    """
    Checks for rules that jump to user-defined chains. While not inherently risky,
    it means the actual policy enforcement happens in another chain, requiring
    further manual review to ensure no risks are introduced.
    """
    if rule.target == TargetAction.JUMP and rule.jump_target_chain:
        # Known built-in targets (not actually chains to be reviewed for security policy)
        # This list can be expanded.
        known_safe_jumps = {"RETURN", "LOG", "MASQUERADE", "SNAT", "DNAT", "REDIRECT"} 
        # Also, built-in chains are not "user-defined" in this context
        built_in_chains = {"INPUT", "OUTPUT", "FORWARD", "PREROUTING", "POSTROUTING"}

        if rule.jump_target_chain.upper() not in known_safe_jumps and \
           rule.jump_target_chain.upper() not in built_in_chains:
            if policy_config.log_info_findings:
                return Finding(
                    risk_level=RiskLevel.INFO,
                    message=f"Rule jumps to user-defined chain '{rule.jump_target_chain}'. "
                            "The security implications depend on the rules within that chain, requiring manual review.",
                    finding_type="JUMP_TO_USER_CHAIN",
                    rule=rule
                )
    return None

def validate_firewall_rules(parsed_rules: List[FirewallRule], policy_config: PolicyConfiguration) -> List[Finding]:
    """
    Iterates through all parsed firewall rules and applies a comprehensive set of policy checks.
    Aggregates all identified findings.
    """
    findings: List[Finding] = []
    _log_info(f"Starting validation against {len(parsed_rules)} rules with configured policy...")

    for rule in parsed_rules:
        _log_debug(f"Validating rule: {rule.original_line}")
        # Apply checks specific to default policies
        if rule.is_default_policy:
            finding = _check_default_policy(rule, policy_config)
            if finding: findings.append(finding)
        else: # Apply checks for regular rules
            # High-severity checks
            finding = _check_allow_any_any(rule, policy_config)
            if finding: findings.append(finding)

            finding = _check_exposed_sensitive_ports(rule, policy_config)
            if finding: findings.append(finding)

            finding = _check_unrestricted_forward(rule, policy_config)
            if finding: findings.append(finding)
            
            # Medium-severity checks
            finding = _check_unrestricted_output(rule, policy_config)
            if finding: findings.append(finding)

            # Low-severity/Informational checks
            finding = _check_accept_invalid_state(rule, policy_config)
            if finding: findings.append(finding)
            
            finding = _check_jump_to_user_defined_chain(rule, policy_config)
            if finding: findings.append(finding)

            # Example: Check for rules that explicitly reject, as this can leak information
            # Depending on policy, REJECT might be preferred over DROP, or vice-versa.
            # This is an INFO finding as it's often a design choice.
            if rule.target == TargetAction.REJECT and policy_config.log_info_findings:
                findings.append(Finding(
                    risk_level=RiskLevel.INFO,
                    message="Rule uses 'REJECT' target. This sends an ICMP error message back to the sender, "
                            "potentially revealing host existence and port status. 'DROP' is more stealthy.",
                    finding_type="REJECT_TARGET_USED",
                    rule=rule
                ))
            
            # Example: Check for rules without comments (makes auditing harder)
            if not rule.comment and policy_config.log_info_findings:
                findings.append(Finding(
                    risk_level=RiskLevel.INFO,
                    message="Rule has no comment. Adding comments improves rule maintainability and auditability.",
                    finding_type="NO_RULE_COMMENT",
                    rule=rule
                ))

    _log_info(f"Validation complete. Found {len(findings)} potential security issues.")
    return findings

# --- Reporting ---

def _generate_report(findings: List[Finding]) -> str:
    """
    Generates a human-readable report from the list of findings.
    Groups findings by risk level for clarity.
    """
    report_lines: List[str] = []
    
    report_lines.append("\n" + "="*90)
    report_lines.append(" Firewall Rule Validation Report ".center(90, '='))
    report_lines.append("="*90 + "\n")

    if not findings:
        report_lines.append("No security findings identified. The firewall configuration appears to align with policy.\n")
        report_lines.append("="*90)
        return "\n".join(report_lines)

    # Group findings by risk level and sort them from most critical to least
    findings_by_risk: Dict[RiskLevel, List[Finding]] = {level: [] for level in RiskLevel}
    for finding in findings:
        findings_by_risk[finding.risk_level].append(finding)

    # Define the order in which risk levels should appear in the report
    _risk_levels_order = [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW, RiskLevel.INFO]

    total_findings_count = 0
    for level in _risk_levels_order:
        if findings_by_risk[level]:
            report_lines.append(f"\n{'='*5} [{level.value}] FINDINGS ({len(findings_by_risk[level])} issues) {'='*5}")
            report_lines.append("-" * 90)
            for i, finding in enumerate(findings_by_risk[level]):
                report_lines.append(f"  Issue {i+1}:")
                report_lines.append(f"{finding}\n") # Using the __str__ method of Finding
            total_findings_count += len(findings_by_risk[level])
    
    report_lines.append("="*90)
    report_lines.append(f" Total Findings: {total_findings_count} ".center(90, '='))
    report_lines.append("="*90)

    return "\n".join(report_lines)

# --- Main Script Execution ---

def main():
    """
    Main function to parse command-line arguments, load configuration,
    perform firewall rule parsing and validation, and generate a report.
    """
    parser = argparse.ArgumentParser(
        description="Firewall Rule Validator: Parses iptables-save output and checks it "
                    "against predefined or custom security policies. Flags risky rules "
                    "like 'ALLOW ANY ANY' or sensitive port exposures.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "config_file",
        nargs='?', # Makes it optional; if not provided, reads from stdin
        type=str,
        help="Path to the firewall configuration file (e.g., output of `iptables-save`).\n"
             "If omitted, the script reads from standard input (e.g., `sudo iptables-save | python firewall_validator.py`)."
    )
    parser.add_argument(
        "-p", "--policy-config",
        type=str,
        help="Path to a JSON file containing custom policy configuration. "
             "If not provided, a robust built-in default policy is used.\n\n"
             "Example JSON structure for a custom policy file:\n"
             "{\n"
             "  \"sensitive_tcp_ports\": [22, 3389, 8080],\n"
             "  \"sensitive_udp_ports\": [53, 161],\n"
             "  \"internet_sources\": [\"0.0.0.0/0\", \"::/0\", \"1.2.3.4/32\"],\n"
             "  \"allow_any_any_is_risky\": true,\n"
             "  \"expose_sensitive_ports_is_risky\": true,\n"
             "  \"default_allow_policy_is_risky\": true,\n"
             "  \"unrestricted_output_is_risky\": true,\n"
             "  \"unrestricted_forward_is_risky\": true,\n"
             "  \"log_info_findings\": false\n"
             "}"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output, including debug messages (prints to stderr)."
    )
    # Individual policy toggle arguments for fine-grained control without a JSON file
    parser.add_argument(
        "--disable-allow-any-any-check",
        action="store_true",
        help="Disable the 'ALLOW ANY ANY' policy check (CRITICAL risk)."
    )
    parser.add_argument(
        "--disable-sensitive-port-check",
        action="store_true",
        help="Disable the sensitive port exposure check (HIGH risk)."
    )
    parser.add_argument(
        "--disable-default-allow-check",
        action="store_true",
        help="Disable the default chain policy 'ACCEPT' check (HIGH risk)."
    )
    parser.add_argument(
        "--disable-unrestricted-output-check",
        action="store_true",
        help="Disable the unrestricted outbound traffic rule check (MEDIUM risk)."
    )
    parser.add_argument(
        "--disable-unrestricted-forward-check",
        action="store_true",
        help="Disable the unrestricted packet forwarding rule check (CRITICAL risk)."
    )
    parser.add_argument(
        "--include-info-findings",
        action="store_true",
        help="Include informational findings (e.g., jumps to user-defined chains, rules without comments) in the report."
    )
    parser.add_argument(
        "--no-port-name-warnings",
        action="store_true",
        help="Suppress warnings about non-numeric port names (e.g., 'http') which cannot be definitively checked against numeric sensitive port lists."
    )

    args = parser.parse_args()

    # Set global debug flag based on verbose argument
    global _DEBUG_MODE
    if args.verbose:
        _DEBUG_MODE = True
        _log_info("Verbose mode enabled (debug messages will print to stderr).")

    # Initialize policy configuration with defaults
    policy_kwargs: Dict[str, Any] = {}

    # Load custom policy from JSON file if specified
    if args.policy_config:
        try:
            with open(args.policy_config, 'r') as f:
                custom_policy = json.load(f)
                
                # Convert list of ports to set if present
                if "sensitive_tcp_ports" in custom_policy and isinstance(custom_policy["sensitive_tcp_ports"], list):
                    policy_kwargs["sensitive_tcp_ports"] = set(custom_policy["sensitive_tcp_ports"])
                if "sensitive_udp_ports" in custom_policy and isinstance(custom_policy["sensitive_udp_ports"], list):
                    policy_kwargs["sensitive_udp_ports"] = set(custom_policy["sensitive_udp_ports"])
                
                # Pass other boolean/list flags directly if present and correct type
                for key in ["internet_sources", "allow_any_any_is_risky", "expose_sensitive_ports_is_risky",
                            "default_allow_policy_is_risky", "unrestricted_output_is_risky",
                            "unrestricted_forward_is_risky", "log_info_findings", "warn_on_non_numeric_ports"]:
                    if key in custom_policy:
                        policy_kwargs[key] = custom_policy[key]
            _log_info(f"Loaded custom policy from '{args.policy_config}'.")
        except FileNotFoundError:
            _log_error(f"Custom policy file not found: {args.policy_config}")
            sys.exit(1)
        except json.JSONDecodeError:
            _log_error(f"Error parsing JSON from policy file: {args.policy_config}. Ensure it is valid JSON.")
            sys.exit(1)
        except Exception as e:
            _log_error(f"An unexpected error occurred while loading policy '{args.policy_config}': {e}")
            sys.exit(1)

    # Override policy settings with command-line flags (command line takes precedence)
    if args.disable_allow_any_any_check:
        policy_kwargs["allow_any_any_is_risky"] = False
    if args.disable_sensitive_port_check:
        policy_kwargs["expose_sensitive_ports_is_risky"] = False
    if args.disable_default_allow_check:
        policy_kwargs["default_allow_policy_is_risky"] = False
    if args.disable_unrestricted_output_check:
        policy_kwargs["unrestricted_output_is_risky"] = False
    if args.disable_unrestricted_forward_check:
        policy_kwargs["unrestricted_forward_is_risky"] = False
    if args.include_info_findings:
        policy_kwargs["log_info_findings"] = True
    if args.no_port_name_warnings:
        policy_kwargs["warn_on_non_numeric_ports"] = False

    # Instantiate the PolicyConfiguration object
    policy_config = PolicyConfiguration(**policy_kwargs)
    _log_debug(f"Effective policy configuration: {json.dumps(policy_kwargs, indent=2)}")

    # Read firewall configuration input
    config_lines: List[str] = []
    if args.config_file:
        try:
            with open(args.config_file, 'r') as f:
                config_lines = f.readlines()
            _log_info(f"Successfully read firewall configuration from file: '{args.config_file}'")
        except FileNotFoundError:
            _log_error(f"Firewall configuration file not found: {args.config_file}")
            sys.exit(1)
        except Exception as e:
            _log_error(f"An unexpected error occurred while reading file '{args.config_file}': {e}")
            sys.exit(1)
    else:
        _log_info("No input file specified. Reading firewall configuration from standard input (stdin)...")
        if sys.stdin.isatty():
            _log_warning("Stdin is not piped. Please paste configuration and press Ctrl+D when finished, "
                         "or provide a file path as an argument.")
        config_lines = sys.stdin.readlines()
        if not config_lines:
            _log_error("No configuration data received from standard input. Exiting.")
            sys.exit(1)

    # Parse rules
    parsed_rules = _parse_firewall_config(config_lines, policy_config)

    if not parsed_rules:
        _log_warning("No valid firewall rules were parsed from the input. Please check the input format.")
        sys.exit(0)

    # Validate rules against the policy
    findings = validate_firewall_rules(parsed_rules, policy_config)

    # Filter INFO level findings if not requested explicitly in policy
    if not policy_config.log_info_findings:
        findings = [f for f in findings if f.risk_level != RiskLevel.INFO]

    # Generate and print the final report
    report = _generate_report(findings)
    print(report)

    # Exit with a non-zero status code if critical or high findings are present
    if any(f.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH] for f in findings):
        _log_error("Validation completed with CRITICAL or HIGH risk findings.")
        sys.exit(1) # Indicates critical security issues
    elif any(f.risk_level in [RiskLevel.MEDIUM, RiskLevel.LOW] for f in findings):
        _log_warning("Validation completed with MEDIUM or LOW risk findings.")
        sys.exit(2) # Indicates non-critical but potentially concerning issues
    else:
        _log_info("Validation completed with no significant security findings detected.")
        sys.exit(0) # All clear


if __name__ == "__main__":
    main()