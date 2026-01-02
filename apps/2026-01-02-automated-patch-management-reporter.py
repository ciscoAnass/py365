import paramiko
import os
import re
import csv
import logging
import datetime
from collections import defaultdict

# --- Configuration Section ---
# Configure logging for detailed script execution insights
LOG_FILE = 'patch_management_reporter.log'
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logging.getLogger().addHandler(console_handler)

# List of target servers
# Each server entry should be a dictionary with 'host', 'username', and either 'password' or 'key_filepath'.
# Example with password: {'host': '192.168.1.10', 'username': 'sysadmin', 'password': 'your_password'}
# Example with key: {'host': 'server.example.com', 'username': 'ubuntu', 'key_filepath': '/home/user/.ssh/id_rsa'}
# Ensure SSH keys have correct permissions (chmod 400).
SERVER_LIST = [
    # {'host': 'your_server_ip_1', 'username': 'your_user', 'password': 'your_password'},
    # {'host': 'your_server_ip_2', 'username': 'your_user', 'key_filepath': '/path/to/your/ssh/key'},
    # {'host': 'your_server_ip_3', 'username': 'your_user', 'password': 'another_password'},
    # Add your actual server configurations here.
]

# Output file paths
HTML_REPORT_FILE = 'patch_report.html'
CSV_REPORT_FILE = 'patch_report.csv'

# SSH Connection Parameters
SSH_PORT = 22
SSH_TIMEOUT = 15  # seconds
MAX_SSH_RETRIES = 3 # Maximum attempts to connect to a server

# Heuristic-based Security Priority Classification (for systems where explicit security info is not readily available)
# These lists are used to assign a "security priority" to packages when parsing `apt list --upgradable`
# or when `yum updateinfo list security` doesn't provide enough detail.
HIGH_SECURITY_PACKAGES_KEYWORDS = [
    'linux-image', 'kernel', 'openssl', 'sudo', 'systemd', 'sshd', 'ssh',
    'nginx', 'apache2', 'bind9', 'postfix', 'dovecot', 'exim',
    'php', 'python', 'java', 'mysql', 'postgresql', 'mongodb', 'redis', 'memcached',
    'docker', 'kubernetes', 'containerd', 'qemu', 'kvm', 'xen', 'virtualbox',
    'firewalld', 'iptables', 'nftables', 'selinux', 'apparmor',
    'glibc', 'zlib', 'libssl', 'libcrypto', 'gnutls',
    'cairo', 'pango', 'fontconfig', # Common libraries with security implications
]

MEDIUM_SECURITY_PACKAGES_KEYWORDS = [
    'lib', 'python3-', 'php-', 'perl-', 'ruby-', 'nodejs-', 'npm-', 'yarn-',
    'gcc', 'clang', 'make', 'cmake', 'autotools',
    'git', 'svn', 'mercurial',
    'rsync', 'samba', 'nfs-utils',
    'cron', 'logrotate', 'journald',
    'network-manager', 'iputils', 'net-tools', 'util-linux',
]

# --- Global Data Structures ---
# Store all discovered patch information across the fleet
all_patches_data = []

# --- Helper Functions for SSH Operations ---

def create_ssh_client(server_config):
    """
    Establishes an SSH client connection to a specified server.
    Handles password or key-based authentication.
    """
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy()) # Be cautious with AutoAddPolicy in production
                                                                 # For a sysadmin script, it can be convenient,
                                                                 # but for higher security, use WarningPolicy or manually add keys.

    host = server_config['host']
    username = server_config['username']
    password = server_config.get('password')
    key_filepath = server_config.get('key_filepath')

    logging.info(f"Attempting to connect to {username}@{host}:{SSH_PORT}...")

    try:
        if password:
            client.connect(hostname=host, port=SSH_PORT, username=username, password=password, timeout=SSH_TIMEOUT, auth_timeout=SSH_TIMEOUT)
            logging.info(f"Successfully connected to {host} using password authentication.")
        elif key_filepath and os.path.exists(key_filepath):
            private_key = paramiko.RSAKey.from_private_key_file(key_filepath)
            client.connect(hostname=host, port=SSH_PORT, username=username, pkey=private_key, timeout=SSH_TIMEOUT, auth_timeout=SSH_TIMEOUT)
            logging.info(f"Successfully connected to {host} using key authentication from {key_filepath}.")
        else:
            logging.error(f"Authentication method not specified or key file not found for {host}. Skipping.")
            return None
        return client
    except paramiko.AuthenticationException:
        logging.error(f"Authentication failed for {username}@{host}.")
    except paramiko.SSHException as e:
        logging.error(f"SSH error connecting to {host}: {e}")
    except paramiko.BadHostKeyException as e:
        logging.error(f"Bad host key for {host}: {e}. Host key may have changed or is incorrect.")
    except Exception as e:
        logging.error(f"General error connecting to {host}: {e}")
    return None

def execute_remote_command(ssh_client, command):
    """
    Executes a command on the remote server via the SSH client.
    Returns stdout, stderr, and exit status.
    """
    logging.debug(f"Executing command: '{command}'")
    try:
        stdin, stdout, stderr = ssh_client.exec_command(command, timeout=SSH_TIMEOUT)
        exit_status = stdout.channel.recv_exit_status()
        stdout_output = stdout.read().decode('utf-8').strip()
        stderr_output = stderr.read().decode('utf-8').strip()

        if exit_status != 0:
            logging.warning(f"Command '{command}' on {ssh_client.get_transport().getpeername()[0]} returned non-zero exit status {exit_status}.")
            logging.debug(f"STDERR: {stderr_output}")

        return stdout_output, stderr_output, exit_status
    except paramiko.SSHException as e:
        logging.error(f"SSH command execution failed: {e}")
    except Exception as e:
        logging.error(f"Error executing command '{command}': {e}")
    return "", "Command execution failed.", -1

# --- OS Detection and Patch Command Execution ---

def detect_os_type(ssh_client):
    """
    Detects the operating system type (Debian/Ubuntu or RHEL/CentOS/Fedora)
    on the remote server.
    """
    logging.info("Detecting OS type...")
    # Try reading /etc/os-release first, which is standard for most modern Linux distros
    stdout, stderr, exit_status = execute_remote_command(ssh_client, 'cat /etc/os-release')
    if exit_status == 0 and stdout:
        if 'ID=ubuntu' in stdout or 'ID=debian' in stdout:
            logging.info("Detected OS: Debian/Ubuntu.")
            return 'debian'
        if 'ID="centos"' in stdout or 'ID="rhel"' in stdout or 'ID="fedora"' in stdout:
            logging.info("Detected OS: RHEL/CentOS/Fedora.")
            return 'rhel'

    # Fallback to /etc/issue for older systems or specific cases
    stdout, stderr, exit_status = execute_remote_command(ssh_client, 'cat /etc/issue')
    if exit_status == 0 and stdout:
        if 'Ubuntu' in stdout or 'Debian' in stdout:
            logging.info("Detected OS: Debian/Ubuntu (via /etc/issue).")
            return 'debian'
        if 'CentOS' in stdout or 'Red Hat' in stdout or 'Fedora' in stdout:
            logging.info("Detected OS: RHEL/CentOS/Fedora (via /etc/issue).")
            return 'rhel'

    logging.warning(f"Could not reliably detect OS type for {ssh_client.get_transport().getpeername()[0]}. Assuming unknown.")
    return 'unknown'

def get_apt_upgradable_packages(ssh_client, hostname):
    """
    Runs 'apt list --upgradable' on a Debian/Ubuntu system and parses its output.
    Attempts to classify packages by security priority using heuristics.
    """
    logging.info(f"Checking for APT upgradable packages on {hostname}...")
    stdout, stderr, exit_status = execute_remote_command(ssh_client, 'sudo apt list --upgradable')

    if exit_status != 0:
        logging.error(f"Failed to list APT upgradable packages on {hostname}: {stderr}")
        return []

    # Example output line:
    # package-name/focal-updates 2.0.0-1ubuntu1 amd64 [upgradable from: 1.0.0-1ubuntu1]
    # package-name/focal-security 2.0.0-1ubuntu1 amd64 [upgradable from: 1.0.0-1ubuntu1]
    # Listing...
    # python3-update-manager/focal-updates 1:20.04.10.8 amd64 [upgradable from: 1:20.04.10.7]

    patches = []
    # Regex to capture package name, new version, and optionally the repository/suite part (e.g., focal-updates, focal-security)
    # The current version is optional as it's not always present or consistently formatted.
    package_regex = re.compile(r'^([a-zA-Z0-9.\-]+)(?:/([a-zA-Z0-9.\-]+))?\s+([\w\d\.\-~+:]+)\s+.*\[upgradable from: ([\w\d\.\-~+:]+)\]$')

    for line in stdout.splitlines():
        line = line.strip()
        if not line or line == "Listing...":
            continue

        match = package_regex.match(line)
        if match:
            pkg_name = match.group(1)
            pkg_suite = match.group(2) if match.group(2) else "unknown"
            new_version = match.group(3)
            current_version = match.group(4)

            # Determine patch type and priority based on suite and package name heuristics
            patch_type = "Bugfix/Enhancement"
            priority = "Low"

            if 'security' in pkg_suite.lower():
                patch_type = "Security"
                priority = "High"
            else:
                for keyword in HIGH_SECURITY_PACKAGES_KEYWORDS:
                    if keyword in pkg_name.lower():
                        patch_type = "Security (Heuristic)"
                        priority = "High"
                        break
                if priority != "High":
                    for keyword in MEDIUM_SECURITY_PACKAGES_KEYWORDS:
                        if keyword in pkg_name.lower():
                            patch_type = "Bugfix/Enhancement (Heuristic)"
                            priority = "Medium"
                            break

            patches.append({
                'server_hostname': hostname,
                'os_type': 'debian',
                'package_name': pkg_name,
                'current_version': current_version,
                'new_version': new_version,
                'patch_type': patch_type,
                'priority': priority,
                'advisory_id': 'N/A' # APT doesn't provide advisory IDs directly in this output
            })
            logging.debug(f"Parsed APT patch: {pkg_name} {new_version} ({patch_type}, {priority})")
        else:
            logging.debug(f"Skipping unparseable APT line: {line}")

    logging.info(f"Found {len(patches)} APT upgradable packages on {hostname}.")
    return patches

def get_yum_upgradable_packages(ssh_client, hostname):
    """
    Runs 'yum check-update' and 'yum updateinfo list security all' on a RHEL/CentOS system
    and parses their output to get available patches and security information.
    """
    logging.info(f"Checking for YUM/DNF upgradable packages on {hostname}...")
    patches = []
    upgradable_packages = {} # Store basic info from check-update first

    # 1. Get basic upgradable packages (yum check-update or dnf check-update)
    # Try dnf first for modern systems, then fallback to yum
    stdout, stderr, exit_status = execute_remote_command(ssh_client, 'sudo dnf check-update')
    if exit_status == 0:
        package_manager = 'dnf'
    else: # Fallback to yum
        stdout, stderr, exit_status = execute_remote_command(ssh_client, 'sudo yum check-update')
        if exit_status == 0:
            package_manager = 'yum'
        else:
            logging.error(f"Failed to check updates with both DNF and YUM on {hostname}: {stderr}")
            return []

    # Example output:
    # Package_Name.arch  VERSION.RELEASE  repo
    # kernel.x86_64                                3.10.0-1160.71.1.el7      updates
    # libgcc.x86_64                                4.8.5-44.el7              base
    check_update_regex = re.compile(r'^([a-zA-Z0-9.\-]+)\.([a-zA-Z0-9_]+)\s+([\w\d\.\-~+:]+)\s+([\w\d\.\-]+)$')
    for line in stdout.splitlines():
        line = line.strip()
        if not line or 'Obsoleting Packages' in line or 'Security' in line or 'Updated' in line or 'Available' in line:
            continue
        match = check_update_regex.match(line)
        if match:
            pkg_name = match.group(1)
            arch = match.group(2)
            new_version = match.group(3)
            repo = match.group(4)
            # YUM/DNF check-update doesn't easily provide current version, often it's "Installed: current_version" if a full update is pending
            upgradable_packages[pkg_name] = {
                'arch': arch,
                'new_version': new_version,
                'repo': repo,
                'patch_type': 'Bugfix/Enhancement', # Default, will be updated if security found
                'priority': 'Low',                   # Default, will be updated if security found
                'advisory_id': 'N/A'
            }
            logging.debug(f"Parsed YUM/DNF upgradable: {pkg_name} {new_version}")
        else:
            logging.debug(f"Skipping unparseable YUM/DNF check-update line: {line}")

    # 2. Get security updates using updateinfo (requires yum-plugin-security or dnf-plugins-core)
    # This command explicitly lists security advisories and the packages they affect.
    stdout, stderr, exit_status = execute_remote_command(ssh_client, f'sudo {package_manager} updateinfo list security all')
    if exit_status != 0:
        logging.warning(f"Failed to get YUM/DNF security info on {hostname} (plugin might be missing): {stderr}")
        # If security info fails, rely on the basic upgradable list with heuristics
        for pkg_name, pkg_info in upgradable_packages.items():
            for keyword in HIGH_SECURITY_PACKAGES_KEYWORDS:
                if keyword in pkg_name.lower():
                    pkg_info['patch_type'] = "Security (Heuristic)"
                    pkg_info['priority'] = "High"
                    break
            if pkg_info['priority'] != "High":
                for keyword in MEDIUM_SECURITY_PACKAGES_KEYWORDS:
                    if keyword in pkg_name.lower():
                        pkg_info['patch_type'] = "Bugfix/Enhancement (Heuristic)"
                        pkg_info['priority'] = "Medium"
                        break
            patches.append({
                'server_hostname': hostname,
                'os_type': 'rhel',
                'package_name': pkg_name,
                'current_version': 'N/A', # Not easily available from yum check-update
                'new_version': pkg_info['new_version'],
                'patch_type': pkg_info['patch_type'],
                'priority': pkg_info['priority'],
                'advisory_id': pkg_info['advisory_id']
            })
        logging.info(f"Found {len(patches)} YUM/DNF upgradable packages on {hostname} (no explicit security info).")
        return patches

    # Example yum updateinfo output:
    # RHSA-2023:1234 important/Sec.  package-name-1.0-1.el7.x86_64
    # RHBA-2023:5678 bugfix         other-package-2.0-2.el7.noarch
    updateinfo_regex = re.compile(r'^(RHSA|RHBA|RHEA)-(\d{4}:\d+)\s+([a-zA-Z]+)(?:/Sec.)?\s+([a-zA-Z0-9.\-]+)-([\w\d\.\-~+:]+)\.([a-zA-Z0-9_]+)$')

    security_advisories = defaultdict(list) # {pkg_name: [{'advisory_id', 'patch_type', 'priority'}, ...]}

    for line in stdout.splitlines():
        line = line.strip()
        if not line or 'Loaded plugins' in line or 'Security' in line or 'Bugfix' in line or 'Enhancement' in line or 'Total' in line:
            continue

        match = updateinfo_regex.match(line)
        if match:
            advisory_type = match.group(1) # RHSA, RHBA, RHEA
            advisory_id = f"{advisory_type}-{match.group(2)}"
            advisory_severity = match.group(3) # important, moderate, low, bugfix, enhancement
            pkg_name = match.group(4)
            pkg_version = match.group(5)
            pkg_arch = match.group(6)

            patch_type = advisory_severity.capitalize() # "Bugfix", "Enhancement"
            priority = "Low"

            if advisory_type == 'RHSA' or 'sec.' in advisory_severity.lower():
                patch_type = "Security"
                if advisory_severity.lower() in ['critical', 'important']:
                    priority = "High"
                elif advisory_severity.lower() == 'moderate':
                    priority = "Medium"
                else:
                    priority = "Low" # "low" security or just "security"
            elif advisory_type == 'RHBA':
                patch_type = "Bugfix"
                priority = "Medium" if advisory_severity.lower() == 'important' else "Low"
            elif advisory_type == 'RHEA':
                patch_type = "Enhancement"
                priority = "Low"

            security_advisories[pkg_name].append({
                'advisory_id': advisory_id,
                'patch_type': patch_type,
                'priority': priority
            })
            logging.debug(f"Parsed YUM/DNF security advisory: {advisory_id} for {pkg_name} ({patch_type}, {priority})")
        else:
            logging.debug(f"Skipping unparseable YUM/DNF updateinfo line: {line}")

    # Consolidate information
    for pkg_name, pkg_info in upgradable_packages.items():
        if pkg_name in security_advisories:
            # Take the highest priority if multiple advisories for one package
            highest_priority_info = max(security_advisories[pkg_name], key=lambda x: ['Low', 'Medium', 'High'].index(x['priority']))
            pkg_info['patch_type'] = highest_priority_info['patch_type']
            pkg_info['priority'] = highest_priority_info['priority']
            pkg_info['advisory_id'] = ", ".join([adv['advisory_id'] for adv in security_advisories[pkg_name]])

        patches.append({
            'server_hostname': hostname,
            'os_type': 'rhel',
            'package_name': pkg_name,
            'current_version': 'N/A', # Still not easily available from check-update
            'new_version': pkg_info['new_version'],
            'patch_type': pkg_info['patch_type'],
            'priority': pkg_info['priority'],
            'advisory_id': pkg_info['advisory_id']
        })

    logging.info(f"Found {len(patches)} YUM/DNF upgradable packages on {hostname} (with security info).")
    return patches


# --- Report Generation Functions ---

def generate_html_report(all_data, filename):
    """
    Generates an HTML report from the consolidated patch data.
    Includes a summary and a detailed table sorted by priority.
    """
    logging.info(f"Generating HTML report: {filename}...")

    # Sort data: High priority first, then Medium, then Low. Within each priority, sort by hostname then package name.
    priority_order = {'High': 0, 'Medium': 1, 'Low': 2, 'N/A': 3, 'Unknown': 4, 'Security': 0, 'Bugfix/Enhancement': 1}
    sorted_data = sorted(all_data, key=lambda x: (priority_order.get(x['priority'], 99), x['server_hostname'], x['package_name']))

    # Statistics
    total_servers = len(set(d['server_hostname'] for d in all_data)) if all_data else 0
    servers_with_patches = len(set(d['server_hostname'] for d in all_data if d['priority'] != 'N/A'))
    total_patches = len(all_data)
    security_patches = sum(1 for d in all_data if d['priority'] == 'High' and 'Security' in d['patch_type'])
    bugfix_patches = sum(1 for d in all_data if 'Bugfix' in d['patch_type'])
    enhancement_patches = sum(1 for d in all_data if 'Enhancement' in d['patch_type'])

    # HTML header and basic styling
    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Automated Patch Management Report - {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f4f4f4; color: #333; }}
        h1 {{ color: #0056b3; border-bottom: 2px solid #0056b3; padding-bottom: 10px; }}
        h2 {{ color: #0056b3; }}
        .report-section {{ background-color: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 15px; }}
        .summary-item {{ background-color: #e9ecef; padding: 15px; border-radius: 5px; text-align: center; }}
        .summary-item strong {{ display: block; font-size: 1.2em; color: #0056b3; }}
        .summary-item span {{ font-size: 0.9em; color: #555; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
        th {{ background-color: #0056b3; color: white; cursor: pointer; }}
        tr:nth-child(even) {{ background-color: #f2f2f2; }}
        tr:hover {{ background-color: #e2e6ea; }}
        .priority-high {{ background-color: #f8d7da; color: #721c24; }}
        .priority-medium {{ background-color: #fff3cd; color: #856404; }}
        .priority-low {{ background-color: #d1ecf1; color: #0c5460; }}
        .footer {{ text-align: center; margin-top: 30px; font-size: 0.8em; color: #777; }}
    </style>
</head>
<body>
    <h1>Automated Patch Management Report</h1>
    <div class="report-section">
        <h2>Report Overview</h2>
        <p>Report generated on: <strong>{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</strong></p>
        <div class="summary-grid">
            <div class="summary-item"><strong>{total_servers}</strong> <span>Total Servers Scanned</span></div>
            <div class="summary-item"><strong>{servers_with_patches}</strong> <span>Servers Requiring Patches</span></div>
            <div class="summary-item"><strong>{total_patches}</strong> <span>Total Patches Available</span></div>
            <div class="summary-item"><strong>{security_patches}</strong> <span>Security Patches (High Priority)</span></div>
            <div class="summary-item"><strong>{bugfix_patches}</strong> <span>Bugfix Patches</span></div>
            <div class="summary-item"><strong>{enhancement_patches}</strong> <span>Enhancement Patches</span></div>
        </div>
    </div>

    <div class="report-section">
        <h2>Detailed Patch List</h2>
        <table>
            <thead>
                <tr>
                    <th>Server Hostname</th>
                    <th>OS Type</th>
                    <th>Package Name</th>
                    <th>Current Version</th>
                    <th>New Version</th>
                    <th>Patch Type</th>
                    <th>Priority</th>
                    <th>Advisory ID</th>
                </tr>
            </thead>
            <tbody>
    """

    for patch in sorted_data:
        priority_class = f"priority-{patch['priority'].lower()}" if patch['priority'] in ['High', 'Medium', 'Low'] else ''
        html_content += f"""
                <tr class="{priority_class}">
                    <td>{patch['server_hostname']}</td>
                    <td>{patch['os_type']}</td>
                    <td>{patch['package_name']}</td>
                    <td>{patch['current_version']}</td>
                    <td>{patch['new_version']}</td>
                    <td>{patch['patch_type']}</td>
                    <td>{patch['priority']}</td>
                    <td>{patch['advisory_id']}</td>
                </tr>
        """

    html_content += """
            </tbody>
        </table>
    </div>
    <div class="footer">
        <p>Automated Patch Management Reporter - Developed using Paramiko and standard Python libraries.</p>
    </div>
</body>
</html>
    """

    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        logging.info(f"HTML report saved to {filename}")
    except IOError as e:
        logging.error(f"Failed to write HTML report to {filename}: {e}")

def generate_csv_report(all_data, filename):
    """
    Generates a CSV report from the consolidated patch data.
    """
    logging.info(f"Generating CSV report: {filename}...")

    if not all_data:
        logging.warning("No patch data available to generate CSV report.")
        # Create an empty file with headers for consistency
        headers = [
            'Server Hostname', 'OS Type', 'Package Name', 'Current Version',
            'New Version', 'Patch Type', 'Priority', 'Advisory ID'
        ]
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=headers)
                writer.writeheader()
            logging.info(f"Empty CSV report with headers saved to {filename}")
        except IOError as e:
            logging.error(f"Failed to write empty CSV report to {filename}: {e}")
        return

    # Sort data (same as HTML for consistency)
    priority_order = {'High': 0, 'Medium': 1, 'Low': 2, 'N/A': 3, 'Unknown': 4, 'Security': 0, 'Bugfix/Enhancement': 1}
    sorted_data = sorted(all_data, key=lambda x: (priority_order.get(x['priority'], 99), x['server_hostname'], x['package_name']))

    # Define CSV headers based on dictionary keys
    fieldnames = [
        'server_hostname', 'os_type', 'package_name', 'current_version',
        'new_version', 'patch_type', 'priority', 'advisory_id'
    ]

    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(sorted_data)
        logging.info(f"CSV report saved to {filename}")
    except IOError as e:
        logging.error(f"Failed to write CSV report to {filename}: {e}")

# --- Main Script Execution Logic ---

def main():
    """
    Main function to orchestrate the patch management reporting process.
    Iterates through servers, connects, gathers data, and generates reports.
    """
    logging.info("--- Starting Automated Patch Management Reporter ---")
    start_time = datetime.datetime.now()

    if not SERVER_LIST:
        logging.error("No servers configured in SERVER_LIST. Please add server details to proceed.")
        logging.info("--- Automated Patch Management Reporter Finished (No Servers) ---")
        return

    processed_servers_count = 0
    successful_servers_count = 0
    skipped_servers_count = 0

    for server_config in SERVER_LIST:
        host = server_config['host']
        processed_servers_count += 1
        logging.info(f"\n--- Processing server: {host} (Server {processed_servers_count}/{len(SERVER_LIST)}) ---")

        ssh_client = None
        attempt = 0
        while attempt < MAX_SSH_RETRIES:
            try:
                ssh_client = create_ssh_client(server_config)
                if ssh_client:
                    successful_servers_count += 1
                    break
            except Exception as e:
                logging.warning(f"Connection attempt {attempt + 1}/{MAX_SSH_RETRIES} to {host} failed: {e}")
            attempt += 1
            if attempt < MAX_SSH_RETRIES:
                logging.info(f"Retrying connection to {host} in a moment...")
                # Could add a small delay here if needed: time.sleep(5)
        
        if not ssh_client:
            logging.error(f"Failed to connect to {host} after {MAX_SSH_RETRIES} attempts. Skipping this server.")
            skipped_servers_count += 1
            continue

        try:
            os_type = detect_os_type(ssh_client)
            if os_type == 'debian':
                patches = get_apt_upgradable_packages(ssh_client, host)
            elif os_type == 'rhel':
                patches = get_yum_upgradable_packages(ssh_client, host)
            else:
                logging.warning(f"Unsupported or unknown OS type '{os_type}' for {host}. Skipping patch collection.")
                patches = []

            all_patches_data.extend(patches)

        except Exception as e:
            logging.error(f"An unexpected error occurred while processing {host}: {e}")
        finally:
            if ssh_client:
                ssh_client.close()
                logging.info(f"Closed SSH connection to {host}.")

    logging.info("\n--- Patch data collection complete ---")
    logging.info(f"Total servers configured: {len(SERVER_LIST)}")
    logging.info(f"Successfully connected to: {successful_servers_count} servers")
    logging.info(f"Skipped due to connection issues: {skipped_servers_count} servers")
    logging.info(f"Total patches found across all servers: {len(all_patches_data)}")

    # Generate reports
    if all_patches_data:
        generate_html_report(all_patches_data, HTML_REPORT_FILE)
        generate_csv_report(all_patches_data, CSV_REPORT_FILE)
    else:
        logging.warning("No patches found across the fleet. Generating empty reports with headers.")
        generate_html_report([], HTML_REPORT_FILE) # Generate with headers and summary, but no rows
        generate_csv_report([], CSV_REPORT_FILE)   # Generate with headers, but no rows

    end_time = datetime.datetime.now()
    duration = end_time - start_time
    logging.info(f"--- Automated Patch Management Reporter Finished in {duration} ---")

# --- Entry Point ---
if __name__ == "__main__":
    # Ensure paramiko is installed. If not, inform the user.
    try:
        import paramiko
    except ImportError:
        print("Error: The 'paramiko' library is not installed.")
        print("Please install it using: pip install paramiko")
        exit(1)

    main()