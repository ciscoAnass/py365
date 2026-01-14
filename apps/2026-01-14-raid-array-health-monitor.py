import subprocess
import sys
import re
import os
import smtplib
from email.mime.text import MIMEText
import logging
import logging.handlers
import argparse
import collections
import time
from shutil import which # For finding mdadm in PATH

# --- Configuration Constants ---
# These default values can be overridden by command-line arguments.
DEFAULT_EMAIL_RECIPIENTS = []  # List of email addresses, e.g., ["admin@example.com"]
DEFAULT_SMTP_SERVER = 'localhost'
DEFAULT_SMTP_PORT = 25
DEFAULT_SENDER_EMAIL = 'raidmonitor@' + os.uname().nodename
DEFAULT_LOG_LEVEL = logging.INFO
DEFAULT_LOG_FILE = '/var/log/raid_health_monitor.log'
DEFAULT_SYSLOG_ADDRESS = ('localhost', 514)  # For syslog handler (host, port)
DEFAULT_MDADM_COMMAND_PATH = '/usr/sbin/mdadm'  # Full path for robustness

# Global variable to store the actual mdadm command path after validation
MDADM_COMMAND = DEFAULT_MDADM_COMMAND_PATH

# --- Data Structures ---
# Named tuple for parsed individual disk information
DiskInfo = collections.namedtuple('DiskInfo', ['device', 'minor', 'raid_disk', 'state', 'state_words'])

class RaidArray:
    """
    A class to hold comprehensive information about a single Linux software RAID array,
    parsed from `mdadm --detail` output.
    """
    def __init__(self, device_path):
        """
        Initializes a new RaidArray object.

        Args:
            device_path (str): The /dev/mdX path for the RAID array.
        """
        self.device_path = device_path
        # Basic array identification
        self.md_version = None
        self.creation_time = None
        self.raid_level = None
        self.uuid = None

        # Array geometry and capacity
        self.array_size = None  # e.g., "4194240 (4.00 GiB 4.29 GB)"
        self.used_dev_size = None  # e.g., "4194240 (4.00 GiB 4.29 GB)"
        self.chunk_size = None  # e.g., "512K"
        self.layout = None  # e.g., "contiguous"

        # Device counts
        self.raid_devices = None  # Configured number of devices
        self.total_devices = None # Total devices currently associated (can include removed)
        self.active_devices = None
        self.working_devices = None
        self.failed_devices = None
        self.spare_devices = None

        # Array operational state
        self.persistent_superblock = None
        self.update_time = None
        self.state = None  # e.g., 'clean', 'clean, degraded', 'active, degraded, rebuilding'
        self.events = None  # Event count for array changes
        self.rebuild_status = None  # e.g., '3.7% complete' or 'none'

        # List of DiskInfo objects for individual component devices
        self.disks = []

        # Overall health status determined by the monitor script
        self.is_healthy = True
        self.health_message = "OK"

    def __str__(self):
        """Returns a concise string summary of the RAID array's health."""
        status_line = f"[{self.device_path}] Level: {self.raid_level or 'N/A'}, State: {self.state or 'N/A'}"
        if self.failed_devices is not None and self.failed_devices > 0:
            status_line += f", Failed: {self.failed_devices}"
        if self.is_healthy is False:
            status_line += f" -> UNHEALTHY: {self.health_message}"
        else:
            status_line += " -> HEALTHY"
        return status_line

    def get_detailed_status(self):
        """
        Returns a detailed multi-line string representing all parsed information
        and health status of the RAID array.
        """
        details = [
            f"--- RAID Array Details: {self.device_path} ---",
            f"  UUID: {self.uuid or 'N/A'}",
            f"  Version: {self.md_version or 'N/A'}",
            f"  Creation Time: {self.creation_time or 'N/A'}",
            f"  RAID Level: {self.raid_level or 'N/A'}",
            f"  Current State: {self.state or 'N/A'}",
            f"  Array Size: {self.array_size or 'N/A'}",
            f"  Used Dev Size: {self.used_dev_size or 'N/A'}",
            f"  Chunk Size: {self.chunk_size or 'N/A'}",
            f"  Layout: {self.layout or 'N/A'}",
            f"  Configured Devices: {self.raid_devices or 'N/A'}",
            f"  Total Devices (currently): {self.total_devices or 'N/A'}",
            f"  Active/Working/Failed/Spare Devices: {self.active_devices or 0}/{self.working_devices or 0}/{self.failed_devices or 0}/{self.spare_devices or 0}",
        ]
        if self.rebuild_status and 'none' not in self.rebuild_status.lower():
            details.append(f"  Rebuild Status: {self.rebuild_status}")
        details.append("\n  Individual Disk Status:")
        if self.disks:
            for disk in self.disks:
                state_desc = {
                    'U': 'Up/Healthy',
                    'F': 'FAILED',
                    'S': 'Spare',
                    'R': 'Rebuilding', # 'R' is often part of state_words, not a specific char
                    '-': 'Removed' # Placeholder for removed slots
                }.get(disk.state, 'Unknown')
                details.append(f"    - {disk.device} (RAID Disk: {disk.raid_disk}, Minor: {disk.minor}) -> "
                               f"Explicit State: '{disk.state}' ({state_desc}), Status Words: '{disk.state_words}'")
        else:
            details.append("    No individual disk information available (or array is inactive/empty).")
        details.append(f"\n  Overall Health: {'HEALTHY' if self.is_healthy else 'UNHEALTHY (CRITICAL)'}")
        details.append(f"  Health Message: {self.health_message}")
        details.append("--------------------------------------------------")
        return "\n".join(details)


# --- Global Logger Instance ---
logger = None

def setup_logging(log_level, log_file, syslog_address):
    """
    Configures and returns a global logger instance for the script.
    Includes handlers for console (stdout), file, and syslog.

    Args:
        log_level (int): The minimum logging level (e.g., logging.INFO, logging.DEBUG).
        log_file (str): Path to the log file. Set to '' to disable file logging.
        syslog_address (tuple): (host, port) for syslog, or None to disable syslog.
    """
    global logger
    if logger is not None:
        return logger  # Logger already configured

    logger = logging.getLogger(__name__)
    logger.setLevel(log_level)

    # Prevent duplicate handlers if called multiple times in an unusual scenario
    if not logger.handlers:
        # Console handler for immediate feedback
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
        logger.addHandler(console_handler)

        # File handler for persistent logs
        if log_file:
            try:
                # Use RotatingFileHandler to manage log file size
                file_handler = logging.handlers.RotatingFileHandler(
                    log_file, maxBytes=10485760, backupCount=5  # 10MB per file, 5 backups
                )
                file_handler.setFormatter(logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                ))
                logger.addHandler(file_handler)
                logger.debug(f"File logging enabled to: {log_file}")
            except IOError as e:
                logger.error(f"Could not set up file logging to '{log_file}': {e}. File logging disabled.")
            except Exception as e:
                logger.error(f"An unexpected error occurred setting up file logging: {e}. File logging disabled.")

        # Syslog handler for centralized logging
        if syslog_address:
            try:
                syslog_handler = logging.handlers.SysLogHandler(address=syslog_address)
                syslog_handler.setFormatter(logging.Formatter(
                    '%(name)s: %(levelname)s: %(message)s'
                ))
                logger.addHandler(syslog_handler)
                logger.debug(f"Syslog logging enabled to {syslog_address[0]}:{syslog_address[1]}")
            except Exception as e:
                logger.error(f"Could not set up syslog logging to {syslog_address}: {e}. Syslog logging disabled.")
    return logger

def run_command(command_args, description="command execution"):
    """
    Executes a shell command safely, captures output, and logs errors.

    Args:
        command_args (list): A list of strings representing the command and its arguments.
        description (str): A description of the command for logging purposes.

    Returns:
        tuple: (stdout_str, stderr_str, return_code)
    """
    try:
        logger.debug(f"Executing command: {' '.join(command_args)}")
        process = subprocess.run(
            command_args,
            capture_output=True,
            text=True,  # Decode stdout/stderr as text
            check=False, # Do not raise CalledProcessError, check return code manually
            encoding='utf-8',
            errors='replace' # Replace unencodable characters
        )
        if process.returncode != 0:
            logger.warning(
                f"Command '{command_args[0]}' for {description} failed with exit code {process.returncode}. "
                f"Stderr: {process.stderr.strip()}"
            )
        return process.stdout, process.stderr, process.returncode
    except FileNotFoundError:
        logger.critical(f"Error: Command '{command_args[0]}' not found. "
                        f"Please ensure it is installed and in your PATH. Cannot perform {description}.")
        return "", f"Command '{command_args[0]}' not found.", 127 # Standard exit code for command not found
    except PermissionError:
        logger.critical(f"Error: Permission denied when trying to execute '{command_args[0]}'. "
                        f"Please check file permissions. Cannot perform {description}.")
        return "", f"Permission denied for '{command_args[0]}'.", 1
    except Exception as e:
        logger.critical(f"An unexpected error occurred while executing '{' '.join(command_args)}' "
                        f"for {description}: {e}")
        return "", str(e), 1

def validate_mdadm_path(path):
    """
    Validates if the mdadm executable exists at the given path and is executable.

    Args:
        path (str): The full path to the mdadm executable.

    Returns:
        bool: True if the path is valid, False otherwise.
    """
    if not path:
        logger.critical("mdadm executable path is not specified or is empty.")
        return False
    if not os.path.exists(path):
        logger.critical(f"mdadm executable not found at specified path: '{path}'.")
        return False
    if not os.path.isfile(path):
        logger.critical(f"'{path}' is not a file. It should be the mdadm executable.")
        return False
    if not os.access(path, os.X_OK):
        logger.critical(f"mdadm executable at '{path}' is not executable. Check file permissions (e.g., `chmod +x {path}`).")
        return False
    logger.debug(f"mdadm executable validated at: {path}")
    return True

def check_mdadm_version():
    """
    Checks the mdadm version and logs it. This helps confirm mdadm is working.

    Returns:
        bool: True if version check was successful, False otherwise.
    """
    cmd = [MDADM_COMMAND, '--version']
    stdout, stderr, retcode = run_command(cmd, "check mdadm version")
    if retcode == 0:
        logger.debug(f"mdadm version information:\n{stdout.strip()}")
        return True
    else:
        logger.error(f"Failed to get mdadm version. Is mdadm correctly installed? Error: {stderr.strip()}")
        return False

def find_raid_arrays_from_proc_mdstat():
    """
    Discovers active RAID arrays by parsing `/proc/mdstat`. This is generally
    the most reliable method on Linux systems.

    Returns:
        list: A list of device paths (e.g., ['/dev/md0', '/dev/md127']).
    """
    raid_devices = []
    proc_mdstat_path = '/proc/mdstat'
    if not os.path.exists(proc_mdstat_path):
        logger.error(f"'{proc_mdstat_path}' not found. Cannot determine RAID arrays.")
        return []

    try:
        with open(proc_mdstat_path, 'r') as f:
            content = f.read()

        # Regex to find lines like 'md0 : active raid1 sda1[0] sdb1[1]'
        # Captures the 'mdX' device name. It specifically looks for active arrays
        # by checking for ': active' or ': inactive' followed by device list.
        # This handles cases where an array might be inactive but still listed.
        md_array_pattern = re.compile(r"^(md\d+) : .*?\s+(active|inactive|auto-read-only)", re.MULTILINE)
        matches = md_array_pattern.findall(content)

        if not matches:
            logger.info(f"No active or inactive RAID arrays found in '{proc_mdstat_path}'.")
            return []

        # Deduplicate and sort the discovered md device names
        discovered_md_names = sorted(list(set([m[0] for m in matches])))

        for md_name in discovered_md_names:
            device_path = os.path.join('/dev', md_name)
            if os.path.exists(device_path):
                raid_devices.append(device_path)
            else:
                logger.warning(f"RAID device '{device_path}' found in '{proc_mdstat_path}' "
                               f"but does not exist on filesystem. Skipping this array.")

    except IOError as e:
        logger.error(f"Error reading '{proc_mdstat_path}': {e}")
    except Exception as e:
        logger.error(f"An unexpected error occurred while parsing '{proc_mdstat_path}': {e}")

    logger.debug(f"Found RAID devices: {raid_devices}")
    return raid_devices

def get_mdadm_detail_output(array_path):
    """
    Executes 'mdadm --detail <array_path>' and returns its standard output.

    Args:
        array_path (str): The /dev/mdX path of the RAID array.

    Returns:
        str or None: The stdout of the command if successful, otherwise None.
    """
    cmd = [MDADM_COMMAND, '--detail', array_path]
    stdout, stderr, retcode = run_command(cmd, f"get details for array {array_path}")

    if retcode != 0:
        logger.error(f"Failed to get details for {array_path}. mdadm returned code {retcode}. "
                     f"Stderr: {stderr.strip()}")
        return None
    return stdout

def parse_mdadm_output(array_path, mdadm_output):
    """
    Parses the detailed output of 'mdadm --detail' for a specific array
    and populates a RaidArray object with the extracted information.

    Args:
        array_path (str): The /dev/mdX path of the RAID array.
        mdadm_output (str): The raw string output from 'mdadm --detail'.

    Returns:
        RaidArray: An object containing parsed RAID array details.
    """
    raid_array = RaidArray(array_path)
    lines = mdadm_output.strip().split('\n')

    # Regular expression patterns for key array-level information
    # These typically appear as 'Key : Value' pairs.
    array_patterns = {
        'md_version': r"Version : (.*)",
        'creation_time': r"Creation Time : (.*)",
        'raid_level': r"Raid Level : (.*)",
        'uuid': r"UUID : (.*)",
        'array_size': r"Array Size : (.*)",
        'used_dev_size': r"Used Dev Size : (.*)",
        'chunk_size': r"Chunk Size : (.*)",
        'layout': r"Layout : (.*)",
        'raid_devices': r"Raid Devices : (\d+)",
        'total_devices': r"Total Devices : (\d+)",
        'persistent_superblock': r"Persistent Superblock : (.*)",
        'update_time': r"Update Time : (.*)",
        'state': r"State : (.*)",
        'events': r"Events : \[.*\] (\d+)",
        'rebuild_status': r"Rebuild Status : (.*)"
    }

    # Pattern for the line containing aggregated device counts:
    # "Active Devices : 2 Working Devices : 2 Failed Devices : 0 Spare Devices : 0"
    device_counts_pattern = re.compile(
        r"Active Devices : (\d+)\s+Working Devices : (\d+)\s+Failed Devices : (\d+)\s+Spare Devices : (\d+)"
    )

    # Regex for parsing individual disk lines (component devices).
    # Example formats:
    #    0     8       1        0      active sync   /dev/sda1[0]
    #    1     8      17        1      active sync   /dev/sdb1[1]
    #    0     8        1        0      faulty spare   /dev/sda1[0](F)
    #    -       0        0        0      removed
    # The 'Number' field can be '-' for removed devices.
    # The 'RaidDevice' field can be '-' for removed devices.
    # The 'State' field can be multiple words (e.g., 'active sync').
    # The final `(U)`, `(F)`, `(S)` is optional.
    disk_line_pattern = re.compile(
        r"^\s*(?:-|\d+)\s+\d+\s+(\d+)\s+(?:-|\d+)\s+(\S+(?:\s+\S+)*?)\s+(\S+)\[(?:-|\d+)\](?:\(([UFS])\))?"
    )
    # Capturing groups:
    # 1: Minor device number (int) - always present even if device removed (minor 0)
    # 2: State_Words (str) - e.g., 'active sync', 'faulty spare', 'spare rebuilding'
    # 3: DevicePath (str) - e.g., '/dev/sda1', or 'none' for removed
    # 4: Final state char (str) - optional (U, F, S). None if not present.

    for line in lines:
        line = line.strip()

        # Try to match general array properties first
        for key, pattern_str in array_patterns.items():
            match = re.search(pattern_str, line)
            if match:
                value = match.group(1).strip()
                setattr(raid_array, key, value)
                break # Move to next line after a match for array properties

        # Try to match the aggregated device counts line
        if raid_array.active_devices is None: # Only parse this once
            match = device_counts_pattern.search(line)
            if match:
                raid_array.active_devices = int(match.group(1))
                raid_array.working_devices = int(match.group(2))
                raid_array.failed_devices = int(match.group(3))
                raid_array.spare_devices = int(match.group(4))

        # Try to match individual disk lines
        match_disk = disk_line_pattern.match(line)
        if match_disk:
            minor, state_words, device_path, final_state_char = match_disk.groups()
            minor = int(minor)
            
            # Infer the primary state character if not explicitly given
            # 'U' for active/healthy, 'F' for faulty, 'S' for spare
            state = final_state_char
            if state is None:
                # Based on state words
                if 'faulty' in state_words:
                    state = 'F'
                elif 'spare' in state_words:
                    state = 'S'
                elif 'removed' in state_words or device_path == 'none':
                    state = '-' # Indicate removed slot
                else: # active, rebuilding, sync, recovery, etc.
                    state = 'U' # Assume active/up if no explicit F/S

            # Attempt to extract RaidDevice index from device_path like /dev/sda1[0]
            # Some entries (like removed) don't have this.
            raid_disk_match = re.search(r'\[(\d+)\]', line)
            raid_disk_idx = int(raid_disk_match.group(1)) if raid_disk_match else None
            
            # Skip "removed" devices or "none" device path unless it explicitly states faulty
            if device_path == 'none' and state != 'F':
                logger.debug(f"Skipping 'none' or removed device line: {line}")
                continue

            raid_array.disks.append(DiskInfo(
                device=device_path,
                minor=minor,
                raid_disk=raid_disk_idx,
                state=state,
                state_words=state_words
            ))
            logger.debug(f"Parsed disk: {device_path}, state: {state}, words: {state_words}")

    return raid_array


def evaluate_array_health(raid_array):
    """
    Evaluates the health of a single RAID array based on its parsed details.
    Updates the raid_array.is_healthy and raid_array.health_message attributes.

    Args:
        raid_array (RaidArray): The RAID array object to evaluate.

    Returns:
        tuple: (bool, str) - True if healthy, False otherwise, along with a message.
    """
    alerts = []
    is_critical_issue = False

    logger.debug(f"Evaluating health for {raid_array.device_path} (State: {raid_array.state}, "
                 f"Failed Devices: {raid_array.failed_devices}, Spare Devices: {raid_array.spare_devices})")

    # Check overall state keywords (case-insensitive)
    if raid_array.state:
        state_lower = raid_array.state.lower()
        if 'degraded' in state_lower:
            alerts.append(f"Array state is DEGRADED: '{raid_array.state}'.")
            is_critical_issue = True
        if 'inactive' in state_lower:
            alerts.append(f"Array state is INACTIVE: '{raid_array.state}'. This means it's not running.")
            is_critical_issue = True
        if 'read-only' in state_lower:
            alerts.append(f"Array state is READ-ONLY: '{raid_array.state}'. This might indicate underlying issues.")
            is_critical_issue = True # Treat as critical, usually means degraded beyond repair or in recovery
        if 'resync' in state_lower or 'rebuilding' in state_lower:
            # Resyncing/rebuilding is a normal process after a failure/replacement.
            # Only add as a warning unless combined with critical failure modes.
            alerts.append(f"Array is currently RESYNCING/REBUILDING: '{raid_array.state}'."
                          f" Rebuild Status: {raid_array.rebuild_status or 'N/A'}.")
            # Do not set is_critical_issue to True for rebuilding alone

    # Check for explicit failed devices count
    if raid_array.failed_devices is not None and raid_array.failed_devices > 0:
        alerts.append(f"Detected {raid_array.failed_devices} FAILED devices based on array metadata.")
        is_critical_issue = True

    # Check individual disk states from parsed DiskInfo objects
    failed_disks = [d for d in raid_array.disks if d.state == 'F']
    if failed_disks:
        alerts.append(f"Specific disks found FAILED: {', '.join([d.device for d in failed_disks])}.")
        is_critical_issue = True

    # Check for spare disks when array is not clean (implies a problem led to spare activation)
    # This is often a precursor to or accompanying a degraded state.
    if raid_array.spare_devices is not None and raid_array.spare_devices > 0:
        if raid_array.state and 'clean' not in raid_array.state.lower() and \
           raid_array.state and 'active' in raid_array.state.lower() and \
           not is_critical_issue: # Only add if not already marked critical
            alerts.append(f"Detected {raid_array.spare_devices} spare device(s) in use while array state is "
                          f"'{raid_array.state}'. This usually means a disk failed and was replaced, "
                          f"or the array is currently rebuilding.")
            # This is a warning, not critical unless it leads to degradation.
            # We don't change is_critical_issue here unless it *becomes* degraded.

    # Check for any "removed" devices that are not marked as faulty (might be old entries)
    removed_devices = [d for d in raid_array.disks if d.state == '-']
    if removed_devices and raid_array.state and 'degraded' not in raid_array.state.lower():
        alerts.append(f"Detected {len(removed_devices)} 'removed' device slots in the array. "
                      f"These are not actively part of the array, but might indicate past issues or configuration drift.")
        # Not critical on its own, especially if the array is otherwise 'clean'.

    raid_array.is_healthy = not is_critical_issue
    if not alerts:
        raid_array.health_message = "Array is healthy."
    else:
        raid_array.health_message = " ".join(alerts)

    logger.debug(f"Health evaluation for {raid_array.device_path} completed. Is Healthy: {raid_array.is_healthy}, Message: {raid_array.health_message}")
    return raid_array.is_healthy, raid_array.health_message

def send_email_alert(recipients, smtp_server, smtp_port, sender_email, subject, message):
    """
    Sends an email alert to the specified recipients.

    Args:
        recipients (list): A list of email addresses.
        smtp_server (str): The SMTP server address.
        smtp_port (int): The SMTP server port.
        sender_email (str): The sender's email address.
        subject (str): The email subject line.
        message (str): The body of the email.
    """
    if not recipients:
        logger.warning("No email recipients configured. Skipping email alert.")
        return

    msg = MIMEText(message)
    msg['Subject'] = subject
    msg['From'] = sender_email
    msg['To'] = ", ".join(recipients) # For multiple recipients

    try:
        logger.info(f"Attempting to send email alert to {', '.join(recipients)} via {smtp_server}:{smtp_port}...")
        with smtplib.SMTP(smtp_server, smtp_port, timeout=10) as server:
            # server.starttls() # Uncomment and configure if your SMTP server requires TLS
            # server.login("username", "password") # Uncomment and configure if authentication is required
            server.send_message(msg)
        logger.info(f"Email alert sent successfully to {', '.join(recipients)}.")
    except smtplib.SMTPConnectError as e:
        logger.error(f"Failed to connect to SMTP server {smtp_server}:{smtp_port}. Check server address/port and firewall: {e}")
    except smtplib.SMTPAuthenticationError as e:
        logger.error(f"SMTP authentication failed. Check username/password for {sender_email}: {e}")
    except smtplib.SMTPSenderRefused as e:
        logger.error(f"SMTP sender email '{sender_email}' refused by server: {e}")
    except smtplib.SMTPRecipientsRefused as e:
        logger.error(f"SMTP recipient(s) refused: {e}")
    except smtplib.SMTPException as e:
        logger.error(f"An SMTP error occurred while sending email: {e}")
    except Exception as e:
        logger.error(f"An unexpected error occurred while sending email: {e}")

def generate_alert_message(unhealthy_arrays):
    """
    Generates a human-readable alert subject and message for unhealthy arrays.

    Args:
        unhealthy_arrays (list): A list of RaidArray objects that are unhealthy.

    Returns:
        tuple: (subject_str, message_str)
    """
    hostname = os.uname().nodename
    subject = f"CRITICAL RAID ALERT for {hostname} - {len(unhealthy_arrays)} Array(s) Unhealthy!"
    message_parts = [
        f"RAID Health Monitor on {hostname} detected critical issues at {time.ctime()} ({time.tzname[0]}).\n",
        f"The following {len(unhealthy_arrays)} RAID array(s) are in an unhealthy or degraded state "
        f"and require immediate attention:\n"
    ]

    for array in unhealthy_arrays:
        message_parts.append(array.get_detailed_status())
        message_parts.append("\n") # Add extra space between array details

    message_parts.append("\nThis automated alert indicates a critical problem with your RAID storage.\n"
                         "Please investigate the affected arrays promptly using `mdadm --detail /dev/mdX`.\n")
    return subject, "\n".join(message_parts)

def parse_arguments():
    """
    Parses command-line arguments, providing flexible configuration for the script.

    Returns:
        argparse.Namespace: An object containing the parsed arguments.
    """
    parser = argparse.ArgumentParser(
        description="Monitor Linux software RAID (mdadm) array health and send critical alerts.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Example usage:\n"
            "  python raid_monitor.py --email-recipients admin@example.com --log-level DEBUG\n"
            "  python raid_monitor.py --no-email --log-file /var/log/my_raid_monitor.log\n"
            "  python raid_monitor.py --mdadm-path /bin/mdadm --syslog-address 192.168.1.10:514\n"
            "Exit codes:\n"
            "  0: All arrays healthy.\n"
            "  1: General script error (e.g., mdadm not found, argument parsing error).\n"
            "  2: Critical RAID health issues detected.\n"
        )
    )

    parser.add_argument(
        '--email-recipients',
        nargs='*', # 0 or more arguments
        default=DEFAULT_EMAIL_RECIPIENTS,
        help=f"List of email addresses to send critical alerts to. Separate multiple with spaces.\n"
             f"Default: {', '.join(DEFAULT_EMAIL_RECIPIENTS) if DEFAULT_EMAIL_RECIPIENTS else 'None'}"
    )
    parser.add_argument(
        '--smtp-server',
        default=DEFAULT_SMTP_SERVER,
        help=f"SMTP server address for sending emails. Default: {DEFAULT_SMTP_SERVER}"
    )
    parser.add_argument(
        '--smtp-port',
        type=int,
        default=DEFAULT_SMTP_PORT,
        help=f"SMTP server port. Default: {DEFAULT_SMTP_PORT}"
    )
    parser.add_argument(
        '--sender-email',
        default=DEFAULT_SENDER_EMAIL,
        help=f"Email address from which alerts will be sent. Default: {DEFAULT_SENDER_EMAIL}"
    )
    parser.add_argument(
        '--no-email',
        action='store_true',
        help="Do not send email alerts, only log to console/file/syslog."
    )
    parser.add_argument(
        '--log-level',
        default='INFO',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        help=f"Set the logging level. Messages at or above this level will be processed.\n"
             f"Default: {DEFAULT_LOG_LEVEL.name}"
    )
    parser.add_argument(
        '--log-file',
        default=DEFAULT_LOG_FILE,
        help=f"Path to the log file. Set to 'None' or empty string to disable file logging.\n"
             f"Default: {DEFAULT_LOG_FILE}"
    )
    parser.add_argument(
        '--no-syslog',
        action='store_true',
        help="Do not send logs to syslog."
    )
    parser.add_argument(
        '--syslog-address',
        default=f"{DEFAULT_SYSLOG_ADDRESS[0]}:{DEFAULT_SYSLOG_ADDRESS[1]}",
        help=f"Syslog server address and port (e.g., 'localhost:514').\n"
             f"Default: {DEFAULT_SYSLOG_ADDRESS[0]}:{DEFAULT_SYSLOG_ADDRESS[1]}"
    )
    parser.add_argument(
        '--mdadm-path',
        default=DEFAULT_MDADM_COMMAND_PATH,
        help=f"Full path to the mdadm executable. This can be used if mdadm is not in PATH or "
             f"at the default location. Default: {DEFAULT_MDADM_COMMAND_PATH}"
    )

    args = parser.parse_args()

    # Convert log level string to logging constant
    args.log_level = getattr(logging, args.log_level.upper(), DEFAULT_LOG_LEVEL)

    # Parse syslog address string into a tuple (host, port)
    if not args.no_syslog:
        try:
            host, port_str = args.syslog_address.split(':')
            args.syslog_address_parsed = (host, int(port_str))
        except ValueError:
            parser.error(f"Invalid syslog-address format: '{args.syslog_address}'. Use 'host:port' (e.g., 'localhost:514').")
    else:
        args.syslog_address_parsed = None
    
    # Handle empty string for log-file to disable it explicitly
    if args.log_file.strip() == '' or args.log_file.lower() == 'none':
        args.log_file = None

    return args

def main():
    """
    Main function to orchestrate the RAID array health monitoring process.
    """
    global MDADM_COMMAND

    try:
        args = parse_arguments()

        # Set the global mdadm command path
        MDADM_COMMAND = args.mdadm_path

        # Validate mdadm path early
        if not validate_mdadm_path(MDADM_COMMAND):
            # Attempt to find mdadm in PATH if the provided path is invalid/default and not found
            logger_temp = logging.getLogger(__name__ + "_init") # Temp logger for early checks
            logger_temp.setLevel(logging.CRITICAL)
            console_handler_temp = logging.StreamHandler(sys.stderr)
            console_handler_temp.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
            logger_temp.addHandler(console_handler_temp)

            found_mdadm_in_path = which('mdadm')
            if found_mdadm_in_path:
                MDADM_COMMAND = found_mdadm_in_path
                logger_temp.warning(f"Using mdadm found in PATH: '{MDADM_COMMAND}', "
                                    f"as the specified/default path was invalid.")
            else:
                logger_temp.critical(f"mdadm executable not found at '{MDADM_COMMAND}' "
                                     f"and not found in system PATH. Please ensure mdadm is installed "
                                     f"or specify its path with --mdadm-path. Exiting.")
                sys.exit(1) # Critical error: mdadm not found

        # Setup logging after initial mdadm path check for full functionality
        setup_logging(args.log_level, args.log_file, args.syslog_address_parsed)
        logger.info("RAID array health monitoring script started.")
        logger.debug(f"Script arguments: {args}")
        logger.debug(f"Using mdadm executable at: {MDADM_COMMAND}")

        # Check mdadm version for diagnostic purposes
        check_mdadm_version()

        # Step 1: Discover RAID arrays
        logger.info("Discovering active RAID arrays from /proc/mdstat...")
        array_paths = find_raid_arrays_from_proc_mdstat()

        if not array_paths:
            logger.info("No active RAID arrays found to monitor. Exiting.")
            sys.exit(0) # Exit successfully if no arrays to monitor

        all_raid_arrays = []
        unhealthy_arrays = []

        # Step 2 & 3: Get detailed information, parse, and evaluate health for each array
        for path in array_paths:
            logger.info(f"Processing array: {path}")
            mdadm_output = get_mdadm_detail_output(path)
            if mdadm_output:
                raid_array = parse_mdadm_output(path, mdadm_output)
                all_raid_arrays.append(raid_array)

                is_healthy, health_message = evaluate_array_health(raid_array)
                # Update the RaidArray object's health status based on evaluation
                raid_array.is_healthy = is_healthy
                raid_array.health_message = health_message

                if not is_healthy:
                    logger.critical(f"UNHEALTHY RAID ARRAY DETECTED: {raid_array.device_path}. Reason: {health_message}")
                    unhealthy_arrays.append(raid_array)
                else:
                    logger.info(f"Array {raid_array.device_path} is healthy. {health_message}")
                logger.debug(raid_array.get_detailed_status()) # Log full details at DEBUG level
            else:
                logger.error(f"Could not retrieve mdadm details for array {path}. Skipping health check for this array.")

        # Step 4: Send alerts if any arrays are unhealthy
        if unhealthy_arrays:
            logger.critical(f"Detected {len(unhealthy_arrays)} unhealthy RAID array(s). Preparing and sending alerts.")
            subject, message = generate_alert_message(unhealthy_arrays)

            # Always print critical alert summary to console
            logger.critical(f"\n--- CRITICAL RAID HEALTH ALERT ---")
            logger.critical(f"Subject: {subject}")
            logger.critical(f"{message}\n")
            logger.critical(f"----------------------------------\n")

            # Send email if configured and not explicitly disabled
            if not args.no_email and args.email_recipients:
                send_email_alert(
                    args.email_recipients,
                    args.smtp_server,
                    args.smtp_port,
                    args.sender_email,
                    subject,
                    message
                )
            elif not args.no_email and not args.email_recipients:
                logger.warning("Email alerting requested, but no recipients specified. Skipping email notification.")

            logger.critical("RAID health check completed with CRITICAL issues. Exiting with status 2.")
            sys.exit(2) # Exit with a non-zero code to indicate critical problems
        else:
            logger.info("All monitored RAID arrays are reported healthy. Exiting with status 0.")
            sys.exit(0) # Exit successfully
    except Exception as e:
        # Catch any unexpected errors that bypass specific handlers
        if logger:
            logger.critical(f"An unhandled critical error occurred during script execution: {e}", exc_info=True)
        else:
            # If logger isn't set up yet, print to stderr
            print(f"CRITICAL ERROR: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr)
        sys.exit(1) # General error exit code

if __name__ == "__main__":
    main()