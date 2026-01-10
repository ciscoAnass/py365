import os
import sys
import subprocess
import logging
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple

# --- Constants and Configuration ---

# Default path to the fstab file. This is the standard location on Linux systems.
DEFAULT_FSTAB_PATH = "/etc/fstab"

# Default log file path for the script's operations. This provides a persistent
# record of checks and alerts.
DEFAULT_LOG_FILE_PATH = "/var/log/nfs_mount_checker.log"

# Exit codes for the script. These allow external systems (e.g., cron, monitoring tools)
# to easily interpret the script's outcome.
EXIT_CODE_SUCCESS = 0             # All checks passed, no issues found.
EXIT_CODE_UNMOUNTED_SHARES = 1    # One or more network shares were found unmounted.
EXIT_CODE_CONFIGURATION_ERROR = 2 # Script configuration issues (e.g., invalid paths).
EXIT_CODE_RUNTIME_ERROR = 3       # General operational errors (e.g., command execution failures).

# Filesystem types that are considered network shares (NFS/SMB/CIFS).
# These are the types the script will specifically look for in fstab.
NETWORK_FS_TYPES = ("nfs", "nfs4", "cifs", "smbfs")

# Name of the logger to be used throughout the script. This helps in distinguishing
# logs from different applications in a shared logging system.
LOGGER_NAME = "nfs_mount_checker"

# Minimum Python version requirement. Ensures compatibility with language features used.
PYTHON_MIN_VERSION = (3, 6)

# Path to the findmnt utility. This is a crucial command for checking current mounts.
# It's part of the util-linux package on most Linux distributions.
FINDMNT_COMMAND_PATH = "/usr/bin/findmnt"

# --- Data Models ---
# These dataclasses provide a structured way to store parsed information,
# making the code more readable and robust.

@dataclass
class FstabEntry:
    """
    Represents a single entry parsed from the /etc/fstab file.
    Each attribute corresponds to a field in a standard fstab entry.
    """
    device: str          # The device (e.g., remote NFS path, UUID, /dev/sda1).
    mount_point: str     # The directory where the device is mounted.
    fs_type: str         # The filesystem type (e.g., nfs, cifs, ext4).
    options: List[str] = field(default_factory=list) # Mount options (e.g., rw, auto, soft).
    dump: int = 0        # Used by the dump utility (0 to ignore).
    pass_num: int = 0    # Used by fsck to determine check order (0 to ignore).
    original_line: str = "" # Stores the exact line from fstab for debugging/logging.

    def __str__(self):
        """
        Provides a human-readable string representation of the fstab entry,
        useful for logging and console output.
        """
        return (f"Device: '{self.device}', Mount Point: '{self.mount_point}', "
                f"FS Type: '{self.fs_type}', Options: '{','.join(self.options)}'")

@dataclass
class MountedEntry:
    """
    Represents a single currently mounted filesystem, parsed from `findmnt -J` output.
    Captures key information about an active mount.
    """
    source: str          # The source of the mount (e.g., remote NFS server, device path).
    target: str          # The mount point (directory).
    fstype: str          # The actual filesystem type of the mounted share.
    options: List[str] = field(default_factory=list) # Active mount options.
    uuid: Optional[str] = None # UUID of the filesystem, if available.
    label: Optional[str] = None # Label of the filesystem, if available.

    def __str__(self):
        """
        Provides a human-readable string representation of a mounted entry,
        useful for logging and console output.
        """
        return (f"Source: '{self.source}', Target: '{self.target}', "
                f"FS Type: '{self.fstype}', Options: '{','.join(self.options)}'")

@dataclass
class ScriptConfiguration:
    """
    Holds configuration parameters for the nfs-mount-checker script.
    Allows for easy management and potential customization of script behavior.
    """
    fstab_path: str = DEFAULT_FSTAB_PATH         # Path to the fstab file.
    log_file_path: str = DEFAULT_LOG_FILE_PATH   # Path to the script's log file.
    # Placeholder for alert recipients. In a production scenario, this would likely
    # be used for email addresses, PagerDuty integration keys, or webhook URLs.
    alert_recipients: List[str] = field(default_factory=list)

    def __post_init__(self):
        """
        Performs validation after the ScriptConfiguration object has been initialized.
        Ensures essential configuration values are present and valid.
        """
        if not isinstance(self.fstab_path, str) or not self.fstab_path:
            raise ValueError("fstab_path must be a non-empty string.")
        if not isinstance(self.log_file_path, str) or not self.log_file_path:
            raise ValueError("log_file_path must be a non-empty string.")
        if not isinstance(self.alert_recipients, list):
            raise ValueError("alert_recipients must be a list of strings.")
        # Additional validation could be added here, e.g., checking if log_file_path is writable.

# --- Utility Functions ---
# These functions provide common operations used throughout the script,
# enhancing modularity and reusability.

def _setup_logging(log_file: str, log_level: int = logging.INFO) -> logging.Logger:
    """
    Sets up a comprehensive logging system for the script.
    Logs messages to both a specified file and the console (stderr),
    with detailed formatting including timestamps and log levels.

    Args:
        log_file (str): The absolute path to the log file.
        log_level (int): The minimum logging level to capture (e.g., logging.INFO, logging.DEBUG).

    Returns:
        logging.Logger: The configured logger instance.
    """
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(log_level)

    # Prevent adding duplicate handlers if _setup_logging is called multiple times.
    if not logger.handlers:
        # Define a consistent format for all log messages.
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        # File Handler: Writes log messages to the specified file.
        # This is important for persistent record-keeping.
        try:
            # Ensure the directory for the log file exists.
            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except IOError as e:
            # If file logging fails, log an error to stderr and continue with console logging only.
            sys.stderr.write(f"ERROR: Could not open log file '{log_file}': {e}\n")
            sys.stderr.write("Proceeding with console logging only for critical errors.\n")
        except Exception as e:
            sys.stderr.write(f"ERROR: Unexpected error setting up file logging: {e}\n")
            sys.stderr.write("Proceeding with console logging only.\n")

        # Console Handler: Writes log messages to standard error (stderr).
        # This provides immediate feedback during execution, especially for alerts.
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    logger.info(f"Logging configured. Outputting to '{log_file}' and stderr at level {logging.getLevelName(log_level)}.")
    return logger

def _check_python_version(min_version: Tuple[int, int]) -> None:
    """
    Checks if the current Python version meets the minimum requirement.
    This ensures the script runs in an environment with expected language features.

    Args:
        min_version (Tuple[int, int]): A tuple representing the minimum
                                       (major, minor) Python version required.

    Raises:
        SystemExit: If the Python version is below the minimum required.
    """
    if sys.version_info < min_version:
        sys.stderr.write(f"ERROR: This script requires Python {min_version[0]}.{min_version[1]} "
                         f"or higher. You are running {sys.version_info.major}.{sys.version_info.minor}.\n")
        sys.exit(EXIT_CODE_RUNTIME_ERROR)

def _execute_command(command: List[str], logger: logging.Logger,
                     check: bool = True, capture_output: bool = True,
                     text: bool = True, timeout: Optional[int] = 30) -> Optional[subprocess.CompletedProcess]:
    """
    Executes an external shell command using subprocess.run, handling its output and errors.
    This function centralizes command execution, making it consistent and error-resilient.

    Args:
        command (List[str]): A list of strings representing the command and its arguments.
        logger (logging.Logger): The logger instance for logging command execution details.
        check (bool): If True, raise a CalledProcessError if the command returns a non-zero exit code.
        capture_output (bool): If True, stdout and stderr are captured.
        text (bool): If True, stdout and stderr are decoded as text.
        timeout (Optional[int]): If provided, the command will be killed after this many seconds.

    Returns:
        Optional[subprocess.CompletedProcess]: The result of the command execution,
                                              or None if an exception occurred and check=False.

    Raises:
        subprocess.CalledProcessError: If check is True and the command returns a non-zero exit code.
        subprocess.TimeoutExpired: If the command times out.
        FileNotFoundError: If the command itself is not found.
    """
    command_str = ' '.join(command)
    logger.debug(f"Attempting to execute command: '{command_str}'")
    try:
        # subprocess.run is the recommended way to run external commands in Python 3.5+.
        result = subprocess.run(
            command,
            capture_output=capture_output,
            text=text,
            check=check,
            timeout=timeout
        )
        if result.returncode != 0:
            logger.warning(
                f"Command '{command_str}' exited with non-zero status {result.returncode}. "
                f"STDOUT: {result.stdout.strip() if result.stdout else 'N/A'} "
                f"STDERR: {result.stderr.strip() if result.stderr else 'N/A'}"
            )
        else:
            logger.debug(f"Command '{command_str}' completed successfully.")
            if result.stdout:
                logger.debug(f"STDOUT (first 200 chars): {result.stdout.strip()[:200]}")
            if result.stderr:
                logger.debug(f"STDERR (first 200 chars): {result.stderr.strip()[:200]}")
        return result
    except FileNotFoundError:
        logger.error(f"Command '{command[0]}' not found. Is it installed and in PATH? Full command: '{command_str}'")
        raise
    except subprocess.TimeoutExpired as e:
        logger.error(f"Command '{command_str}' timed out after {timeout} seconds.")
        # Output any captured data even on timeout.
        if e.stdout: logger.error(f"STDOUT from timeout: {e.stdout.strip()}")
        if e.stderr: logger.error(f"STDERR from timeout: {e.stderr.strip()}")
        raise
    except subprocess.CalledProcessError as e:
        logger.error(
            f"Command '{command_str}' failed with exit code {e.returncode}. "
            f"STDOUT: {e.stdout.strip() if e.stdout else 'N/A'} "
            f"STDERR: {e.stderr.strip() if e.stderr else 'N/A'}"
        )
        raise
    except Exception as e:
        logger.error(f"An unexpected error occurred while executing command '{command_str}': {e}", exc_info=True)
        raise

# --- Fstab Parsing Logic ---

def _parse_fstab_line(line: str, line_num: int, logger: logging.Logger) -> Optional[FstabEntry]:
    """
    Parses a single line from the /etc/fstab file into an FstabEntry object.
    Robustly handles comments, empty lines, and malformed entries.

    Args:
        line (str): The raw string line from fstab.
        line_num (int): The line number for better error reporting.
        logger (logging.Logger): The logger instance.

    Returns:
        Optional[FstabEntry]: An FstabEntry object if parsing is successful and
                              the line is relevant (not a comment/empty), otherwise None.
    """
    line = line.strip()
    if not line or line.startswith('#'):
        logger.debug(f"Skipping empty or comment line {line_num}: '{line}'")
        return None

    try:
        # Split the line by any whitespace. This handles multiple spaces between fields.
        parts = line.split()
        if len(parts) < 6:
            logger.warning(f"Line {line_num} in fstab has too few fields (expected at least 6): '{line}'. Skipping.")
            return None

        # Extract the required fields.
        device, mount_point, fs_type, options_str, dump_str, pass_str = parts[:6]

        # Convert dump and pass_num to integers, providing default values on error.
        try:
            dump = int(dump_str)
        except ValueError:
            logger.warning(f"Line {line_num} dump field '{dump_str}' is not an integer. Setting to 0. Line: '{line}'")
            dump = 0
        try:
            pass_num = int(pass_str)
        except ValueError:
            logger.warning(f"Line {line_num} pass field '{pass_str}' is not an integer. Setting to 0. Line: '{line}'")
            pass_num = 0

        # Options string can be a comma-separated list.
        options = [opt.strip() for opt in options_str.split(',') if opt.strip()] if options_str else []

        entry = FstabEntry(
            device=device,
            mount_point=mount_point,
            fs_type=fs_type,
            options=options,
            dump=dump,
            pass_num=pass_num,
            original_line=line # Store the original line for detailed logging if needed.
        )
        logger.debug(f"Parsed fstab line {line_num}: {entry}")
        return entry

    except Exception as e:
        logger.error(f"Critical error parsing fstab line {line_num}: '{line}' - {e}. Skipping this entry.", exc_info=True)
        return None

def _get_expected_network_mounts_from_fstab(fstab_path: str, logger: logging.Logger) -> List[FstabEntry]:
    """
    Reads the /etc/fstab file, parses each line, and extracts entries
    that correspond to known network share filesystem types (NFS, SMB/CIFS).

    Args:
        fstab_path (str): The absolute path to the fstab file.
        logger (logging.Logger): The logger instance.

    Returns:
        List[FstabEntry]: A list of FstabEntry objects for all identified network mounts.
                          Returns an empty list if the file cannot be read or no network mounts are found.
    """
    expected_mounts: List[FstabEntry] = []
    logger.info(f"Attempting to read fstab from: '{fstab_path}' to find network mounts.")

    # Pre-check for file existence and read permissions.
    if not os.path.exists(fstab_path):
        logger.critical(f"fstab file not found at '{fstab_path}'. Cannot proceed with checks.")
        return []
    if not os.access(fstab_path, os.R_OK):
        logger.critical(f"Permission denied to read fstab file at '{fstab_path}'. Please check user permissions.")
        return []

    try:
        with open(fstab_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                entry = _parse_fstab_line(line, line_num, logger)
                # Filter for network filesystem types based on the global constant.
                if entry and entry.fs_type.lower() in NETWORK_FS_TYPES:
                    expected_mounts.append(entry)
                    logger.debug(f"Identified network mount from fstab: {entry}")
                elif entry:
                    # Log non-network mounts at debug level to keep INFO output clean.
                    logger.debug(f"Skipping non-network mount from fstab: {entry.mount_point} ({entry.fs_type})")

    except Exception as e:
        logger.critical(f"Failed to read or parse fstab file '{fstab_path}': {e}", exc_info=True)
        return []

    if not expected_mounts:
        logger.warning(f"No network mounts ({','.join(NETWORK_FS_TYPES)}) found in '{fstab_path}'.")
    else:
        logger.info(f"Successfully identified {len(expected_mounts)} network mounts defined in fstab.")

    return expected_mounts

# --- Current Mount Status (findmnt) Logic ---

def _check_findmnt_availability(logger: logging.Logger) -> bool:
    """
    Checks if the 'findmnt' command is available and executable on the system.
    This is a critical dependency for determining current mount status.

    Args:
        logger (logging.Logger): The logger instance.

    Returns:
        bool: True if 'findmnt' is found and executable, False otherwise.
    """
    logger.debug(f"Checking for availability of '{FINDMNT_COMMAND_PATH}' command...")
    try:
        # Execute findmnt with --version to check its existence and basic functionality.
        # We set check=False because a non-zero exit code might occur if args are wrong,
        # but we only care if the command itself runs.
        result = _execute_command([FINDMNT_COMMAND_PATH, "--version"], logger, check=False, capture_output=False, timeout=5)
        if result and result.returncode == 0:
            logger.info(f"'{FINDMNT_COMMAND_PATH}' found and accessible.")
            return True
        else:
            logger.error(f"'{FINDMNT_COMMAND_PATH}' command failed or not found. "
                         f"Return code: {result.returncode if result else 'N/A'}.")
            return False
    except FileNotFoundError:
        logger.critical(f"'{FINDMNT_COMMAND_PATH}' not found in expected path or system PATH. "
                        "Please ensure 'util-linux' package is installed and 'findmnt' is executable.")
        return False
    except Exception as e:
        logger.critical(f"Error checking findmnt availability: {e}", exc_info=True)
        return False

def _parse_findmnt_json_output(json_output: str, logger: logging.Logger) -> List[MountedEntry]:
    """
    Parses the JSON output from `findmnt -l -J` into a list of MountedEntry objects.
    Using JSON output is much more reliable and robust for programmatic parsing
    compared to parsing plain text `findmnt` output.

    Args:
        json_output (str): The raw JSON string output from `findmnt`.
        logger (logging.Logger): The logger instance.

    Returns:
        List[MountedEntry]: A list of MountedEntry objects representing currently mounted filesystems.
                            Returns an empty list if parsing fails or no filesystems are found.
    """
    mounted_entries: List[MountedEntry] = []
    try:
        import json # Import json only when needed, as it's a standard library anyway.
        data = json.loads(json_output)
        if not data or "filesystems" not in data or not isinstance(data["filesystems"], list):
            logger.warning("findmnt JSON output is empty or malformed (missing/invalid 'filesystems' key).")
            return []

        for fs in data["filesystems"]:
            # Extract relevant fields. 'SOURCE' typically is the device/remote path, 'TARGET' is the mount point.
            source = fs.get("SOURCE")
            target = fs.get("TARGET")
            fstype = fs.get("FSTYPE")
            options_str = fs.get("OPTIONS", "")
            uuid = fs.get("UUID")
            label = fs.get("LABEL")

            # Basic validation for essential fields.
            if not source or not target or not fstype:
                logger.debug(f"Skipping findmnt entry due to missing source/target/fstype: {fs}")
                continue

            # Split options string into a list.
            options = [opt.strip() for opt in options_str.split(',') if opt.strip()] if options_str else []

            # Create and append the MountedEntry.
            mounted_entries.append(
                MountedEntry(
                    source=source,
                    target=target,
                    fstype=fstype,
                    options=options,
                    uuid=uuid,
                    label=label
                )
            )
            logger.debug(f"Parsed current mount: Target='{target}', FSType='{fstype}', Source='{source}'")

    except json.JSONDecodeError as e:
        logger.error(f"Failed to decode findmnt JSON output: {e}. Raw output (first 200 chars): {json_output[:200]}...")
        return []
    except Exception as e:
        logger.error(f"An unexpected error occurred during findmnt JSON parsing: {e}", exc_info=True)
        return []

    return mounted_entries

def _get_current_mounted_filesystems(logger: logging.Logger) -> List[MountedEntry]:
    """
    Executes the 'findmnt -l -J' command to get a list of currently mounted filesystems
    and parses its JSON output into a list of MountedEntry objects.

    Args:
        logger (logging.Logger): The logger instance.

    Returns:
        List[MountedEntry]: A list of MountedEntry objects for currently mounted filesystems.
                            Returns an empty list if findmnt cannot be run or parsed.
    """
    logger.info("Retrieving current mount status using 'findmnt -l -J'...")

    # First, ensure findmnt is available before attempting to run it.
    if not _check_findmnt_availability(logger):
        logger.critical("findmnt command is not available or not executable. Cannot check current mounts.")
        return []

    try:
        # -l: List output format (verbose).
        # -J: JSON output format (most robust for programmatic parsing).
        # findmnt typically runs without elevated privileges for basic listing.
        command = [FINDMNT_COMMAND_PATH, "-l", "-J"]
        result = _execute_command(command, logger, check=True, capture_output=True, timeout=60) # Increased timeout for potentially slow systems.

        if result and result.stdout:
            current_mounts = _parse_findmnt_json_output(result.stdout, logger)
            logger.info(f"Successfully retrieved and parsed {len(current_mounts)} filesystems currently mounted.")
            return current_mounts
        else:
            logger.error("findmnt command returned no output or an empty JSON structure.")
            return []

    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
        logger.error(f"Failed to execute or parse findmnt command due to an error: {e}")
        return []
    except Exception as e:
        logger.error(f"An unexpected error occurred while attempting to get current mounts: {e}", exc_info=True)
        return []

# --- Comparison and Alerting Logic ---

def _send_alert(logger: logging.Logger, message: str, level: int = logging.ERROR) -> None:
    """
    Sends an alert message. This function currently logs the message and prints it to stderr.
    It is designed to be extensible for other alerting mechanisms like email, syslog, or webhooks.

    Args:
        logger (logging.Logger): The logger instance to use for logging the alert.
        message (str): The alert message content.
        level (int): The logging level for the alert (e.g., logging.ERROR, logging.CRITICAL).
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Log the alert message using the provided level.
    # This ensures the alert is recorded in the log file.
    if level == logging.CRITICAL:
        logger.critical(f"[ALERT] {message}")
    elif level == logging.ERROR:
        logger.error(f"[ALERT] {message}")
    elif level == logging.WARNING:
        logger.warning(f"[ALERT] {message}")
    else:
        logger.info(f"[ALERT] {message}") # Default for general alerts.

    # Also print to stderr for immediate visibility if the script is run interactively
    # or if stderr is captured by a monitoring system.
    sys.stderr.write(f"[{timestamp}] [ALERT {logging.getLevelName(level)}] {message}\n")

    # --- EXTENSION POINT: Advanced Alerting ---
    # To extend this script for more sophisticated alerting, uncomment and implement
    # the following sections based on your requirements.

    # Example 1: Sending email alerts
    # if config.alert_recipients and level >= logging.ERROR: # Only send emails for ERROR/CRITICAL
    #     try:
    #         import smtplib
    #         from email.mime.text import MIMEText
    #         # Configure email details
    #         sender_email = "nfs-checker@yourdomain.com"
    #         smtp_server = "localhost" # Or specify your SMTP server (e.g., "smtp.gmail.com", port 587)
    #         smtp_user = None # If your SMTP server requires authentication
    #         smtp_password = None # If your SMTP server requires authentication
    #
    #         msg = MIMEText(f"NFS Mount Checker Alert at {timestamp}:\n\n{message}")
    #         msg['Subject'] = f"NFS Mount Checker Alert - {logging.getLevelName(level)} - Host: {os.uname().nodename}"
    #         msg['From'] = sender_email
    #         msg['To'] = ", ".join(config.alert_recipients)
    #
    #         with smtplib.SMTP(smtp_server) as s:
    #             # s.starttls() # Uncomment if your SMTP server uses TLS
    #             # if smtp_user and smtp_password:
    #             #     s.login(smtp_user, smtp_password)
    #             s.send_message(msg)
    #         logger.debug(f"Email alert successfully sent to: {', '.join(config.alert_recipients)}")
    #     except Exception as mail_e:
    #         logger.error(f"Failed to send email alert to {', '.join(config.alert_recipients)}: {mail_e}", exc_info=True)

    # Example 2: Sending alerts to a webhook (e.g., Slack, Microsoft Teams, PagerDuty)
    # if webhook_url and level >= logging.ERROR:
    #     try:
    #         import requests # Requires 'requests' 3rd party library
    #         payload = {
    #             "text": f"NFS Mount Checker Alert! Host: {os.uname().nodename}\nLevel: {logging.getLevelName(level)}\nMessage: {message}",
    #             "username": "NFS Mount Checker Bot",
    #             "icon_emoji": ":warning:" # Or a URL to an icon
    #         }
    #         response = requests.post(webhook_url, json=payload, timeout=10)
    #         response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)
    #         logger.debug("Webhook alert sent successfully.")
    #     except requests.exceptions.RequestException as req_e:
    #         logger.error(f"Failed to send webhook alert to '{webhook_url}': {req_e}", exc_info=True)
    #     except ImportError:
    #         logger.error("Requests library not found. Cannot send webhook alerts. Install with 'pip install requests'.")


def _compare_expected_vs_current_mounts(
    expected_mounts: List[FstabEntry],
    current_mounts: List[MountedEntry],
    logger: logging.Logger,
    config: ScriptConfiguration # Configuration passed for potential alert recipients etc.
) -> List[str]:
    """
    Compares the list of expected network mounts (from fstab) with the
    list of currently mounted filesystems (from findmnt output).
    Identifies any configured network shares that are not currently mounted.

    Args:
        expected_mounts (List[FstabEntry]): List of network mounts defined in fstab.
        current_mounts (List[MountedEntry]): List of currently active mounts on the system.
        logger (logging.Logger): The logger instance.
        config (ScriptConfiguration): Script configuration object (used for alert mechanisms).

    Returns:
        List[str]: A list of human-readable alert messages for any unmounted shares found.
                   Returns an empty list if all expected shares are mounted.
    """
    unmounted_shares: List[str] = []
    logger.info("Starting comparison of expected vs. currently mounted network shares.")

    # Create a set of currently mounted targets for efficient lookup.
    # Normalize paths (e.g., remove trailing slashes) to ensure accurate comparisons
    # as fstab and findmnt might represent paths slightly differently.
    current_mounted_targets = {os.path.normpath(entry.target) for entry in current_mounts}
    logger.debug(f"Currently mounted targets (normalized): {current_mounted_targets}")

    # Iterate through each expected network mount defined in fstab.
    for expected_entry in expected_mounts:
        # Normalize the expected mount point from fstab for comparison.
        normalized_expected_target = os.path.normpath(expected_entry.mount_point)

        # Check if the expected mount point exists in the set of currently mounted targets.
        if normalized_expected_target not in current_mounted_targets:
            alert_message = (
                f"Network share '{expected_entry.mount_point}' (Type: {expected_entry.fs_type}, "
                f"Device: {expected_entry.device}) is configured in fstab but NOT currently mounted."
                f" Original fstab line: '{expected_entry.original_line}'"
            )
            unmounted_shares.append(alert_message)
            # Send an immediate alert for this critical finding.
            _send_alert(logger, alert_message, level=logging.ERROR)
            logger.error(f"Detected UNMOUNTED network share: {expected_entry}")
        else:
            logger.info(f"Network share '{expected_entry.mount_point}' is confirmed to be mounted.")
            # Advanced checks could be added here:
            # 1. Verify filesystem type: Check if `findmnt`'s reported `fstype` matches `fstab`'s `fs_type`.
            #    e.g., findmnt might report 'nfs' for an fstab entry with 'nfs4'. Consider normalization.
            # 2. Verify mount options: Compare `expected_entry.options` with `mounted_entry.options`.
            #    This is complex as options can be implicitly added or reordered by the kernel.

    if not unmounted_shares:
        logger.info("All configured network shares are currently mounted correctly. No issues found.")
    else:
        logger.critical(f"Comparison completed with {len(unmounted_shares)} UNMOUNTED network share(s) found.")

    return unmounted_shares

# --- Main Checker Class ---

class NfsMountChecker:
    """
    Main class for the NFS/SMB mount checker script.
    Encapsulates all logic for reading fstab, checking mounts, and alerting,
    providing an organized and object-oriented approach.
    """
    def __init__(self, config: ScriptConfiguration, logger: logging.Logger):
        """
        Initializes the NfsMountChecker with given configuration and logger instances.

        Args:
            config (ScriptConfiguration): The script's configuration object.
            logger (logging.Logger): The logger instance to use for all logging.
        """
        self.config = config
        self.logger = logger
        self.logger.info("NfsMountChecker instance initialized.")
        self.logger.debug(f"Configuration loaded: fstab_path='{self.config.fstab_path}', "
                          f"log_file_path='{self.config.log_file_path}', "
                          f"alert_recipients={self.config.alert_recipients if self.config.alert_recipients else '[None configured]'}")

    def run_check(self) -> int:
        """
        Orchestrates the entire mount checking process from start to finish.
        This is the primary entry point for executing the script's core logic.

        The steps include:
        1. Reading and parsing expected network mounts from /etc/fstab.
        2. Querying the system for currently mounted filesystems using `findmnt`.
        3. Comparing the expected mounts against the actual mounts to identify discrepancies.
        4. Sending alerts if any configured network shares are found to be unmounted.

        Returns:
            int: An exit code (0 for success, non-zero for errors or unmounted shares).
        """
        self.logger.info(f"Starting comprehensive NFS/SMB mount check process at {datetime.now().isoformat()}...")
        try:
            # Step 1: Retrieve expected network mounts from fstab.
            self.logger.debug("Calling _get_expected_network_mounts_from_fstab...")
            expected_mounts = _get_expected_network_mounts_from_fstab(
                self.config.fstab_path, self.logger
            )
            if not expected_mounts:
                self.logger.warning("No network mounts configured in fstab to check. Script will exit gracefully.")
                # If there are no network mounts configured, the check technically succeeds in finding no issues.
                return EXIT_CODE_SUCCESS

            # Step 2: Retrieve currently mounted filesystems using findmnt.
            self.logger.debug("Calling _get_current_mounted_filesystems...")
            current_mounts = _get_current_mounted_filesystems(self.logger)
            if not current_mounts:
                self.logger.error("Could not retrieve current mount status from the system. Cannot perform a full check.")
                _send_alert(self.logger, "Failed to retrieve current mount status (findmnt command issue). Cannot verify network shares.", level=logging.CRITICAL)
                return EXIT_CODE_RUNTIME_ERROR

            # Step 3: Compare the expected mounts with the currently active mounts.
            self.logger.debug("Calling _compare_expected_vs_current_mounts...")
            unmounted_shares = _compare_expected_vs_current_mounts(
                expected_mounts, current_mounts, self.logger, self.config
            )

            # Step 4: Determine the final exit code based on the comparison results.
            if unmounted_shares:
                self.logger.critical(f"Mount check finished with {len(unmounted_shares)} UNMOUNTED network share(s). Exiting with error code {EXIT_CODE_UNMOUNTED_SHARES}.")
                return EXIT_CODE_UNMOUNTED_SHARES
            else:
                self.logger.info(f"Mount check finished. All configured network shares are mounted correctly. Exiting with success code {EXIT_CODE_SUCCESS}.")
                return EXIT_CODE_SUCCESS

        except Exception as e:
            # Catch any unexpected exceptions during the main check execution.
            self.logger.critical(f"An unhandled fatal error occurred during the mount check process: {e}", exc_info=True)
            _send_alert(self.logger, f"Script terminated due to a critical, unhandled error: {e}", level=logging.CRITICAL)
            return EXIT_CODE_RUNTIME_ERROR

# --- Main Execution Block ---

def main() -> int:
    """
    Main function for the script. This function initializes the script's
    environment, sets up logging, and orchestrates the execution of the checker.
    """
    # 1. Initial Python Version Check: Ensures the script is run with a compatible Python version.
    _check_python_version(PYTHON_MIN_VERSION)

    # 2. Configuration Setup: Creates the ScriptConfiguration object,
    #    potentially overriding defaults with environment variables or command-line arguments.
    try:
        # Example of how to override default paths and alert recipients using environment variables.
        # This makes the script more flexible for different deployment environments.
        fstab_path_override = os.getenv("NFS_CHECKER_FSTAB_PATH", DEFAULT_FSTAB_PATH)
        log_file_path_override = os.getenv("NFS_CHECKER_LOG_FILE_PATH", DEFAULT_LOG_FILE_PATH)
        alert_emails_raw = os.getenv("NFS_CHECKER_ALERT_EMAILS", "") # Comma-separated list
        alert_recipients_list = [email.strip() for email in alert_emails_raw.split(',') if email.strip()]

        config = ScriptConfiguration(
            fstab_path=fstab_path_override,
            log_file_path=log_file_path_override,
            alert_recipients=alert_recipients_list
        )
    except ValueError as ve:
        # Catch configuration validation errors.
        sys.stderr.write(f"ERROR: Script configuration error: {ve}\n")
        return EXIT_CODE_CONFIGURATION_ERROR
    except Exception as e:
        # Catch any other unexpected errors during configuration setup.
        sys.stderr.write(f"ERROR: Unexpected error during script configuration setup: {e}\n")
        return EXIT_CODE_RUNTIME_ERROR

    # 3. Logger Setup: Initializes the logging system based on the configured log file path.
    #    This is done early so all subsequent actions can be logged.
    logger = None # Initialize to None for error handling outside try block.
    try:
        logger = _setup_logging(config.log_file_path, logging.INFO)
    except Exception as e:
        sys.stderr.write(f"CRITICAL ERROR: Failed to setup logging. All output will go to stderr: {e}\n")
        # If logging itself fails, we can't rely on the logger, so print to stderr and exit.
        return EXIT_CODE_RUNTIME_ERROR

    logger.info("NFS Mount Checker script execution started.")
    logger.debug(f"Resolved Configuration: FSTAB='{config.fstab_path}', LOG='{config.log_file_path}', ALERTS='{config.alert_recipients}'")

    # 4. Instantiate and Run Checker: Creates an instance of the NfsMountChecker class
    #    and invokes its main `run_check` method.
    exit_code = EXIT_CODE_RUNTIME_ERROR # Default to error in case of unhandled exception.
    try:
        checker = NfsMountChecker(config, logger)
        exit_code = checker.run_check()
    except Exception as e:
        # If an error occurs even after the checker has started, log it as critical.
        logger.critical(f"Fatal unhandled error during NfsMountChecker execution: {e}", exc_info=True)
        _send_alert(logger, f"Script terminated due to a fatal, unhandled error: {e}", level=logging.CRITICAL)
        exit_code = EXIT_CODE_RUNTIME_ERROR

    logger.info(f"NFS Mount Checker script execution finished with exit code: {exit_code}")
    return exit_code

if __name__ == "__main__":
    # This block ensures that `main()` is called only when the script is executed directly
    # (not when imported as a module). The `sys.exit()` call passes the integer exit code
    # back to the operating system, which is crucial for cron jobs and monitoring tools.
    sys.exit(main())