import os
import sys
import subprocess
import logging
import datetime
import time
import shutil

# --- Configuration Section ---
# This dictionary holds all configurable parameters for the automated server teardown script.
# It is designed to be easily modified without changing the core logic of the script.
# For a production environment, these settings could be loaded from an external YAML, JSON,
# or INI file to enhance flexibility and manageability, but for this self-contained script,
# a Python dictionary is used.
CONFIG = {
    # General script settings
    "SCRIPT_NAME": "Automated Server Teardown Script",
    "DRY_RUN": True,  # IMPORTANT: Set to False to actually execute commands like poweroff,
                      # unmount, and stop services.
                      # It is highly recommended to keep this True for initial testing
                      # in any environment, especially production.
    "WAIT_AFTER_SERVICE_STOP_SECONDS": 5,  # Seconds to wait after sending a stop command to a service
    "SERVICE_STOP_TIMEOUT_SECONDS": 60,    # Maximum seconds to wait for a service to gracefully stop
    "UNMOUNT_RETRY_ATTEMPTS": 3,           # Number of retries for unmounting network shares
    "UNMOUNT_RETRY_DELAY_SECONDS": 5,      # Delay in seconds between unmount retries
    "UNMOUNT_FORCE_AFTER_RETRIES": True,   # If graceful unmount fails after retries, attempt a force unmount (-f)
    "BACKUP_RETENTION_DAYS": 7,            # Number of days to keep old backups for cleanup purposes (0 for no cleanup)
    "SERVER_IDENTIFIER": "production-web-server-01", # A unique identifier for this server, used in backup filenames and logs.
                                                     # Helps in distinguishing backups from different servers.

    # Logging settings
    "LOG_DIR": "/var/log/server-teardown", # Directory where log files will be stored.
                                           # Ensure this directory has appropriate write permissions for the script user.
    "LOG_FILE_NAME": "teardown.log",       # Name of the main log file.
    "LOG_LEVEL": logging.INFO,             # Global logging level. Options: logging.DEBUG, logging.INFO,
                                           # logging.WARNING, logging.ERROR, logging.CRITICAL.
                                           # INFO is good for production; DEBUG for detailed troubleshooting.

    # Services to stop (order matters!)
    # This list defines critical services that must be stopped gracefully before other operations
    # like backups or unmounting network shares. Services are stopped in the order they appear
    # in this list. Systemd service names are expected (e.g., 'apache2', 'mysql').
    "SERVICES_TO_STOP": [
        "apache2",        # Example: Apache HTTP Server
        "nginx",          # Example: NGINX web server or reverse proxy
        "mysql",          # Example: MySQL/MariaDB database server
        "postgresql",     # Example: PostgreSQL database server
        "redis-server",   # Example: Redis in-memory data store
        "tomcat",         # Example: Apache Tomcat application server
        "jenkins",        # Example: Jenkins CI/CD server
        "docker",         # Example: Docker daemon (if applications are containerized)
        "cron",           # Example: Cron job scheduler (stopping may prevent new jobs from starting)
        "rsyslog"         # Example: System logging daemon (stop gracefully to ensure logs are written)
    ],

    # Backup configurations
    # Each dictionary in this list represents a distinct backup task.
    # The script will iterate through these configurations and attempt to perform each backup.
    #   - "name": A descriptive name for the backup (e.g., "application_data").
    #   - "type": The type of backup. Currently, "directory" is robustly handled.
    #             "database" is a placeholder for future expansion (e.g., using pg_dump, mysqldump).
    #   - "source": The absolute path to the directory or data to be backed up.
    #   - "destination": The absolute path to the directory where the backup archive will be stored.
    #                    This should typically be a local temporary storage before poweroff.
    #   - "exclude_patterns": (Optional) A list of patterns (glob-style or regex depending on tool)
    #                         to exclude from the backup (e.g., "cache/", "*.log").
    "BACKUP_CONFIGS": [
        {
            "name": "critical_app_data",
            "type": "directory",
            "source": "/var/www/html/my_application",
            "destination": "/tmp/teardown_backups", # Local temporary storage
            "exclude_patterns": ["cache/", "*.log", "*.tmp", "node_modules/", ".git/"]
        },
        {
            "name": "server_config_files",
            "type": "directory",
            "source": "/etc",
            "destination": "/tmp/teardown_backups",
            "exclude_patterns": [
                "/etc/ssl/private",  # Exclude sensitive private keys
                "/etc/ssh",          # Exclude SSH host keys and config (consider backing up selectively if needed)
                "*.bak", "*.old", "*.disabled", # Exclude temporary/old config files
                "certs/", "keys/", # More specific exclusions
                "/etc/pki/tls/private", # RHEL/CentOS specific private key path
                "/etc/cups" # Common large/less critical directory
            ]
        },
        {
            "name": "database_dumps",
            "type": "directory", # For now, we backup a directory potentially containing pre-generated dumps.
            "source": "/var/lib/mysql_dumps", # Assume a pre-script or cron generates these dumps
            "destination": "/tmp/teardown_backups",
            "exclude_patterns": []
        }
        # Add more backup configurations as needed for different critical data
    ],

    # Network shares to unmount
    # This list defines network shares (e.g., NFS, CIFS) that need to be unmounted gracefully
    # before the server powers off. Shares are unmounted in the order they appear.
    # Ensure these are the correct mount points on the system.
    "NETWORK_SHARES_TO_UNMOUNT": [
        "/mnt/nfs_data",
        "/mnt/cifs_share",
        "/home/user/remote_drive", # Example of a user-mounted remote drive
        "/var/www/shared_content", # Example of a shared content directory
        "/opt/shared_applications" # Example of a shared application binary directory
    ],

    # External command paths
    # These paths ensure the script can find and execute necessary system utilities.
    # Verify these paths are correct for your specific Linux distribution and setup.
    "COMMAND_SYSTEMCTL": "/usr/bin/systemctl",   # Systemd service manager
    "COMMAND_MOUNT": "/usr/bin/mount",           # Utility to mount filesystems
    "COMMAND_UMOUNT": "/usr/bin/umount",         # Utility to unmount filesystems
    "COMMAND_TAR": "/usr/bin/tar",               # Archiving utility for backups
    "COMMAND_RSYNC": "/usr/bin/rsync",           # (Optional) Can be used for incremental/more advanced backups if configured
    "COMMAND_POWEROFF": "/usr/sbin/poweroff",    # Command to shut down the system. Alternatives: "/sbin/poweroff", "/usr/bin/shutdown -h now"
    "COMMAND_LSBLK": "/usr/bin/lsblk",           # Lists block devices (useful for checking mounts)
    "COMMAND_FIND": "/usr/bin/find",             # Utility to find files (used for backup cleanup)
    "COMMAND_RM": "/usr/bin/rm"                  # Utility to remove files (used for backup cleanup)
}

# --- Global Logger Instance ---
# This logger object will be initialized once during script setup and used throughout
# to centralize all logging operations.
logger = None

def setup_logging():
    """
    Configures the global logger for the script.
    Sets up a file handler to write logs to a file and a console handler
    to output logs to standard output, both with detailed formatting.
    Ensures the log directory exists before setting up the file handler.
    """
    global logger
    if logger is not None:
        return logger # Return existing logger if already configured

    # Ensure the log directory exists; create it if it doesn't.
    log_dir = CONFIG["LOG_DIR"]
    try:
        os.makedirs(log_dir, exist_ok=True, mode=0o750) # Create with specific permissions
        logger_path = os.path.join(log_dir, CONFIG["LOG_FILE_NAME"])
    except OSError as e:
        # Fallback to current directory if log_dir creation fails
        sys.stderr.write(f"WARNING: Could not create log directory '{log_dir}': {e}. "
                         f"Logging to current directory.\n")
        log_dir = os.getcwd()
        logger_path = os.path.join(log_dir, CONFIG["LOG_FILE_NAME"])

    # Initialize the logger instance
    logger = logging.getLogger(CONFIG["SCRIPT_NAME"])
    logger.setLevel(CONFIG["LOG_LEVEL"])
    logger.propagate = False # Prevent logs from propagating to the root logger

    # Define a consistent log formatter for all handlers
    formatter = logging.Formatter(
        "[%(asctime)s] - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Console Handler: Outputs logs to stdout
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO) # Console typically shows INFO and above
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File Handler: Outputs logs to a specified file
    file_handler = logging.FileHandler(logger_path)
    file_handler.setLevel(CONFIG["LOG_LEVEL"]) # File logs at the configured global level
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    logger.info(f"Logging initialized. Outputting to console and log file: {logger_path}")
    logger.info(f"Dry run mode is {'ENABLED' if CONFIG['DRY_RUN'] else 'DISABLED'}. "
                "No destructive actions will be taken if dry run is enabled.")
    return logger

def execute_command(command_parts, capture_output=False, check_result=True, timeout=180, description="command"):
    """
    Executes a shell command using subprocess.run, providing robust error handling,
    logging, and support for a dry-run mode.

    Args:
        command_parts (list): A list of strings representing the command and its arguments.
                              Example: ["ls", "-l", "/tmp"].
        capture_output (bool): If True, stdout and stderr are captured and returned.
                               Otherwise, they are streamed to the parent process's stdout/stderr.
        check_result (bool): If True, a subprocess.CalledProcessError is raised if the command
                             returns a non-zero exit code.
        timeout (int): Maximum time in seconds to wait for the command to complete.
        description (str): A human-readable description of the command for logging purposes.

    Returns:
        subprocess.CompletedProcess: An object containing the command's exit code, stdout, and stderr.
                                     In dry-run mode, a simulated successful result is returned.

    Raises:
        FileNotFoundError: If the command executable is not found.
        subprocess.TimeoutExpired: If the command exceeds the specified timeout.
        subprocess.CalledProcessError: If check_result is True and the command fails.
        Exception: For any other unexpected errors during command execution.
    """
    cmd_str = " ".join(command_parts)
    logger.debug(f"Attempting to execute '{description}': {cmd_str}")

    if CONFIG["DRY_RUN"]:
        logger.info(f"DRY RUN: Would execute '{description}': {cmd_str}")
        # Simulate a successful command execution for dry-run mode
        return subprocess.CompletedProcess(command_parts, 0, stdout="Dry run success\n", stderr="")

    try:
        result = subprocess.run(
            command_parts,
            capture_output=capture_output,
            text=True,  # Decode stdout/stderr as text using default encoding
            check=check_result,
            timeout=timeout
        )
        if capture_output:
            # Log captured output only if debugging is enabled, otherwise it can be too verbose
            if result.stdout:
                logger.debug(f"'{description}' STDOUT: {result.stdout.strip()}")
            if result.stderr:
                logger.warning(f"'{description}' STDERR: {result.stderr.strip()}")
        logger.debug(f"Successfully executed '{description}'. Exit code: {result.returncode}")
        return result
    except FileNotFoundError:
        logger.error(f"Command '{command_parts[0]}' not found. Is it installed and in PATH? "
                     f"Check configuration for the correct path for '{command_parts[0]}'.")
        raise # Re-raise to halt execution if a critical command is missing
    except subprocess.TimeoutExpired:
        logger.error(f"Command '{description}' timed out after {timeout} seconds: {cmd_str}")
        raise # Re-raise as this is a critical failure
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to execute '{description}'. Command: '{e.cmd}' "
                     f"Exit code: {e.returncode}. STDOUT: '{e.stdout.strip()}'. STDERR: '{e.stderr.strip()}'")
        raise # Re-raise to propagate the error
    except Exception as e:
        logger.error(f"An unexpected error occurred while executing '{description}': {e}", exc_info=True)
        raise # Catch all other exceptions

def check_prerequisites():
    """
    Performs initial checks to ensure the script has the necessary permissions and tools
    to execute its tasks. This includes:
    1. Verifying root privileges (unless in dry-run mode).
    2. Checking for the existence and executability of all required external utilities.
    If any critical prerequisite is not met, the script will log an error and exit.
    """
    logger.info("--- Starting prerequisite checks ---")

    # 1. Check for root privileges
    if os.geteuid() != 0 and not CONFIG["DRY_RUN"]:
        logger.critical("This script requires root privileges to stop services, unmount shares, and poweroff.")
        logger.critical("Please run as root using 'sudo' or as the root user directly. Exiting.")
        sys.exit(1)
    elif CONFIG["DRY_RUN"] and os.geteuid() != 0:
        logger.warning("Running in DRY_RUN mode without root privileges. "
                       "Actual execution of commands like 'poweroff' would require root.")
    else:
        logger.info("Root privileges confirmed or dry run enabled.")

    # 2. Check for required external utilities
    required_commands = [
        ("systemctl", CONFIG["COMMAND_SYSTEMCTL"]),
        ("mount", CONFIG["COMMAND_MOUNT"]),
        ("umount", CONFIG["COMMAND_UMOUNT"]),
        ("tar", CONFIG["COMMAND_TAR"]),
        ("poweroff", CONFIG["COMMAND_POWEROFF"]),
        ("lsblk", CONFIG["COMMAND_LSBLK"]),
        ("find", CONFIG["COMMAND_FIND"])
    ]
    # Add rsync to required commands if any backup config is using it, or generally if it's expected
    # For now, tar is primary, but good to check if rsync is available.
    # if CONFIG["BACKUP_CONFIGS"] and any(c.get("type") == "rsync_backup" for c in CONFIG["BACKUP_CONFIGS"]):
    #    required_commands.append(("rsync", CONFIG["COMMAND_RSYNC"]))


    missing_commands = []
    for cmd_name, cmd_path in required_commands:
        if not cmd_path: # Check if the path is explicitly empty in config
             logger.error(f"Configuration error: Command path for '{cmd_name}' is empty.")
             missing_commands.append(cmd_name)
        elif not os.path.isfile(cmd_path):
            logger.error(f"Required command '{cmd_name}' not found at specified path: '{cmd_path}'.")
            missing_commands.append(cmd_name)
        elif not os.access(cmd_path, os.X_OK):
            logger.error(f"Required command '{cmd_name}' at '{cmd_path}' is not executable.")
            missing_commands.append(cmd_name)
    
    if missing_commands:
        logger.critical(f"Missing one or more critical system commands: {', '.join(missing_commands)}. "
                        "Please install them or correct their paths in the configuration. Exiting.")
        sys.exit(1)
    else:
        logger.info("All required external commands found and are executable.")

    logger.info("--- Prerequisite checks completed successfully ---")

def get_service_status(service_name):
    """
    Checks the current status of a systemd service.
    Args:
        service_name (str): The name of the systemd service (e.g., "apache2").
    Returns:
        bool: True if the service is reported as 'active' by systemctl, False otherwise.
    """
    logger.debug(f"Checking status of service: '{service_name}'")
    try:
        result = execute_command(
            [CONFIG["COMMAND_SYSTEMCTL"], "is-active", service_name],
            capture_output=True,
            check_result=False, # We evaluate status based on output, not just exit code
            description=f"get service status for {service_name}"
        )
        status = result.stdout.strip()
        if status == "active":
            logger.info(f"Service '{service_name}' is currently active.")
            return True
        else:
            logger.info(f"Service '{service_name}' is currently inactive or reported as '{status}'.")
            return False
    except Exception as e:
        logger.error(f"Failed to check status of service '{service_name}': {e}")
        return False

def stop_service(service_name):
    """
    Attempts to stop a specified systemd service gracefully.
    It includes a timeout mechanism to ensure the script doesn't hang indefinitely
    waiting for a service that fails to stop.
    Args:
        service_name (str): The name of the systemd service to stop.
    Returns:
        bool: True if the service was successfully stopped, False otherwise.
    """
    if not get_service_status(service_name):
        logger.info(f"Service '{service_name}' is already stopped or inactive. Skipping stop command.")
        return True

    logger.info(f"Attempting to stop service: '{service_name}'")
    try:
        execute_command(
            [CONFIG["COMMAND_SYSTEMCTL"], "stop", service_name],
            description=f"stop service {service_name}"
        )
        logger.info(f"Initiated stop command for service '{service_name}'. Waiting for it to cease activity.")

        # Wait for the service to actually stop, checking its status periodically
        start_time = time.time()
        while time.time() - start_time < CONFIG["SERVICE_STOP_TIMEOUT_SECONDS"]:
            if not get_service_status(service_name):
                logger.info(f"Service '{service_name}' successfully stopped after "
                            f"{int(time.time() - start_time)} seconds.")
                return True
            logger.debug(f"Service '{service_name}' still running after {int(time.time() - start_time)}s. "
                         f"Waiting for {CONFIG['WAIT_AFTER_SERVICE_STOP_SECONDS']}s...")
            time.sleep(CONFIG["WAIT_AFTER_SERVICE_STOP_SECONDS"])

        logger.warning(f"Service '{service_name}' did not stop within "
                       f"{CONFIG['SERVICE_STOP_TIMEOUT_SECONDS']} seconds. It may still be running.")
        return False
    except Exception as e:
        logger.error(f"An error occurred while stopping service '{service_name}': {e}", exc_info=True)
        return False

def stop_all_critical_services():
    """
    Orchestrates the shutdown of all critical services defined in the configuration.
    Services are stopped in the order they are listed. This sequential shutdown helps
    maintain system stability and data integrity, especially for dependencies.
    Returns:
        bool: True if all configured services were successfully stopped or were already inactive,
              False if one or more services failed to stop.
    """
    logger.info("--- Starting critical services graceful shutdown sequence ---")
    all_services_stopped = True
    services_failed_to_stop = []

    if not CONFIG["SERVICES_TO_STOP"]:
        logger.info("No critical services configured to stop. Skipping service shutdown phase.")
        return True

    for service_name in CONFIG["SERVICES_TO_STOP"]:
        if not stop_service(service_name):
            logger.error(f"Critical service '{service_name}' failed to stop. This is a potential issue.")
            all_services_stopped = False
            services_failed_to_stop.append(service_name)
        else:
            logger.info(f"Service '{service_name}' handled successfully (stopped or already inactive).")

    if all_services_stopped:
        logger.info("All configured critical services successfully stopped.")
    else:
        logger.warning(f"One or more critical services failed to stop: {', '.join(services_failed_to_stop)}. "
                       "Proceeding with teardown, but be aware of potential issues with data integrity "
                       "or resources being held open.")
    logger.info("--- Critical services shutdown sequence completed ---")
    return all_services_stopped

def get_mounted_filesystems():
    """
    Retrieves a list of currently mounted filesystems from the system.
    This function parses the output of the 'mount' command to identify
    active mount points.
    Returns:
        dict: A dictionary where keys are mount points (e.g., "/mnt/data")
              and values are the corresponding device paths (e.g., "/dev/sdb1").
              Returns an empty dictionary if unable to retrieve mount information.
    """
    mounted_filesystems = {}
    try:
        # execute_command ensures logging and dry-run handling
        result = execute_command(
            [CONFIG["COMMAND_MOUNT"]],
            capture_output=True,
            description="list mounted filesystems",
            check_result=True # Expect mount command to succeed
        )
        for line in result.stdout.splitlines():
            # Example line: /dev/sda1 on / type ext4 (rw,relatime)
            # Example line: 192.168.1.100:/data on /mnt/nfs_data type nfs4 (rw,relatime,vers=4.1,rsize=262144,wsize=262144,namlen=255,hard,proto=tcp,timeo=600,retrans=2,sec=sys,clientaddr=...,local_lock=none,addr=...)
            parts = line.split()
            if " on " in line and " type " in line:
                try:
                    device_part = line.split(" on ")[0].strip()
                    mount_point_part = line.split(" on ")[1].split(" type ")[0].strip()
                    
                    # Basic heuristic: mount point usually starts with '/', device path could be complex
                    if mount_point_part.startswith('/'):
                        # For network shares, device_part might be like "server:/share"
                        # For local, it might be "/dev/sdaX" or UUID=...
                        mounted_filesystems[mount_point_part] = device_part
                except IndexError:
                    logger.debug(f"Skipping potentially malformed mount line during parsing: {line}")
            else:
                logger.debug(f"Skipping non-relevant mount output line: {line}")
        logger.debug(f"Detected mounted filesystems: {mounted_filesystems}")
    except Exception as e:
        logger.error(f"Failed to get list of mounted filesystems: {e}", exc_info=True)
        # Continue with empty dict rather than halt if mount listing fails
    return mounted_filesystems

def is_share_mounted(share_path):
    """
    Checks if a specific network share path is currently mounted on the system.
    Args:
        share_path (str): The absolute path of the mount point to check (e.g., "/mnt/nfs_data").
    Returns:
        bool: True if the share is found in the list of mounted filesystems, False otherwise.
    """
    mounted_filesystems = get_mounted_filesystems()
    return share_path in mounted_filesystems

def unmount_network_share(share_path):
    """
    Attempts to unmount a specified network share gracefully. If graceful unmount fails
    after several retries, it can optionally attempt a forceful unmount.
    Args:
        share_path (str): The absolute path of the network share (mount point) to unmount.
    Returns:
        bool: True if the share was successfully unmounted, False otherwise.
    """
    if not is_share_mounted(share_path):
        logger.info(f"Network share '{share_path}' is not currently mounted. Skipping unmount operation.")
        return True

    logger.info(f"Attempting to unmount network share: '{share_path}'")
    for attempt in range(CONFIG["UNMOUNT_RETRY_ATTEMPTS"]):
        try:
            logger.debug(f"Unmount attempt {attempt + 1}/{CONFIG['UNMOUNT_RETRY_ATTEMPTS']} for '{share_path}'...")
            execute_command(
                [CONFIG["COMMAND_UMOUNT"], share_path],
                description=f"unmount {share_path}",
                check_result=True # Expect umount command to succeed
            )
            # Re-check if it's truly unmounted after the command
            if not is_share_mounted(share_path):
                logger.info(f"Successfully unmounted '{share_path}' on attempt {attempt + 1}.")
                return True
            else:
                logger.warning(f"Unmount command for '{share_path}' appeared to succeed, but the share is still reported as mounted. "
                               f"Attempt {attempt + 1}/{CONFIG['UNMOUNT_RETRY_ATTEMPTS']}.")
        except Exception as e:
            logger.warning(f"Failed to unmount '{share_path}' on attempt {attempt + 1}/{CONFIG['UNMOUNT_RETRY_ATTEMPTS']}: {e}")
        
        # If it's the last attempt and force unmount is enabled, skip sleep to try force immediately
        if attempt < CONFIG["UNMOUNT_RETRY_ATTEMPTS"] - 1:
            time.sleep(CONFIG["UNMOUNT_RETRY_DELAY_SECONDS"])

    # If all graceful retries failed, and force unmount is enabled and not in dry-run mode
    if CONFIG["UNMOUNT_FORCE_AFTER_RETRIES"]:
        if CONFIG["DRY_RUN"]:
            logger.info(f"DRY RUN: Would attempt force unmount for '{share_path}' after graceful retries failed.")
        else:
            logger.warning(f"All graceful unmount attempts for '{share_path}' failed. "
                           "Attempting force unmount (-f) as configured.")
            try:
                execute_command(
                    [CONFIG["COMMAND_UMOUNT"], "-f", share_path],
                    description=f"force unmount {share_path}",
                    check_result=True
                )
                if not is_share_mounted(share_path):
                    logger.info(f"Successfully force unmounted '{share_path}'.")
                    return True
                else:
                    logger.error(f"Force unmount for '{share_path}' executed, but it still appears mounted. "
                                 "This is highly unusual and indicates a deeper issue.")
            except Exception as e:
                logger.error(f"Failed to force unmount '{share_path}': {e}", exc_info=True)
    
    logger.error(f"Failed to unmount network share '{share_path}' after all attempts (graceful and force if enabled).")
    return False

def unmount_all_network_shares():
    """
    Orchestrates the unmounting of all network shares defined in the configuration.
    Shares are unmounted in the order they appear in the configuration list.
    Returns:
        bool: True if all configured shares were successfully unmounted or were already unmounted,
              False if one or more shares failed to unmount.
    """
    logger.info("--- Starting network shares unmount sequence ---")
    all_shares_unmounted = True
    shares_failed_to_unmount = []

    if not CONFIG["NETWORK_SHARES_TO_UNMOUNT"]:
        logger.info("No network shares configured to unmount. Skipping unmount phase.")
        return True

    for share_path in CONFIG["NETWORK_SHARES_TO_UNMOUNT"]:
        if not unmount_network_share(share_path):
            logger.error(f"Network share '{share_path}' failed to unmount. This may leave resources locked.")
            all_shares_unmounted = False
            shares_failed_to_unmount.append(share_path)
        else:
            logger.info(f"Network share '{share_path}' handled successfully (unmounted or already unmounted).")

    if all_shares_unmounted:
        logger.info("All configured network shares successfully unmounted.")
    else:
        logger.warning(f"One or more network shares failed to unmount: {', '.join(shares_failed_to_unmount)}. "
                       "Proceeding, but this may indicate issues and could prevent a clean shutdown "
                       "or data loss on those shares.")
    logger.info("--- Network shares unmount sequence completed ---")
    return all_shares_unmounted

def create_directory_backup(config_entry):
    """
    Performs a directory backup using the 'tar' utility.
    The backup is compressed (gzip) and stored with a timestamped filename.
    Args:
        config_entry (dict): A dictionary containing configuration for a specific backup task,
                             including name, source path, destination path, and exclude patterns.
    Returns:
        bool: True if the backup archive was successfully created, False otherwise.
    """
    backup_name = config_entry["name"]
    source_path = config_entry["source"]
    destination_dir = config_entry["destination"]
    exclude_patterns = config_entry.get("exclude_patterns", [])

    logger.info(f"Attempting to create directory backup for '{backup_name}' from source: '{source_path}' "
                f"to destination: '{destination_dir}'")

    if not os.path.exists(source_path):
        logger.error(f"Backup source path '{source_path}' does not exist. Skipping backup '{backup_name}'.")
        return False
    if not os.path.isdir(source_path):
        logger.error(f"Backup source path '{source_path}' is not a directory. Skipping backup '{backup_name}'.")
        return False

    try:
        os.makedirs(destination_dir, exist_ok=True, mode=0o750)
    except OSError as e:
        logger.error(f"Failed to create backup destination directory '{destination_dir}': {e}. Skipping backup '{backup_name}'.")
        return False
    
    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_filename = f"{CONFIG['SERVER_IDENTIFIER']}-{backup_name}-{timestamp}.tar.gz"
    backup_filepath = os.path.join(destination_dir, backup_filename)

    # Construct the tar command. Using -C to change directory to the parent of source_path
    # This ensures that the archive contains 'source_path' itself, not just its contents,
    # and handles absolute paths correctly within the archive.
    tar_command = [
        CONFIG["COMMAND_TAR"],
        "-czf", backup_filepath,      # Create, gzip, file
        "-C", os.path.dirname(source_path) # Change directory to parent of source
    ]
    tar_command.append(os.path.basename(source_path)) # Add the actual directory to backup

    for pattern in exclude_patterns:
        tar_command.extend(["--exclude", pattern])

    try:
        execute_command(
            tar_command,
            description=f"create tar.gz backup for {backup_name}",
            check_result=True,
            timeout=3600 # Allow generous time for large backups (1 hour)
        )
        if not CONFIG["DRY_RUN"] and not os.path.exists(backup_filepath):
            logger.error(f"Backup command for '{backup_name}' completed, but the expected archive file "
                         f"'{backup_filepath}' was not found. This might indicate an issue with tar.")
            return False
        logger.info(f"Successfully created directory backup: {backup_filepath}")
        return True
    except Exception as e:
        logger.error(f"Failed to create directory backup for '{backup_name}': {e}", exc_info=True)
        return False

def cleanup_old_backups(destination_dir):
    """
    Cleans up old backup archives in a specified directory based on the configured retention policy.
    It identifies files matching a specific naming pattern and deletes those older than
    `BACKUP_RETENTION_DAYS`.
    Args:
        destination_dir (str): The directory containing the backup archives to clean up.
    """
    if CONFIG["DRY_RUN"]:
        logger.info(f"DRY RUN: Skipping cleanup of old backups in '{destination_dir}'.")
        return

    if not CONFIG["BACKUP_RETENTION_DAYS"] or CONFIG["BACKUP_RETENTION_DAYS"] <= 0:
        logger.info(f"Backup retention days is set to {CONFIG['BACKUP_RETENTION_DAYS']}. Skipping cleanup.")
        return

    logger.info(f"Cleaning up old backups in '{destination_dir}' older than {CONFIG['BACKUP_RETENTION_DAYS']} days.")
    
    # Construct the `find` command to locate old backup files
    # It searches for files (`-type f`) in `destination_dir` that match the backup naming pattern
    # (`-name "{SERVER_IDENTIFIER}-*.tar.gz"`) and have been modified more than `BACKUP_RETENTION_DAYS` ago (`-mtime`).
    find_command = [
        CONFIG["COMMAND_FIND"], destination_dir,
        "-name", f"{CONFIG['SERVER_IDENTIFIER']}-*.tar.gz",
        "-type", "f",
        "-mtime", f"+{CONFIG['BACKUP_RETENTION_DAYS']}"
    ]
    
    try:
        result = execute_command(
            find_command,
            capture_output=True,
            check_result=False, # find might exit non-zero if no files are found, which is fine
            description=f"find old backups in {destination_dir}"
        )
        files_to_delete = result.stdout.strip().splitlines()

        if not files_to_delete:
            logger.info(f"No old backups found in '{destination_dir}' for cleanup based on retention policy.")
            return

        logger.info(f"Found {len(files_to_delete)} old backups to delete in '{destination_dir}'.")
        for file_path in files_to_delete:
            if not os.path.exists(file_path):
                logger.debug(f"File '{file_path}' no longer exists, skipping deletion.")
                continue
            try:
                logger.info(f"Deleting old backup file: {file_path}")
                # Using os.remove for direct file deletion; for directories shutil.rmtree might be used
                os.remove(file_path) 
            except OSError as e:
                logger.error(f"Error deleting old backup file '{file_path}': {e}", exc_info=True)
            except Exception as e:
                logger.error(f"An unexpected error occurred while trying to delete '{file_path}': {e}", exc_info=True)

        logger.info(f"Finished cleanup of old backups in '{destination_dir}'.")

    except Exception as e:
        logger.error(f"Error during the process of cleaning up old backups in '{destination_dir}': {e}", exc_info=True)

def perform_all_backups():
    """
    Orchestrates the execution of all configured backup tasks.
    It iterates through the `BACKUP_CONFIGS` list and calls the appropriate
    backup function for each configured item (currently primarily directory backups).
    After all backups are attempted, it triggers a cleanup of old backups in each
    unique destination directory.
    Returns:
        bool: True if all configured backup tasks completed successfully, False otherwise.
    """
    logger.info("--- Starting final backup sequence ---")
    all_backups_successful = True
    failed_backups = []
    processed_destination_dirs = set() # To ensure cleanup is run only once per unique destination

    if not CONFIG["BACKUP_CONFIGS"]:
        logger.info("No backup configurations specified. Skipping final backup phase.")
        return True

    for backup_conf in CONFIG["BACKUP_CONFIGS"]:
        backup_type = backup_conf.get("type", "unknown").lower()
        backup_name = backup_conf.get("name", "unnamed_backup")
        destination_dir = backup_conf.get("destination")

        if not destination_dir:
            logger.error(f"Backup '{backup_name}' is missing a destination directory. Skipping this backup task.")
            all_backups_successful = False
            failed_backups.append(backup_name)
            continue

        processed_destination_dirs.add(destination_dir) # Add to set for later cleanup

        if backup_type == "directory":
            if not create_directory_backup(backup_conf):
                logger.error(f"Backup task '{backup_name}' (directory) failed.")
                all_backups_successful = False
                failed_backups.append(backup_name)
            else:
                logger.info(f"Backup task '{backup_name}' (directory) completed successfully.")
        elif backup_type == "database":
            # Placeholder for actual database backup logic (e.g., `pg_dump`, `mysqldump`).
            # This would involve specific commands and potentially credentials.
            # For this script, we assume directory backups can contain pre-generated database dumps.
            logger.warning(f"Database backup for '{backup_name}' is noted as 'database' type. "
                           "Actual database dumping logic is a placeholder and not fully implemented for direct execution. "
                           "Assuming it's handled by pre-existing dumps in a directory that is backed up.")
            # If this was meant to be a direct DB dump, and it's not implemented, it's effectively a failure
            # For now, if the source path exists, we treat it as potentially pre-dumped data within a directory backup.
            # If direct database backup logic was implemented here, it would be a specific function call.
            # For now, it's a "soft fail" or "pass-through" depending on actual needs.
            # To be strict, we'll mark it as a warning that it's not fully implemented for a direct dump.
            logger.warning(f"Backup '{backup_name}' (database type) functionality is a placeholder. "
                           "Please implement specific database dump commands if direct database backups are required.")
            # Marking as failed to be cautious, as direct database dumping is critical.
            all_backups_successful = False
            failed_backups.append(f"{backup_name} (Database type - explicit dump not implemented)")
        else:
            logger.error(f"Unknown backup type '{backup_type}' specified for backup task '{backup_name}'. Skipping.")
            all_backups_successful = False
            failed_backups.append(f"{backup_name} (Unknown type: {backup_type})")

    # After all backup attempts, perform cleanup for each unique destination directory
    logger.info("Starting cleanup of old backups across all configured destination directories.")
    for dest_dir in processed_destination_dirs:
        cleanup_old_backups(dest_dir)

    if all_backups_successful:
        logger.info("All final backup tasks completed successfully or handled gracefully.")
    else:
        logger.error(f"One or more backup tasks failed: {', '.join(failed_backups)}. "
                     "Review logs for details on failed backups. Server will still be powered off.")
    logger.info("--- Final backup sequence completed ---")
    return all_backups_successful

def issue_poweroff_command():
    """
    Issues the final 'poweroff' command to shut down the server.
    This command is only executed if `DRY_RUN` is set to `False` in the configuration.
    It's designed to be the very last action taken by the script.
    Returns:
        bool: True if the poweroff command was successfully issued, False otherwise.
    """
    logger.info("--- Initiating server poweroff sequence ---")
    if CONFIG["DRY_RUN"]:
        logger.info(f"DRY RUN: Would execute the poweroff command: {CONFIG['COMMAND_POWEROFF']}")
        logger.info("Server would now be shutting down in a real execution.")
        return True

    logger.warning("Executing actual server poweroff command. This action is irreversible.")
    try:
        # Using subprocess.Popen here instead of subprocess.run because `poweroff` will
        # terminate the system and thus the script itself. `Popen` allows the command
        # to be launched without waiting for its completion, which will never happen
        # from the script's perspective before the OS shuts down.
        subprocess.Popen([CONFIG["COMMAND_POWEROFF"]])
        logger.info("Poweroff command issued successfully. System should shut down shortly.")
        
        # Give a small delay to allow the logger to flush any pending messages
        # before the OS potentially cuts off all processes. This is a best effort.
        time.sleep(5) 
        return True
    except FileNotFoundError:
        logger.critical(f"Poweroff command '{CONFIG['COMMAND_POWEROFF']}' not found. "
                        "Cannot initiate server shutdown. Please check configuration.")
        return False
    except Exception as e:
        logger.critical(f"Failed to issue poweroff command due to an unexpected error: {e}", exc_info=True)
        return False

def main():
    """
    The main orchestration function for the automated server teardown script.
    It defines the sequence of operations:
    1. Setup logging.
    2. Perform initial prerequisite checks (root, command availability).
    3. Stop critical services gracefully.
    4. Perform final backups of critical data.
    5. Unmount all configured network shares.
    6. Issue the final poweroff command to shut down the server.
    Error handling ensures that critical failures are logged and the script exits with
    an appropriate status code.
    """
    global logger
    logger = setup_logging()
    logger.info(f"--- {CONFIG['SCRIPT_NAME']} started at {datetime.datetime.now().isoformat()} ---")
    logger.info(f"Server Identifier for this teardown: {CONFIG['SERVER_IDENTIFIER']}")
    logger.info(f"Current Dry Run Mode setting: {'Enabled' if CONFIG['DRY_RUN'] else 'Disabled'}")

    # Track overall script success to set appropriate exit code
    overall_success = True

    try:
        # Step 1: Check prerequisites (e.g., root privileges, essential commands)
        # This step is critical and will exit the script immediately on failure.
        check_prerequisites()
        logger.info("Prerequisite checks passed. Proceeding with teardown stages.")

        # Step 2: Stop critical services
        logger.info("\n--- Stage 1: Stopping Critical Services ---")
        service_shutdown_successful = stop_all_critical_services()
        if not service_shutdown_successful:
            logger.warning("Not all critical services stopped successfully. "
                           "This may impact data consistency or prevent clean resource release.")
            overall_success = False

        # Step 3: Perform final backups
        logger.info("\n--- Stage 2: Performing Final Backups ---")
        backup_successful = perform_all_backups()
        if not backup_successful:
            logger.error("One or more backup tasks failed. Data integrity might be compromised. "
                         "Please review logs for details on failed backups.")
            overall_success = False

        # Step 4: Unmount network shares
        logger.info("\n--- Stage 3: Unmounting Network Shares ---")
        shares_unmounted_successful = unmount_all_network_shares()
        if not shares_unmounted_successful:
            logger.error("Not all network shares were unmounted successfully. "
                         "This could lead to data corruption on the shares or prevent clean shutdown.")
            overall_success = False

        # Step 5: Issue poweroff command
        logger.info("\n--- Stage 4: Issuing Server Poweroff Command ---")
        logger.info("All preliminary teardown steps (service stops, backups, unmounts) attempted.")
        poweroff_issued = issue_poweroff_command()

        if poweroff_issued:
            logger.info("Server teardown process initiated poweroff successfully. Script will now exit.")
            sys.exit(0 if overall_success else 1) # Exit with 0 if poweroff issued and all previous steps successful
        else:
            logger.critical("Failed to issue poweroff command. Server remains active. "
                            "Manual intervention is required to shut down the server.")
            sys.exit(1) # Indicate critical failure

    except SystemExit:
        # Catch intentional exits from sys.exit() calls within functions
        # This prevents the `finally` block from unnecessarily logging a "critical error"
        # for an expected termination.
        logger.debug("Script exited via sys.exit().")
        pass
    except Exception as e:
        # Catch any unexpected, unhandled exceptions during the script's execution
        logger.critical(f"An unhandled critical error occurred during the teardown process: {e}", exc_info=True)
        overall_success = False
        sys.exit(1)
    finally:
        # This block ensures cleanup actions (like flushing logs) happen regardless of script success or failure.
        final_status_message = "completed successfully" if overall_success else "finished with errors"
        logger.info(f"--- {CONFIG['SCRIPT_NAME']} {final_status_message} at {datetime.datetime.now().isoformat()} ---")
        
        # Explicitly flush and close log handlers to ensure all messages are written.
        if logger:
            for handler in logger.handlers[:]: # Iterate over a copy to safely remove
                try:
                    handler.flush()
                    handler.close()
                    logger.removeHandler(handler)
                except Exception as e:
                    sys.stderr.write(f"Error closing log handler {handler}: {e}\n")

if __name__ == "__main__":
    main()