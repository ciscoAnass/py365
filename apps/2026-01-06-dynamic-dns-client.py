import os
import sys
import time
import json
import logging
import logging.handlers
import configparser
import requests  # Third-party library: pip install requests

# Importing fcntl for file locking on Unix-like systems.
# This module is not available on Windows. For cross-platform compatibility
# on Windows, file locking would require a different approach (e.g., `msvcrt.locking`)
# or be omitted if not strictly critical for the application's single-instance model.
# For the purpose of maximizing lines and detail, it's included here with notes.
try:
    import fcntl
except ImportError:
    # If fcntl is not available (e.g., Windows), define a dummy object
    # to prevent errors, effectively making file locking a no-op on these platforms.
    class DummyFcntl:
        LOCK_EX = 0
        LOCK_SH = 0
        LOCK_NB = 0
        LOCK_UN = 0
        def flock(self, fd, op):
            pass # No-op
    fcntl = DummyFcntl()
    print("WARNING: fcntl module not found. File locking will be disabled. "
          "This is expected on non-Unix-like systems (e.g., Windows).", file=sys.stderr)


# --- Constants and Configuration Defaults ---
DEFAULT_CONFIG_FILE = 'ddns_client.ini'
DEFAULT_IP_HISTORY_FILE = 'last_known_ip.txt'
DEFAULT_LOG_FILE = 'ddns_client.log'
DEFAULT_LOG_LEVEL = 'INFO'
# Using api.ipify.org as it's simple, fast, and provides JSON output.
# Other options: 'https://ifconfig.me/ip' (plain text), 'https://ipecho.net/plain'
DEFAULT_IP_CHECK_API = 'https://api.ipify.org?format=json'
DEFAULT_IP_CHECK_TIMEOUT = 10  # Seconds
DEFAULT_USER_AGENT = 'DynamicDNSClient/1.0 (Python)'
# Minimum time (in seconds) that must pass between writing to the IP history file
# if the IP hasn't changed. This prevents excessive file I/O if the script runs very frequently.
IP_HISTORY_UPDATE_INTERVAL_ON_NO_CHANGE = 300 # 5 minutes

# --- Custom Exceptions ---
class ConfigurationError(Exception):
    """Exception raised for errors encountered during configuration loading or validation."""
    pass

class NetworkError(Exception):
    """Exception raised for network-related issues, such as timeouts or connection failures,
    when interacting with external APIs (IP check service, DNS provider)."""
    pass

class APIError(Exception):
    """Exception raised when an external API (IP check service, DNS provider) returns an
    error status, malformed response, or specific error messages within its payload."""
    pass

class DNSUpdateError(Exception):
    """Exception raised specifically when a DNS record update operation fails
    with the chosen DNS provider API."""
    pass

# --- Global Logger Instance ---
# The logger will be initialized early and potentially re-configured after loading settings.
logger = None

def setup_logging(log_file_path, log_level_str='INFO'):
    """
    Configures the global logger for the application.
    Sets up a file handler (with rotation) and a console handler, both with detailed formatting.
    This function handles re-initialization gracefully if called multiple times.

    Args:
        log_file_path (str): The absolute or relative path to the log file.
        log_level_str (str): The desired logging level (e.g., 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL').

    Returns:
        logging.Logger: The configured logger instance.

    Raises:
        ValueError: If an invalid log level string is provided.
        ConfigurationError: If the log file path is invalid or inaccessible.
    """
    global logger
    # If logger is already set up and has handlers, clear them to prevent duplicate output
    # when re-configuring logging (e.g., after loading config from file).
    if logger and logger.handlers:
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)

    if logger is None:
        logger = logging.getLogger(__name__)

    # Convert string log level to numeric value
    numeric_log_level = getattr(logging, log_level_str.upper(), None)
    if not isinstance(numeric_log_level, int):
        raise ValueError(f"Invalid log level specified: '{log_level_str}'. "
                         "Must be one of DEBUG, INFO, WARNING, ERROR, CRITICAL.")
    logger.setLevel(numeric_log_level)

    # Define a consistent formatter for all handlers
    formatter = logging.Formatter(
        '[%(asctime)s] [%(levelname)s] [%(name)s] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # --- File Handler Setup ---
    # Use TimedRotatingFileHandler for automatic log file rotation based on time.
    # This keeps log file sizes manageable and prevents filling up disk space.
    try:
        # Resolve log file path to an absolute path for robustness
        abs_log_file_path = _get_abs_path(log_file_path)
        log_dir = os.path.dirname(abs_log_file_path)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True) # Create directory if it doesn't exist

        file_handler = logging.handlers.TimedRotatingFileHandler(
            abs_log_file_path,
            when='midnight',       # Rotate logs daily at midnight
            interval=1,            # Every 1 day
            backupCount=7,         # Keep 7 days of backup logs
            encoding='utf-8'
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        logger.debug(f"File logging configured to {abs_log_file_path} with level {log_level_str}.")
    except Exception as e:
        # If file logging fails, log to stderr and proceed without file logging
        sys.stderr.write(f"ERROR: Could not set up file logger at '{log_file_path}': {e}\n")
        sys.stderr.write("WARNING: Proceeding without file logging. All logs will go to console.\n")
        # Ensure logger level is still set even if file handler failed
        logger.setLevel(numeric_log_level)

    # --- Console Handler Setup ---
    # Log messages to standard output (console). This is useful for immediate feedback.
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    logger.debug(f"Console logging configured with level {log_level_str}.")

    logger.info("Logging system fully initialized.")
    return logger

def _get_abs_path(file_name):
    """
    Returns the absolute path for a given file name,
    relative to the script's directory. This ensures consistency
    regardless of where the script is executed from.

    Args:
        file_name (str): The name of the file (e.g., 'ddns_client.ini', 'last_known_ip.txt').

    Returns:
        str: The absolute path to the file.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(script_dir, file_name)

def generate_default_config(config_file_path):
    """
    Generates a default configuration file with placeholder values if one does not exist.
    This helps new users get started by providing a template. The script then exits,
    prompting the user to edit the generated file.

    Args:
        config_file_path (str): The absolute path where the configuration file should be created.

    Raises:
        ConfigurationError: If the default configuration file cannot be written due to permissions or path issues.
    """
    logger.info(f"Configuration file not found at '{config_file_path}'. Generating a default template.")
    config = configparser.ConfigParser()

    # Define the default sections and their key-value pairs
    config['GENERAL'] = {
        'log_file': DEFAULT_LOG_FILE,
        'log_level': DEFAULT_LOG_LEVEL,
        'ip_history_file': DEFAULT_IP_HISTORY_FILE
    }

    config['IP_CHECK'] = {
        'api_url': DEFAULT_IP_CHECK_API,
        'timeout_seconds': str(DEFAULT_IP_CHECK_TIMEOUT)
    }

    config['CLOUDFLARE'] = {
        'api_token': 'YOUR_CLOUDFLARE_API_TOKEN', # Placeholder for user's token
        'zone_id': 'YOUR_CLOUDFLARE_ZONE_ID',     # Placeholder for user's Zone ID
        'record_name': 'your.subdomain.example.com', # Placeholder for the DNS record to update
        'ttl': '300',                             # Time To Live in seconds (300s = 5 minutes)
        'proxied': 'False'                        # Set to 'True' if you want Cloudflare proxying
    }

    # Attempt to write the configuration to the specified file
    try:
        # Ensure the directory for the config file exists
        config_dir = os.path.dirname(config_file_path)
        if config_dir and not os.path.exists(config_dir):
            os.makedirs(config_dir, exist_ok=True)

        with open(config_file_path, 'w') as configfile:
            config.write(configfile)
        logger.info(f"Default configuration file created at '{config_file_path}'. "
                    "Please edit this file with your specific Cloudflare API credentials "
                    "and DNS record details, then run the script again.")
        # Exit the script after generating the config to ensure the user reviews it.
        sys.exit(0)
    except IOError as e:
        logger.error(f"Failed to write default configuration file to '{config_file_path}': {e}")
        raise ConfigurationError(f"Could not create config file: {e}")

def load_configuration(config_file_path):
    """
    Loads configuration settings from the specified INI file and performs validation.

    Args:
        config_file_path (str): The absolute path to the configuration file.

    Returns:
        configparser.ConfigParser: The loaded configuration object with validated settings.

    Raises:
        ConfigurationError: If the configuration file cannot be read, is invalid,
                            or contains missing/incorrect required parameters.
    """
    config = configparser.ConfigParser()
    try:
        # If the config file doesn't exist, generate a default one and exit.
        if not os.path.exists(config_file_path):
            generate_default_config(config_file_path) # This call will sys.exit(0) if successful

        # Read the configuration file
        read_files = config.read(config_file_path)
        if not read_files:
            raise ConfigurationError(f"Failed to read configuration file at '{config_file_path}'. "
                                     "It might be empty, inaccessible, or malformed.")
        
        logger.debug(f"Configuration file '{config_file_path}' successfully read.")

        # --- Validate essential sections ---
        required_sections = ['GENERAL', 'CLOUDFLARE', 'IP_CHECK']
        for section in required_sections:
            if section not in config:
                raise ConfigurationError(f"Missing required section '{section}' in configuration file.")
        
        # --- Validate and normalize GENERAL settings ---
        general_config = config['GENERAL']
        if 'log_file' not in general_config or not general_config['log_file'].strip():
            general_config['log_file'] = DEFAULT_LOG_FILE
            logger.warning(f"GENERAL 'log_file' not specified, using default: '{DEFAULT_LOG_FILE}'.")
        if 'log_level' not in general_config or not general_config['log_level'].strip():
            general_config['log_level'] = DEFAULT_LOG_LEVEL
            logger.warning(f"GENERAL 'log_level' not specified, using default: '{DEFAULT_LOG_LEVEL}'.")
        else:
            # Validate log_level string by attempting to convert it
            if not getattr(logging, general_config['log_level'].upper(), None):
                raise ConfigurationError(f"Invalid log_level '{general_config['log_level']}' specified in GENERAL section.")
        if 'ip_history_file' not in general_config or not general_config['ip_history_file'].strip():
            general_config['ip_history_file'] = DEFAULT_IP_HISTORY_FILE
            logger.warning(f"GENERAL 'ip_history_file' not specified, using default: '{DEFAULT_IP_HISTORY_FILE}'.")

        # --- Validate and normalize IP_CHECK settings ---
        ip_check_config = config['IP_CHECK']
        if 'api_url' not in ip_check_config or not ip_check_config['api_url'].strip():
            ip_check_config['api_url'] = DEFAULT_IP_CHECK_API
            logger.warning(f"IP_CHECK 'api_url' not specified, using default: '{DEFAULT_IP_CHECK_API}'.")
        
        # Ensure timeout is an integer and within a reasonable range
        try:
            timeout = int(ip_check_config.get('timeout_seconds', DEFAULT_IP_CHECK_TIMEOUT))
            if timeout <= 0:
                raise ValueError("Timeout must be a positive integer.")
            ip_check_config['timeout_seconds'] = str(timeout) # Store back as string for configparser consistency
        except ValueError:
            raise ConfigurationError("IP_CHECK 'timeout_seconds' must be a valid positive integer.")

        # --- Validate and normalize CLOUDFLARE settings ---
        cf_config = config['CLOUDFLARE']
        required_cf_params = ['api_token', 'zone_id', 'record_name']
        for param in required_cf_params:
            value = cf_config.get(param, '').strip()
            if not value or value.upper() == f'YOUR_CLOUDFLARE_{param.upper()}':
                raise ConfigurationError(
                    f"Cloudflare configuration error: '{param}' is missing or not set. "
                    "Please update your config file with your actual Cloudflare details."
                )
            cf_config[param] = value # Ensure stripped value is stored

        # Validate TTL (Time To Live) and Proxied status
        try:
            ttl = int(cf_config.get('ttl', '300'))
            if not (60 <= ttl <= 86400 or ttl == 1): # Cloudflare's specific TTL requirements
                raise ValueError("TTL must be between 60 and 86400 seconds, or 1 for automatic.")
            cf_config['ttl'] = str(ttl)
        except ValueError:
            raise ConfigurationError("Cloudflare 'ttl' must be a valid integer (60-86400 or 1).")
        
        # Proxied should be a boolean
        proxied_str = cf_config.get('proxied', 'False').lower()
        if proxied_str not in ['true', 'false', '1', '0']:
            raise ConfigurationError("Cloudflare 'proxied' must be 'True' or 'False'.")
        cf_config['proxied'] = 'True' if proxied_str in ['true', '1'] else 'False'

        logger.info("Configuration loaded and validated successfully.")
        return config

    except configparser.Error as e:
        logger.exception(f"Error parsing configuration file '{config_file_path}': {e}")
        raise ConfigurationError(f"Error parsing configuration: {e}")
    except IOError as e:
        logger.exception(f"Could not read configuration file '{config_file_path}': {e}")
        raise ConfigurationError(f"Could not read configuration file: {e}")
    except ConfigurationError: # Re-raise custom ConfigurationError
        raise
    except Exception as e:
        logger.critical(f"An unexpected error occurred during configuration loading: {e}", exc_info=True)
        raise ConfigurationError(f"Unexpected error in configuration: {e}")

def get_public_ip(api_url, timeout_seconds):
    """
    Fetches the current public IP address using an external API endpoint.
    This function expects a JSON response with an 'ip' key, like 'api.ipify.org'.
    If using a plain text API, the parsing logic would need adjustment.

    Args:
        api_url (str): The URL of the API to query for the public IP.
        timeout_seconds (int): The maximum number of seconds to wait for a response from the API.

    Returns:
        str: The public IP address string.

    Raises:
        NetworkError: If there's a problem connecting to the API, a timeout occurs, or
                      other network-related issues prevent a successful request.
        APIError: If the API returns an unexpected HTTP status code (e.g., 4xx, 5xx),
                  the response JSON is malformed, or the 'ip' key is missing.
    """
    logger.debug(f"Attempting to fetch public IP from '{api_url}' with timeout {timeout_seconds}s...")
    try:
        # Set a User-Agent header for better practice and to identify requests.
        headers = {'User-Agent': DEFAULT_USER_AGENT}
        
        # Make the HTTP GET request to the IP check API
        response = requests.get(api_url, timeout=timeout_seconds, headers=headers)
        response.raise_for_status()  # Raise an HTTPError for bad responses (4xx or 5xx client/server errors)

        # Attempt to parse the response as JSON
        data = response.json()
        
        # Extract the IP address from the JSON response.
        # This assumes the API returns a JSON object with an 'ip' key (e.g., {"ip": "1.2.3.4"}).
        public_ip = data.get('ip')
        if not public_ip:
            # If the 'ip' key is missing or empty, it's an API-specific error.
            logger.error(f"IP API response from '{api_url}' missing 'ip' key or malformed. "
                         f"Response content: {response.text[:500]} (truncated if long).")
            raise APIError(f"IP API response malformed: 'ip' key not found or empty.")
        
        logger.info(f"Successfully fetched current public IP: {public_ip}")
        return public_ip

    except requests.exceptions.Timeout:
        logger.error(f"Timeout occurred while fetching public IP from '{api_url}'.")
        raise NetworkError(f"Timeout connecting to IP API: '{api_url}'.")
    except requests.exceptions.ConnectionError as e:
        logger.error(f"Connection error while fetching public IP from '{api_url}': {e}")
        raise NetworkError(f"Could not connect to IP API: '{api_url}'.")
    except requests.exceptions.HTTPError as e:
        logger.error(f"HTTP error fetching public IP from '{api_url}': {e}. Response: {e.response.text[:500] if e.response else 'N/A'}")
        raise APIError(f"IP API returned HTTP error: {e}.")
    except requests.exceptions.RequestException as e:
        # Catch any other requests-related exceptions
        logger.error(f"An unexpected request error occurred fetching public IP from '{api_url}': {e}")
        raise NetworkError(f"Unexpected error during IP API request: {e}.")
    except json.JSONDecodeError as e:
        logger.error(f"Failed to decode JSON response from IP API '{api_url}': {e}. Response: {response.text[:500] if 'response' in locals() else 'N/A'}")
        raise APIError(f"Invalid JSON response from IP API: {e}.")
    except APIError: # Re-raise custom APIError if caught from within this function
        raise
    except Exception as e:
        logger.critical(f"An unexpected and unhandled error occurred while fetching public IP: {e}", exc_info=True)
        raise NetworkError(f"Unexpected error fetching public IP: {e}.")


def get_last_known_ip(ip_history_file):
    """
    Reads the last known public IP address and its associated timestamp from a history file.
    The file is expected to contain a single line in the format "IP_ADDRESS|TIMESTAMP".
    File locking is used on Unix-like systems to prevent race conditions during read/write.

    Args:
        ip_history_file (str): The absolute or relative path to the IP history file.

    Returns:
        tuple: (str or None, float or None)
               - The last known IP address (str) or None if not found/readable.
               - The Unix timestamp (float) of when the IP was last recorded, or None.
    """
    abs_ip_history_file = _get_abs_path(ip_history_file)
    last_ip = None
    last_check_timestamp = None
    
    f = None
    file_locked = False
    try:
        # Attempt to open the file for reading. 'r' mode will raise FileNotFoundError if it doesn't exist.
        f = open(abs_ip_history_file, 'r')

        # Acquire a shared lock for reading on Unix-like systems if fcntl is available.
        # This prevents other processes from writing to the file while we are reading.
        if hasattr(fcntl, 'flock') and fcntl.flock is not DummyFcntl().flock: # Check if it's the real fcntl
            try:
                fcntl.flock(f.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB) # Non-blocking shared lock
                file_locked = True
                logger.debug(f"Acquired shared lock for IP history file: '{abs_ip_history_file}'.")
            except (IOError, OSError) as e:
                logger.warning(f"Could not acquire shared file lock for '{abs_ip_history_file}', proceeding without lock. Error: {e}")
                # If locking fails, proceed without it, but log the warning.
        
        content = f.read().strip()
        if content:
            # Expected format: "IP_ADDRESS|TIMESTAMP"
            parts = content.split('|')
            if len(parts) == 2:
                last_ip = parts[0]
                try:
                    last_check_timestamp = float(parts[1])
                except ValueError:
                    logger.warning(f"Invalid timestamp '{parts[1]}' found in IP history file '{abs_ip_history_file}'. "
                                   "Timestamp will be ignored.")
                    last_check_timestamp = None
                logger.debug(f"Last known IP read: {last_ip} (recorded at {time.ctime(last_check_timestamp) if last_check_timestamp else 'unknown'}).")
            else:
                logger.warning(f"IP history file '{abs_ip_history_file}' content malformed: '{content}'. Expected 'IP|TIMESTAMP'.")
        else:
            logger.debug(f"IP history file '{abs_ip_history_file}' is empty.")
    except FileNotFoundError:
        logger.info(f"IP history file '{abs_ip_history_file}' not found. This is expected on the very first run.")
    except IOError as e:
        logger.error(f"Error reading IP history file '{abs_ip_history_file}': {e}")
    except Exception as e:
        logger.critical(f"An unexpected error occurred while reading IP history file: {e}", exc_info=True)
    finally:
        # Ensure the file is closed and the lock is released if it was acquired.
        if f:
            if file_locked and hasattr(fcntl, 'flock') and fcntl.flock is not DummyFcntl().flock:
                try:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN) # Release the lock
                    logger.debug(f"Released shared lock for IP history file: '{abs_ip_history_file}'.")
                except Exception as e:
                    logger.error(f"Error releasing shared file lock for '{abs_ip_history_file}': {e}")
            f.close()
            logger.debug(f"Closed IP history file: '{abs_ip_history_file}'.")
    
    return last_ip, last_check_timestamp

def write_current_ip_to_file(ip_address, ip_history_file):
    """
    Writes the current public IP address and the current Unix timestamp to the history file.
    This overwrites any previous content. File locking is used to ensure atomic updates.

    Args:
        ip_address (str): The public IP address to write.
        ip_history_file (str): The absolute or relative path to the IP history file.

    Raises:
        IOError: If the file cannot be opened or written to.
    """
    abs_ip_history_file = _get_abs_path(ip_history_file)
    current_timestamp = time.time()
    content_to_write = f"{ip_address}|{current_timestamp}"

    f = None
    file_locked = False
    try:
        # Ensure the directory for the history file exists
        history_dir = os.path.dirname(abs_ip_history_file)
        if history_dir and not os.path.exists(history_dir):
            os.makedirs(history_dir, exist_ok=True)

        # Open the file for writing (truncates existing content)
        f = open(abs_ip_history_file, 'w')

        # Acquire an exclusive lock for writing on Unix-like systems.
        # This prevents any other process from reading or writing while we update.
        if hasattr(fcntl, 'flock') and fcntl.flock is not DummyFcntl().flock:
            try:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB) # Non-blocking exclusive lock
                file_locked = True
                logger.debug(f"Acquired exclusive lock for IP history file: '{abs_ip_history_file}'.")
            except (IOError, OSError) as e:
                logger.warning(f"Could not acquire exclusive file lock for '{abs_ip_history_file}', proceeding without lock. Error: {e}")

        f.write(content_to_write)
        logger.info(f"Updated IP history file '{abs_ip_history_file}' with IP '{ip_address}' and timestamp {current_timestamp}.")
    except IOError as e:
        logger.error(f"Error writing to IP history file '{abs_ip_history_file}': {e}")
        raise # Re-raise to be handled by the main function
    except Exception as e:
        logger.critical(f"An unexpected error occurred while writing IP history file: {e}", exc_info=True)
        raise
    finally:
        # Release the lock and close the file
        if f:
            if file_locked and hasattr(fcntl, 'flock') and fcntl.flock is not DummyFcntl().flock:
                try:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                    logger.debug(f"Released exclusive lock for IP history file: '{abs_ip_history_file}'.")
                except Exception as e:
                    logger.error(f"Error releasing exclusive file lock for '{abs_ip_history_file}': {e}")
            f.close()
            logger.debug(f"Closed IP history file: '{abs_ip_history_file}'.")


class CloudflareDNSUpdater:
    """
    Handles interactions with the Cloudflare API to manage DNS 'A' records.
    This class encapsulates the API authentication, request building,
    and response parsing specific to Cloudflare DNS operations.
    """
    BASE_URL = "https://api.cloudflare.com/client/v4"
    CLOUDFLARE_API_TIMEOUT_SECONDS = 15 # Specific timeout for Cloudflare API calls

    def __init__(self, api_token, zone_id, record_name, ttl=300, proxied=False):
        """
        Initializes the Cloudflare DNS updater with necessary credentials and DNS record details.

        Args:
            api_token (str): The Cloudflare API Token. This token should have
                             permissions to read and edit DNS records for the specified zone.
            zone_id (str): The unique identifier for the DNS zone (domain) in Cloudflare.
                           This can be found in your Cloudflare dashboard.
            record_name (str): The full DNS record name to update (e.g., 'home.example.com').
            ttl (int): The Time To Live (TTL) for the DNS record in seconds.
                       Cloudflare accepts values between 60-86400, or 1 for automatic.
            proxied (bool): Whether the DNS record should be proxied by Cloudflare
                            (True for orange cloud, False for grey cloud).
        """
        if not api_token or not zone_id or not record_name:
            raise ValueError("CloudflareUpdater requires API token, zone ID, and record name.")

        self.api_token = api_token
        self.zone_id = zone_id
        self.record_name = record_name
        self.ttl = int(ttl)      # Ensure TTL is an integer
        self.proxied = bool(proxied) # Ensure proxied is a boolean
        
        # Standard headers for Cloudflare API authentication and content type.
        self.headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
            "User-Agent": DEFAULT_USER_AGENT # Identify our client in Cloudflare's logs
        }
        logger.debug(f"CloudflareUpdater initialized for record: '{self.record_name}', zone ID: '{self.zone_id}'.")

    def _make_api_request(self, method, endpoint, params=None, data=None):
        """
        Internal helper method to standardize making HTTP requests to the Cloudflare API.
        Handles common error patterns, timeouts, and JSON parsing.

        Args:
            method (str): The HTTP method to use (e.g., 'GET', 'POST', 'PUT', 'DELETE').
            endpoint (str): The API endpoint path, relative to BASE_URL (e.g., '/zones/{zone_id}/dns_records').
            params (dict, optional): Dictionary of URL query parameters. Defaults to None.
            data (dict, optional): Dictionary to be sent as a JSON body for POST/PUT requests. Defaults to None.

        Returns:
            dict: The JSON response dictionary from the Cloudflare API if the request is successful.

        Raises:
            NetworkError: For network connectivity issues (timeouts, connection errors).
            APIError: For errors reported by the Cloudflare API (e.g., non-2xx HTTP status,
                      'success': false in JSON response, malformed JSON).
        """
        url = f"{self.BASE_URL}{endpoint}"
        logger.debug(f"Making Cloudflare API {method} request to '{url}' with params: {params}, data: {data}")

        try:
            # Dispatch request based on HTTP method
            response = requests.request(
                method.upper(),
                url,
                headers=self.headers,
                params=params, # For GET requests
                json=data,     # For POST/PUT requests
                timeout=self.CLOUDFLARE_API_TIMEOUT_SECONDS
            )
            response.raise_for_status()  # Raise an HTTPError for 4xx/5xx responses

            json_response = response.json()

            # Cloudflare API responses typically include a 'success' flag.
            if not json_response.get('success'):
                errors = json_response.get('errors', [{'message': 'Unknown Cloudflare API error.'}])
                error_messages = ", ".join([err.get('message', 'No specific error message.') for err in errors])
                logger.error(f"Cloudflare API error for '{endpoint}': {error_messages}. Full response: {json_response}")
                raise APIError(f"Cloudflare API reported errors: {error_messages}")
            
            return json_response

        except requests.exceptions.Timeout:
            logger.error(f"Timeout occurred during Cloudflare API request to '{url}'.")
            raise NetworkError(f"Timeout connecting to Cloudflare API: '{url}'.")
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error during Cloudflare API request to '{url}': {e}")
            raise NetworkError(f"Could not connect to Cloudflare API: '{url}'.")
        except requests.exceptions.HTTPError as e:
            # HTTPError provides response object for detailed logging
            error_details = e.response.text[:500] if e.response else "No response body."
            logger.error(f"Cloudflare API HTTP error ({e.response.status_code}) for '{url}': {e}. Details: {error_details}")
            raise APIError(f"Cloudflare API returned HTTP error: {e}.")
        except requests.exceptions.RequestException as e:
            # Catch any other requests-related exceptions
            logger.error(f"An unexpected request error occurred during Cloudflare API call to '{url}': {e}")
            raise NetworkError(f"Unexpected error during Cloudflare API request: {e}.")
        except json.JSONDecodeError as e:
            # Handle cases where the response is not valid JSON
            response_text = response.text[:500] if 'response' in locals() else 'N/A'
            logger.error(f"Failed to decode JSON response from Cloudflare API '{url}': {e}. Response: {response_text}")
            raise APIError(f"Invalid JSON response from Cloudflare API: {e}.")
        except APIError: # Re-raise custom APIError
            raise
        except Exception as e:
            logger.critical(f"An unexpected and unhandled error occurred during Cloudflare API call to '{url}': {e}", exc_info=True)
            raise NetworkError(f"Unexpected error during Cloudflare API call: {e}.")

    def get_dns_record_details(self):
        """
        Fetches the details (including ID and current content/IP) of the 'A' record
        for the configured record_name within the specified zone.

        Returns:
            tuple: (str, str)
                   - The ID of the DNS record.
                   - The current IP address (content) of the record as found in Cloudflare.
               Returns (None, None) if the record is not found.

        Raises:
            DNSUpdateError: If multiple 'A' records are found for the given name
                            (which makes the update ambiguous), or other specific DNS lookup failures.
            APIError, NetworkError: Propagated from _make_api_request for underlying issues.
        """
        endpoint = f"/zones/{self.zone_id}/dns_records"
        params = {
            "type": "A",             # We are looking for an 'A' record
            "name": self.record_name # The full record name (e.g., 'host.example.com')
        }
        logger.debug(f"Searching for DNS 'A' record '{self.record_name}' in Cloudflare zone '{self.zone_id}'.")
        
        try:
            response_json = self._make_api_request("GET", endpoint, params=params)
            records = response_json.get('result', [])
            
            if not records:
                logger.info(f"Cloudflare DNS 'A' record '{self.record_name}' not found in zone '{self.zone_id}'. "
                            "A new record will be created if an IP change is detected.")
                return None, None # Indicate record not found
            
            if len(records) > 1:
                # This is a critical scenario as we wouldn't know which record to update.
                found_record_ids = [r['id'] for r in records]
                logger.error(f"Multiple 'A' records found for '{self.record_name}' in Cloudflare zone '{self.zone_id}'. "
                             "Please ensure only one 'A' record exists for unambiguous updates. "
                             f"Found record IDs: {found_record_ids}.")
                raise DNSUpdateError(f"Multiple 'A' records found for '{self.record_name}'. "
                                     "Cannot proceed with update due to ambiguity.")
            
            # If exactly one record is found, extract its ID and current content (IP address)
            record_id = records[0]['id']
            current_ip_in_cf = records[0]['content']
            logger.info(f"Found existing Cloudflare DNS 'A' record ID '{record_id}' for '{self.record_name}' "
                        f"with current IP: '{current_ip_in_cf}'.")
            return record_id, current_ip_in_cf

        except DNSUpdateError: # Re-raise specific DNSUpdateError
            raise
        except (APIError, NetworkError) as e:
            logger.error(f"Failed to retrieve DNS record details for '{self.record_name}': {e}")
            raise DNSUpdateError(f"Failed to get DNS record details from Cloudflare: {e}")
        except Exception as e:
            logger.critical(f"An unexpected error occurred while getting DNS record details: {e}", exc_info=True)
            raise DNSUpdateError(f"Unexpected error getting DNS record details: {e}")

    def update_or_create_dns_record(self, new_ip_address, record_id=None):
        """
        Updates an existing Cloudflare DNS 'A' record or creates a new one if it doesn't exist.

        Args:
            new_ip_address (str): The new IP address (content) for the DNS 'A' record.
            record_id (str, optional): The ID of the DNS record to update. If None,
                                        the method assumes the record needs to be created.

        Returns:
            bool: True if the DNS record was successfully updated or created, False otherwise.

        Raises:
            DNSUpdateError: If the update or creation fails due to API issues,
                            invalid input, or other specific DNS-related problems.
            APIError, NetworkError: Propagated from _make_api_request for underlying issues.
        """
        # Construct the payload for the DNS record.
        # Ensure 'type' is 'A' for IPv4 addresses.
        record_payload = {
            "type": "A",
            "name": self.record_name,
            "content": new_ip_address,
            "ttl": self.ttl,
            "proxied": self.proxied
        }

        try:
            if record_id:
                # If a record ID is provided, we perform an update (PUT request).
                logger.info(f"Attempting to update Cloudflare DNS record '{self.record_name}' (ID: {record_id}) "
                            f"to new IP: {new_ip_address}.")
                endpoint = f"/zones/{self.zone_id}/dns_records/{record_id}"
                method = "PUT"
            else:
                # If no record ID, we create a new record (POST request).
                logger.info(f"Attempting to create new Cloudflare DNS record '{self.record_name}' "
                            f"with IP: {new_ip_address}.")
                endpoint = f"/zones/{self.zone_id}/dns_records"
                method = "POST"
            
            # Make the API request with the appropriate method and payload
            response_json = self._make_api_request(method, endpoint, data=record_payload)
            
            if response_json.get('success'):
                action = "updated" if record_id else "created"
                logger.info(f"Cloudflare DNS record '{self.record_name}' successfully {action} to IP: {new_ip_address}.")
                logger.debug(f"Cloudflare API response for {action}: {response_json}")
                return True
            else:
                # This path should ideally be caught by _make_api_request, but included for robustness.
                errors = response_json.get('errors', [{'message': 'Unknown Cloudflare API error during update/creation.'}])
                error_messages = ", ".join([err.get('message', 'No specific error message.') for err in errors])
                logger.error(f"Failed to {'update' if record_id else 'create'} Cloudflare DNS record '{self.record_name}': {error_messages}. "
                             f"Full API response: {response_json}")
                raise DNSUpdateError(f"Cloudflare API failed to {'update' if record_id else 'create'} record: {error_messages}")

        except (APIError, NetworkError, ValueError) as e:
            # Catch specific errors from network or API calls and re-wrap as DNSUpdateError
            action_failed = "update" if record_id else "creation"
            logger.error(f"An error occurred during Cloudflare DNS record {action_failed} for '{self.record_name}': {e}")
            raise DNSUpdateError(f"Failed to {action_failed} DNS record: {e}")
        except Exception as e:
            # Catch any other unexpected errors
            logger.critical(f"An unexpected critical error occurred in update_or_create_dns_record: {e}", exc_info=True)
            raise DNSUpdateError(f"Unexpected error during DNS update: {e}")

def main():
    """
    Main function to execute the dynamic DNS client logic.
    This function orchestrates:
    1. Configuration loading.
    2. IP address checking (current vs. last known).
    3. Conditional DNS record updating via Cloudflare API.
    4. IP history file management.
    Includes comprehensive error handling and logging.
    """
    # Define the default configuration file path relative to the script's location.
    config_file_path = _get_abs_path(DEFAULT_CONFIG_FILE)

    # Initialize a basic logger very early with default settings.
    # This ensures that even configuration loading errors can be logged.
    global logger
    try:
        logger = setup_logging(DEFAULT_LOG_FILE, DEFAULT_LOG_LEVEL)
        logger.info("Dynamic DNS Client application started.")
    except Exception as e:
        sys.stderr.write(f"CRITICAL: Failed to set up initial logging: {e}\n")
        sys.stderr.write("Exiting due to critical logging setup failure.\n")
        sys.exit(1)

    try:
        # --- 1. Load Configuration ---
        # This function might exit the script if it generates a new config file.
        config = load_configuration(config_file_path)

        # After loading configuration, re-initialize logger with potentially updated settings.
        # This ensures logs go to the correct file/level as specified in `ddns_client.ini`.
        log_file_from_config = config['GENERAL'].get('log_file', DEFAULT_LOG_FILE)
        log_level_from_config = config['GENERAL'].get('log_level', DEFAULT_LOG_LEVEL).upper()
        # The `setup_logging` function handles clearing old handlers.
        logger = setup_logging(log_file_from_config, log_level_from_config)
        
        # Get the path for the IP history file, resolving to an absolute path.
        ip_history_file = _get_abs_path(config['GENERAL'].get('ip_history_file', DEFAULT_IP_HISTORY_FILE))
        
        logger.info(f"Configuration successfully loaded from '{config_file_path}'.")

        # --- 2. Retrieve Last Known Public IP ---
        last_known_ip, last_check_timestamp = get_last_known_ip(ip_history_file)
        if last_known_ip:
            logger.info(f"Last known public IP from history: {last_known_ip} "
                        f"(recorded on {time.ctime(last_check_timestamp) if last_check_timestamp else 'unknown date'}).")
        else:
            logger.info("No previous public IP address found in history file. This is common for the first run.")

        # --- 3. Get Current Public IP Address ---
        current_public_ip = None
        ip_api_url = config['IP_CHECK'].get('api_url', DEFAULT_IP_CHECK_API)
        ip_api_timeout = config['IP_CHECK'].getint('timeout_seconds', DEFAULT_IP_CHECK_TIMEOUT)
        
        # Implement a robust retry mechanism for fetching the public IP.
        # This helps in handling transient network issues or temporary API unavailabilities.
        MAX_IP_RETRIES = 3
        RETRY_DELAY_SECONDS = 5 # seconds between retries
        for attempt in range(MAX_IP_RETRIES):
            try:
                current_public_ip = get_public_ip(ip_api_url, ip_api_timeout)
                break # Successfully fetched IP, exit retry loop
            except (NetworkError, APIError) as e:
                logger.warning(f"Attempt {attempt + 1}/{MAX_IP_RETRIES} to get public IP failed: {e}")
                if attempt < MAX_IP_RETRIES - 1:
                    logger.info(f"Retrying public IP check in {RETRY_DELAY_SECONDS} seconds...")
                    time.sleep(RETRY_DELAY_SECONDS)
                else:
                    logger.error("Failed to get public IP after multiple attempts. Aborting DNS update process.")
                    sys.exit(1) # Critical failure, exit application.

        if not current_public_ip:
            logger.critical("Could not determine current public IP address after all retry attempts. Exiting.")
            sys.exit(1)

        # --- 4. Compare IPs and Decide on DNS Update ---
        if current_public_ip == last_known_ip:
            logger.info(f"Public IP address {current_public_ip} has not changed since last recorded check. No DNS update needed.")
            
            # Even if the IP hasn't changed, we update the timestamp in the history file
            # to reflect the last successful check, but only if enough time has passed
            # to prevent hammering the file system.
            if last_check_timestamp and (time.time() - last_check_timestamp) < IP_HISTORY_UPDATE_INTERVAL_ON_NO_CHANGE:
                logger.debug(f"IP history file timestamp update skipped; last update was too recent "
                             f"({time.time() - last_check_timestamp:.2f}s ago, threshold is {IP_HISTORY_UPDATE_INTERVAL_ON_NO_CHANGE}s).")
            else:
                # Write current IP with new timestamp to record last check time.
                write_current_ip_to_file(current_public_ip, ip_history_file)
        else:
            logger.warning(f"Public IP address has changed! Old IP: {last_known_ip if last_known_ip else 'N/A'}, "
                           f"New IP: {current_public_ip}. Initiating DNS update.")
            
            # Extract Cloudflare-specific configuration
            cloudflare_config = config['CLOUDFLARE']
            cf_api_token = cloudflare_config['api_token']
            cf_zone_id = cloudflare_config['zone_id']
            cf_record_name = cloudflare_config['record_name']
            cf_ttl = cloudflare_config.getint('ttl', 300)
            cf_proxied = cloudflare_config.getboolean('proxied', False)

            # Initialize the Cloudflare DNS updater client
            cf_updater = CloudflareDNSUpdater(cf_api_token, cf_zone_id, cf_record_name, cf_ttl, cf_proxied)
            
            dns_update_successful = False
            try:
                # First, try to get details of the existing DNS record.
                # This helps in identifying if we need to update or create a new record,
                # and also provides the current IP in Cloudflare to avoid redundant updates.
                record_id, current_cf_ip = cf_updater.get_dns_record_details()

                # Check if the IP in Cloudflare is already the same as the current public IP.
                # This can happen if a previous update attempt failed partially or if manual changes occurred.
                if current_cf_ip and current_cf_ip == current_public_ip:
                    logger.info(f"Cloudflare DNS record '{cf_record_name}' already points to the correct IP '{current_public_ip}'. "
                                "No update API call is needed.")
                    dns_update_successful = True # Considered successful as state is desired
                else:
                    # Proceed with updating or creating the record
                    dns_update_successful = cf_updater.update_or_create_dns_record(current_public_ip, record_id)
                
                if dns_update_successful:
                    # Only update the history file if the DNS update was genuinely successful.
                    write_current_ip_to_file(current_public_ip, ip_history_file)
                else:
                    logger.error("DNS update process concluded without success. IP history file was NOT updated.")

            except (DNSUpdateError, NetworkError, APIError) as e:
                logger.error(f"Failed to update Cloudflare DNS record for '{cf_record_name}': {e}. "
                             "IP history file was NOT updated.", exc_info=False)
                sys.exit(1) # Exit with error code if DNS update failed.
            except Exception as e:
                logger.critical(f"An unexpected critical error occurred during DNS update process: {e}", exc_info=True)
                sys.exit(1)

    except ConfigurationError as e:
        logger.critical(f"Configuration error: {e}. Please check your config file at '{config_file_path}' "
                        "and ensure all required values are correctly set.", exc_info=False)
        sys.exit(1)
    except Exception as e:
        logger.critical(f"An unhandled and critical error occurred during main execution: {e}", exc_info=True)
        sys.exit(1)
    finally:
        logger.info("Dynamic DNS Client finished execution.")
        # Ensure all buffered log messages are flushed to their destinations before the script exits.
        if logger:
            for handler in logger.handlers:
                try:
                    handler.flush()
                except Exception as e:
                    sys.stderr.write(f"WARNING: Error flushing log handler: {e}\n")

if __name__ == "__main__":
    # This block ensures that `main()` is called only when the script is executed directly.
    # It also provides a final, high-level try-except to catch any unforeseen errors
    # that might escape the main() function's internal error handling.
    try:
        main()
    except Exception as top_level_e:
        # If logger somehow wasn't initialized or failed catastrophically, print to stderr.
        if 'logger' in globals() and logger is not None:
            logger.critical(f"A critical, unhandled error occurred at the top level: {top_level_e}", exc_info=True)
            # Ensure flush for critical errors
            for handler in logger.handlers:
                try:
                    handler.flush()
                except Exception:
                    pass # Ignore errors during final flush
        else:
            sys.stderr.write(f"CRITICAL: Unhandled error before logger was fully functional: {top_level_e}\n")
            import traceback
            traceback.print_exc(file=sys.stderr)
        sys.exit(1) # Exit with a non-zero status code to indicate failure.