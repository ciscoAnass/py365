import os
import sys
import logging
import argparse
import datetime
import requests # This script requires the 'requests' library (pip install requests)
import yaml     # This script requires the 'PyYAML' library (pip install PyYAML)
import json     # Used for general data handling and potential future JSON output

# --- Constants and Configuration Defaults ---
# Default path for the YAML configuration file
DEFAULT_CONFIG_FILE_PATH = 'artifact_cleaner_config.yaml'

# Default logging level if not specified
DEFAULT_LOG_LEVEL = 'INFO'

# Default dry-run mode: True means no actual deletions will occur
DEFAULT_DRY_RUN = True

# Default minimum age for an artifact to be considered for deletion (in days)
DEFAULT_ARTIFACT_AGE_DAYS = 30

# Default minimum age for an artifact's last download time (in days)
DEFAULT_DOWNLOAD_AGE_DAYS = 90

# Default list of repositories to target (empty means no repositories are targeted by default, must be specified)
DEFAULT_TARGET_REPOSITORIES = []

# Default pattern to identify 'snapshot' or transient artifacts (e.g., Docker image tags, file names)
# If set to None or empty string, this pattern matching will be skipped.
DEFAULT_SNAPSHOT_PATTERN = '-SNAPSHOT'

# Default timeout for API requests in seconds
DEFAULT_API_TIMEOUT_SECONDS = 60

# --- Global Logger Setup ---
# Initialize a global logger for the application. This logger is configured initially
# and then re-configured once the actual log level is determined from the config.
logger = logging.getLogger("ArtifactCleaner")

def setup_logging(log_level_str: str = DEFAULT_LOG_LEVEL) -> None:
    """
    Configures the logging system for the application.

    This function sets up a console handler and ensures the logger's level
    is set appropriately. It clears existing handlers to prevent duplicate
    log messages if called multiple times.

    Args:
        log_level_str (str): The desired logging level (e.g., 'DEBUG', 'INFO', 'WARNING', 'ERROR').
    """
    # Convert string log level to logging module's constant
    log_level = getattr(logging, log_level_str.upper(), logging.INFO)
    logger.setLevel(log_level)

    # Prevent propagation to the root logger to avoid duplicate messages if root is also configured
    logger.propagate = False

    # Clear existing handlers to allow re-configuration without adding duplicate handlers
    if logger.handlers:
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)

    # Console Handler: Logs messages to standard output
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level) # Handler's level should also respect the overall log_level
    console_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # Optional: File Handler (uncomment and configure if persistent log file storage is desired)
    # log_file_path = os.getenv('ARTIFACT_CLEANER_LOG_FILE', 'artifact_cleaner.log')
    # file_handler = logging.FileHandler(log_file_path)
    # file_handler.setLevel(logging.DEBUG) # Typically, file logs capture more detail
    # file_formatter = logging.Formatter(
    #     '%(asctime)s - %(levelname)s - %(name)s - %(filename)s:%(lineno)d - %(message)s'
    # )
    # file_handler.setFormatter(file_formatter)
    # logger.addHandler(file_handler)

    logger.debug(f"Logging initialized/re-configured with level: {log_level_str}")

# --- Configuration Data Class ---
class CleanerConfig:
    """
    A data class to meticulously hold and validate all configuration parameters
    required for the artifact cleaning process.
    """
    def __init__(self,
                 repo_url: str,
                 username: str,
                 api_key: str,
                 target_repositories: list,
                 min_artifact_age_days: int,
                 min_download_age_days: int,
                 snapshot_pattern: str,
                 dry_run: bool,
                 log_level: str,
                 api_timeout: int):
        """
        Initializes the CleanerConfig with provided parameters and performs extensive validation
        to ensure all critical settings are present and correctly formatted.

        Args:
            repo_url (str): The base URL of the Artifactory/Nexus instance. This URL should
                            typically include the context path (e.g., 'https://your.artifactory.com/artifactory').
            username (str): The username for authenticating with the repository's API.
            api_key (str): The API key (or password) for repository authentication. It is strongly
                           recommended to provide this via environment variables for security.
            target_repositories (list): A list of strings, where each string is the key or name
                                        of a repository to be scanned for artifacts.
            min_artifact_age_days (int): Artifacts whose creation date is older than this many
                                         days from the current date are considered candidates for deletion.
                                         Must be a non-negative integer.
            min_download_age_days (int): Artifacts whose last download date is older than this many
                                         days from the current date are considered candidates. If an
                                         artifact has never been downloaded, this criterion is implicitly
                                         met, and only `min_artifact_age_days` applies. Must be a non-negative integer.
            snapshot_pattern (str): A substring that, if present in an artifact's name or tag,
                                    marks it as a 'snapshot' or transient build. Examples include
                                    '-SNAPSHOT' for Maven or similar for Docker image tags. If set
                                    to None or an empty string, this filter is not applied.
            dry_run (bool): If True, the script will simulate the deletion process, reporting
                            which artifacts *would* be deleted without actually removing them.
                            If False, actual deletions will occur.
            log_level (str): The desired logging verbosity level, such as 'DEBUG', 'INFO',
                             'WARNING', 'ERROR', or 'CRITICAL'.
            api_timeout (int): The maximum time (in seconds) to wait for a response from the
                               repository's API for any given request. Must be a positive integer.

        Raises:
            ValueError: If any critical configuration parameter is missing, invalid, or
                        does not meet the expected type or format.
        """
        logger.debug("Initializing CleanerConfig and performing detailed validation.")

        # Validate Repository URL
        if not repo_url or not isinstance(repo_url, str):
            raise ValueError("Repository URL (repo_url) is a mandatory string parameter.")
        if not (repo_url.startswith('http://') or repo_url.startswith('https://')):
            raise ValueError("Repository URL must start with 'http://' or 'https://'.")
        # Ensure no trailing slash for consistent URL building later
        self.repo_url = repo_url.rstrip('/') 
        logger.debug(f"Configured repo_url: {self.repo_url}")

        # Validate Username
        if not username or not isinstance(username, str):
            raise ValueError("Username (username) is a mandatory string parameter.")
        self.username = username
        logger.debug(f"Configured username: {self.username}")

        # Validate API Key
        if not api_key or not isinstance(api_key, str):
            raise ValueError("API Key/Password (api_key) is a mandatory string parameter.")
        self.api_key = api_key # Sensitive data; logged only in debug
        logger.debug("API Key configured (not displayed for security).")

        # Validate Target Repositories
        if not isinstance(target_repositories, list) or not target_repositories:
            raise ValueError("Target repositories (target_repositories) must be a non-empty list of strings.")
        if not all(isinstance(repo, str) for repo in target_repositories):
            raise ValueError("All items in target_repositories must be strings.")
        self.target_repositories = target_repositories
        logger.debug(f"Configured target_repositories: {self.target_repositories}")

        # Validate Minimum Artifact Age
        if not isinstance(min_artifact_age_days, int) or min_artifact_age_days < 0:
            raise ValueError("Minimum artifact age (min_artifact_age_days) must be a non-negative integer.")
        self.min_artifact_age_days = min_artifact_age_days
        logger.debug(f"Configured min_artifact_age_days: {self.min_artifact_age_days}")

        # Validate Minimum Download Age
        if not isinstance(min_download_age_days, int) or min_download_age_days < 0:
            raise ValueError("Minimum download age (min_download_age_days) must be a non-negative integer.")
        self.min_download_age_days = min_download_age_days
        logger.debug(f"Configured min_download_age_days: {self.min_download_age_days}")

        # Validate Snapshot Pattern
        # Allow None or empty string to disable the pattern matching
        if snapshot_pattern is not None and not isinstance(snapshot_pattern, str):
            raise ValueError("Snapshot pattern (snapshot_pattern) must be a string or None.")
        self.snapshot_pattern = snapshot_pattern.strip() if snapshot_pattern else None
        logger.debug(f"Configured snapshot_pattern: '{self.snapshot_pattern}'")

        # Validate Dry Run
        if not isinstance(dry_run, bool):
            raise ValueError("Dry run (dry_run) must be a boolean value.")
        self.dry_run = dry_run
        logger.debug(f"Configured dry_run: {self.dry_run}")

        # Validate Log Level
        valid_log_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if not isinstance(log_level, str) or log_level.upper() not in valid_log_levels:
            raise ValueError(f"Invalid log level provided. Must be one of: {', '.join(valid_log_levels)}")
        self.log_level = log_level.upper()
        logger.debug(f"Configured log_level: {self.log_level}")

        # Validate API Timeout
        if not isinstance(api_timeout, int) or api_timeout <= 0:
            raise ValueError("API timeout (api_timeout) must be a positive integer.")
        self.api_timeout = api_timeout
        logger.debug(f"Configured api_timeout: {self.api_timeout} seconds")

        logger.debug("CleanerConfig initialized and validated successfully.")

    def __repr__(self) -> str:
        """
        Provides a detailed string representation of the configuration,
        omitting sensitive information like the API key for security.
        """
        return (f"CleanerConfig(\n"
                f"  repo_url='{self.repo_url}',\n"
                f"  username='{self.username}',\n"
                f"  target_repositories={self.target_repositories},\n"
                f"  min_artifact_age_days={self.min_artifact_age_days},\n"
                f"  min_download_age_days={self.min_download_age_days},\n"
                f"  snapshot_pattern='{self.snapshot_pattern}',\n"
                f"  dry_run={self.dry_run},\n"
                f"  log_level='{self.log_level}',\n"
                f"  api_timeout={self.api_timeout}\n"
                f")")

# --- Configuration Loading and Merging Functions ---
def _load_config_from_yaml(file_path: str) -> dict:
    """
    Attempts to load configuration parameters from a specified YAML file.

    Args:
        file_path (str): The absolute or relative path to the YAML configuration file.

    Returns:
        dict: A dictionary containing configuration parameters parsed from the YAML file.
              Returns an empty dictionary if the file does not exist or is empty.

    Raises:
        SystemExit: If the YAML file exists but cannot be parsed due to a syntax error.
    """
    if not os.path.exists(file_path):
        logger.debug(f"YAML config file not found at: {file_path}. Skipping YAML configuration load.")
        return {}
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
            if config:
                logger.info(f"Configuration successfully loaded from YAML file: {file_path}")
                return config
            else:
                logger.debug(f"YAML config file '{file_path}' is empty. Returning empty configuration.")
                return {}
    except yaml.YAMLError as e:
        logger.error(f"Error parsing YAML configuration file '{file_path}'. Please check its syntax: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"An unexpected error occurred while reading YAML file '{file_path}': {e}", exc_info=True)
        sys.exit(1)

def _load_config_from_environment() -> dict:
    """
    Scans environment variables for configuration parameters.
    Expected environment variables are prefixed with `ARTIFACT_CLEANER_`.
    For example, `ARTIFACT_CLEANER_REPO_URL` maps to `repo_url`.

    Returns:
        dict: A dictionary containing configuration parameters obtained from environment variables.
              Type conversions (e.g., to bool, int, list) are attempted based on common key names.
    """
    env_config = {}
    prefix = "ARTIFACT_CLEANER_"
    logger.debug(f"Scanning environment variables for prefix: {prefix}")
    for key, value in os.environ.items():
        if key.startswith(prefix):
            # Convert environment variable key (e.g., ARTIFACT_CLEANER_REPO_URL) to config key (repo_url)
            config_key = key[len(prefix):].lower() 
            try:
                # Attempt to convert string values from environment variables into appropriate Python types
                if config_key == "dry_run":
                    env_config[config_key] = value.lower() in ('true', '1', 'yes')
                elif config_key in ["min_artifact_age_days", "min_download_age_days", "api_timeout"]:
                    env_config[config_key] = int(value)
                elif config_key == "target_repositories":
                    # Split comma-separated string into a list of repository names
                    env_config[config_key] = [r.strip() for r in value.split(',') if r.strip()]
                elif config_key == "snapshot_pattern" and value.lower() == 'none':
                    # Allow 'none' as a special value to explicitly disable snapshot pattern
                    env_config[config_key] = None
                else:
                    env_config[config_key] = value
                logger.debug(f"Loaded config from ENV: {config_key} = '{env_config[config_key]}'")
            except ValueError as e:
                logger.warning(f"Could not parse environment variable '{key}' value '{value}'. "
                               f"Expected a different type: {e}. Skipping this variable.")
            except Exception as e:
                logger.error(f"An unexpected error occurred while parsing environment variable '{key}': {e}", exc_info=True)
    
    if env_config:
        logger.info(f"Configuration loaded from {len(env_config)} environment variables.")
    else:
        logger.debug("No environment variables with 'ARTIFACT_CLEANER_' prefix found.")
    return env_config

def _parse_cli_arguments() -> argparse.Namespace:
    """
    Parses command-line arguments provided when the script is executed.
    These arguments provide the highest precedence for configuration.

    Returns:
        argparse.Namespace: An object containing the parsed arguments, where attributes
                            correspond to argument names (e.g., args.repo_url).
    """
    parser = argparse.ArgumentParser(
        description="A comprehensive DevOps tool for cleaning old build artifacts or Docker images "
                    "from Artifactory or Nexus-like repositories.",
        formatter_class=argparse.RawTextHelpFormatter # Allows for custom formatting in help messages
    )

    # General configuration argument for the YAML file path
    parser.add_argument(
        '--config-file', type=str, default=DEFAULT_CONFIG_FILE_PATH,
        help=f"Specify the path to a YAML configuration file. "
             f"Values from this file are overridden by environment variables and CLI arguments. "
             f"(Default: '{DEFAULT_CONFIG_FILE_PATH}')"
    )
    # Repository connection details
    parser.add_argument(
        '--repo-url', type=str,
        help="The base URL of the Artifactory/Nexus instance (e.g., https://your.artifactory.com/artifactory). "
             "This is a mandatory parameter."
    )
    parser.add_argument(
        '--username', type=str,
        help="The username for authenticating with the repository's API. This is a mandatory parameter."
    )
    parser.add_argument(
        '--api-key', type=str,
        help="The API Key or password for repository authentication. "
             "For enhanced security, consider providing this via the "
             "`ARTIFACT_CLEANER_API_KEY` environment variable instead of directly on the command line."
    )
    # Target repositories to scan
    parser.add_argument(
        '--target-repositories', type=str,
        help="A comma-separated list of repository keys/names to scan "
             "(e.g., 'maven-snapshots,docker-dev,npm-temp'). This is a mandatory parameter."
    )
    # Deletion criteria parameters
    parser.add_argument(
        '--min-artifact-age-days', type=int, default=None, 
        help=f"Minimum age in days for an artifact based on its creation date. "
             f"Artifacts created more recently than this will be skipped. "
             f"(Default: {DEFAULT_ARTIFACT_AGE_DAYS} days)"
    )
    parser.add_argument(
        '--min-download-age-days', type=int, default=None, 
        help=f"Minimum age in days for an artifact based on its last download date. "
             f"Artifacts downloaded more recently than this will be skipped. "
             f"If an artifact has never been downloaded, this criterion is considered met. "
             f"(Default: {DEFAULT_DOWNLOAD_AGE_DAYS} days)"
    )
    parser.add_argument(
        '--snapshot-pattern', type=str, default=None, 
        help=f"A substring pattern (e.g., '-SNAPSHOT', '-DEV') to identify 'snapshot' or "
             f"transient artifacts in their name or tag. Only artifacts matching this pattern "
             f"will be considered for deletion. Set to an empty string `''` or `none` "
             f"to disable snapshot pattern matching entirely. "
             f"(Default: '{DEFAULT_SNAPSHOT_PATTERN}')"
    )
    # Operational mode and logging
    parser.add_argument(
        '--dry-run', action=argparse.BooleanOptionalAction, default=None, 
        help=f"Enable dry-run mode. If set, the script will only report which artifacts "
             f"would be deleted without performing actual deletions. Use `--no-dry-run` "
             f"to perform actual deletions. (Default: {DEFAULT_DRY_RUN})"
    )
    parser.add_argument(
        '--log-level', type=str, default=None,
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        help=f"Set the logging verbosity level. Available choices: DEBUG, INFO, WARNING, ERROR, CRITICAL. "
             f"(Default: {DEFAULT_LOG_LEVEL})"
    )
    parser.add_argument(
        '--api-timeout', type=int, default=None, 
        help=f"Timeout for API requests to the repository in seconds. "
             f"This prevents the script from hanging indefinitely. "
             f"(Default: {DEFAULT_API_TIMEOUT_SECONDS} seconds)"
    )

    args = parser.parse_args()
    
    # Post-processing for specific CLI arguments:
    # Convert comma-separated string of repositories into a list of strings
    if args.target_repositories:
        args.target_repositories = [r.strip() for r in args.target_repositories.split(',') if r.strip()]
    
    logger.debug("Command-line arguments successfully parsed.")
    return args

def load_configuration() -> CleanerConfig:
    """
    Orchestrates the loading of configuration parameters from various sources
    in a defined precedence order:
    1.  **Default Values**: Baseline configuration.
    2.  **YAML Configuration File**: Overrides defaults. The path to this file can be
        specified via the `--config-file` CLI argument, or it defaults to `artifact_cleaner_config.yaml`.
    3.  **Environment Variables**: Overrides YAML settings. Environment variables must
        be prefixed with `ARTIFACT_CLEANER_` (e.g., `ARTIFACT_CLEANER_REPO_URL`).
    4.  **Command-Line Arguments**: Highest precedence, overriding all previous sources.

    After loading, the combined configuration is used to initialize and validate
    a `CleanerConfig` object.

    Returns:
        CleanerConfig: A fully validated and consolidated configuration object.

    Raises:
        SystemExit: If critical configuration parameters are missing or invalid
                    after attempting to load from all sources.
    """
    logger.info("Initiating configuration loading process from multiple sources...")

    # 1. Start with a dictionary of default values
    final_config_dict = {
        'repo_url': None, # These must be explicitly provided
        'username': None, # and cannot rely on defaults
        'api_key': None,  # for security and functionality.
        'target_repositories': DEFAULT_TARGET_REPOSITORIES,
        'min_artifact_age_days': DEFAULT_ARTIFACT_AGE_DAYS,
        'min_download_age_days': DEFAULT_DOWNLOAD_AGE_DAYS,
        'snapshot_pattern': DEFAULT_SNAPSHOT_PATTERN,
        'dry_run': DEFAULT_DRY_RUN,
        'log_level': DEFAULT_LOG_LEVEL,
        'api_timeout': DEFAULT_API_TIMEOUT_SECONDS
    }
    logger.debug("Initial default configuration loaded.")

    # 2. Parse command-line arguments early to determine the config file path
    cli_args = _parse_cli_arguments()
    config_file_path = cli_args.config_file
    logger.debug(f"Determined config file path from CLI: '{config_file_path}'")

    # 3. Load configuration from the YAML file
    yaml_config = _load_config_from_yaml(config_file_path)
    final_config_dict.update(yaml_config) # YAML overrides defaults
    logger.debug("YAML configuration merged into main config dictionary.")

    # 4. Load configuration from environment variables
    env_config = _load_config_from_environment()
    final_config_dict.update(env_config) # Environment variables override YAML and defaults
    logger.debug("Environment variables configuration merged.")

    # 5. Merge command-line arguments (highest precedence)
    for arg_name, arg_value in vars(cli_args).items():
        if arg_name == 'config_file': # Skip the config_file path itself
            continue
        # Only update if the CLI argument was explicitly provided (i.e., not its default `None`)
        if arg_value is not None:
            # Special handling for snapshot_pattern if 'none' is explicitly passed
            if arg_name == 'snapshot_pattern' and isinstance(arg_value, str) and arg_value.lower() == 'none':
                final_config_dict[arg_name] = None
            else:
                final_config_dict[arg_name] = arg_value
            logger.debug(f"CLI argument '{arg_name}' ('{arg_value}') overriding previous value in config.")
    logger.debug("Command-line arguments merged into final config dictionary.")
    
    # After merging all configuration sources, re-configure logging with the determined log_level
    # This ensures all subsequent log messages use the user-specified verbosity.
    setup_logging(final_config_dict.get('log_level', DEFAULT_LOG_LEVEL))
    logger.info(f"Effective log level set to: {final_config_dict.get('log_level', DEFAULT_LOG_LEVEL)}")

    try:
        # 6. Create and validate the final CleanerConfig object
        # This step implicitly performs all necessary type checks and value constraints.
        config = CleanerConfig(
            repo_url=final_config_dict.get('repo_url'),
            username=final_config_dict.get('username'),
            api_key=final_config_dict.get('api_key'),
            target_repositories=final_config_dict.get('target_repositories'),
            min_artifact_age_days=final_config_dict.get('min_artifact_age_days'),
            min_download_age_days=final_config_dict.get('min_download_age_days'),
            snapshot_pattern=final_config_dict.get('snapshot_pattern'),
            dry_run=final_config_dict.get('dry_run'),
            log_level=final_config_dict.get('log_level'),
            api_timeout=final_config_dict.get('api_timeout')
        )
        logger.info("Final configuration successfully loaded and meticulously validated.")
        logger.debug(f"Detailed final Configuration:\n{config}")
        return config
    except ValueError as e:
        logger.critical(f"A fatal configuration error occurred: {e}")
        logger.critical("Please ensure the following mandatory parameters are correctly configured in your YAML file, "
                        "environment variables, or command-line arguments: 'repo_url', 'username', 'api_key', "
                        "and 'target_repositories'. Refer to documentation for details.")
        sys.exit(1)
    except Exception as e:
        logger.critical(f"An unexpected and unhandled error occurred during configuration loading: {e}", exc_info=True)
        sys.exit(1)


# --- Artifactory Client ---
class ArtifactoryClient:
    """
    A dedicated client for robust interaction with the Artifactory REST API and
    AQL (Artifactory Query Language). This class encapsulates all network communication
    details, authentication, and error handling for Artifactory.

    NOTE: This implementation is designed specifically for Artifactory. If Nexus
          support were to be added, a separate client class would be required,
          utilizing the Nexus 3 REST API for assets and components, as its API
          structure and query language differ significantly from Artifactory's.
    """
    def __init__(self, base_url: str, username: str, api_key: str, timeout: int = DEFAULT_API_TIMEOUT_SECONDS):
        """
        Initializes the ArtifactoryClient with connection details and sets up a
        reusable HTTP session.

        Args:
            base_url (str): The base URL of the Artifactory instance (e.g., https://your.artifactory.com/artifactory).
            username (str): The username for API authentication.
            api_key (str): The API key (or password) for authentication.
            timeout (int): The default request timeout in seconds for all API calls.
        """
        self.base_url = base_url
        self.username = username
        self.api_key = api_key
        self.timeout = timeout
        
        # Use a requests.Session for connection pooling and persistent headers/auth
        self._session = requests.Session()
        self._session.auth = (self.username, self.api_key)
        self._session.headers.update({
            'User-Agent': f'ArtifactCleanerScript/1.0 (Python/{sys.version.split(" ")[0]})',
            'Accept': 'application/json',
            'Content-Type': 'application/json' # For AQL queries which send JSON body
        })
        logger.debug(f"ArtifactoryClient initialized for base URL: {base_url} with user: {username}.")

    def _make_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """
        A private helper method to centralize HTTP request logic, authentication,
        and common error handling for all Artifactory API calls.

        Args:
            method (str): The HTTP method to use (e.g., 'GET', 'POST', 'DELETE').
            endpoint (str): The API endpoint path, relative to the Artifactory base URL.
                            For example, 'api/system/version' or 'my-repo/path/to/file.jar'.
            **kwargs: Arbitrary keyword arguments to pass directly to `requests.Session.request()`,
                      such as `params`, `json`, `data`, `headers`, etc.

        Returns:
            requests.Response: The successful response object from the API call.

        Raises:
            requests.exceptions.RequestException: A base exception for all `requests` errors,
                                                  wrapped by more specific exceptions (Timeout, ConnectionError, HTTPError).
        """
        # Construct the full URL for the API request
        url = f"{self.base_url}/{endpoint}"
        logger.debug(f"Making {method} request to: {url}")
        logger.debug(f"Request details - Params: {kwargs.get('params')}, JSON Body: {kwargs.get('json')}, Data Body: {kwargs.get('data')}")

        try:
            response = self._session.request(method, url, timeout=self.timeout, **kwargs)
            response.raise_for_status()  # Automatically raises HTTPError for 4xx or 5xx responses
            logger.debug(f"Successfully received {response.status_code} from {method} {url}")
            return response
        except requests.exceptions.Timeout:
            logger.error(f"Request timed out after {self.timeout} seconds for {method} {url}.")
            raise
        except requests.exceptions.ConnectionError:
            logger.error(f"Connection error occurred for {method} {url}. Please check the Artifactory URL, "
                         f"network connectivity, and DNS resolution.")
            raise
        except requests.exceptions.HTTPError as e:
            # Log the specific HTTP status code and response body for easier debugging
            logger.error(f"HTTP error {e.response.status_code} for {method} {url}. "
                         f"Response: {e.response.text}")
            raise
        except requests.exceptions.RequestException as e:
            logger.error(f"An unexpected general request error occurred for {method} {url}: {e}", exc_info=True)
            raise

    def test_connection(self) -> bool:
        """
        Tests the connectivity and authentication to the Artifactory instance.
        This is done by attempting to fetch the system's version information,
        a standard and lightweight endpoint requiring authentication.

        Returns:
            bool: True if the connection and authentication are successful, False otherwise.
        """
        logger.info(f"Attempting to test connection to Artifactory at: {self.base_url}...")
        try:
            response = self._make_request('GET', 'api/system/version')
            version_info = response.json()
            logger.info(f"Successfully connected to Artifactory. Version: {version_info.get('version', 'N/A')}, "
                        f"Revision: {version_info.get('revision', 'N/A')}, "
                        f"Artifactory URL: {version_info.get('url', 'N/A')}")
            return True
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to connect to Artifactory or authenticate. Please check URL, username, and API key: {e}")
            return False
        except json.JSONDecodeError:
            logger.error("Failed to decode JSON response from Artifactory version endpoint. "
                         "The server might not be Artifactory or is misconfigured.")
            return False
        except Exception as e:
            logger.error(f"An unexpected error occurred during connection test: {e}", exc_info=True)
            return False

    def find_artifacts_aql(self, aql_query: str) -> dict:
        """
        Executes an Artifactory Query Language (AQL) query to search for artifacts.
        AQL is a powerful search language enabling complex queries across repository metadata.

        Args:
            aql_query (str): The AQL query string. This string should conform to Artifactory's AQL syntax.

        Returns:
            dict: The parsed JSON response from Artifactory, which contains the query results.
                  The expected format is typically `{"results": [...], "range": {...}}`.

        Raises:
            requests.exceptions.RequestException: If the API call fails or the query is malformed.
        """
        logger.debug(f"Executing AQL query:\n{aql_query}")
        try:
            # AQL queries are typically POST requests to /api/search/aql with the query in the JSON body.
            response = self._make_request('POST', 'api/search/aql', json={"find": aql_query})
            return response.json()
        except json.JSONDecodeError:
            logger.error("Failed to decode JSON response from AQL query. Artifactory might have returned an invalid response.")
            raise
        except requests.exceptions.RequestException:
            logger.error(f"Error executing AQL query. The query might be invalid, or an API issue occurred.")
            raise
        except Exception as e:
            logger.error(f"An unexpected error occurred while executing AQL query: {e}", exc_info=True)
            raise

    def delete_artifact(self, repo_item_path: str, item_name: str) -> bool:
        """
        Deletes a specific artifact (file or directory) from Artifactory.

        Important Note on Docker Images:
        This method performs a generic file/directory deletion. For a comprehensive
        Docker image tag deletion that also cleans up Artifactory's internal Docker
        registry metadata, one would typically use the dedicated Docker V2 API:
        `DELETE /api/docker/<repoKey>/v2/<imageName>/tags/<tag>`.
        This script, for simplicity and generality, treats Docker images as file
        items within the repository and deletes their underlying files. This might
        leave stale metadata in Artifactory's Docker registry views until a GC runs.

        Args:
            repo_item_path (str): The full path to the artifact *including* its repository name
                                  but *excluding* the file name (e.g., 'my-repo/path/to/folder').
            item_name (str): The name of the artifact file or directory to delete (e.g., 'my-app-1.0-SNAPSHOT.jar').

        Returns:
            bool: True if the deletion request was successfully sent and acknowledged by Artifactory,
                  False if an error occurred. A 404 (Not Found) response is treated as a success
                  (implies the item was already gone).
        """
        # Construct the full path to the artifact relative to the Artifactory base URL
        # Example: `https://artifactory.example.com/artifactory/my-repo/path/to/file.jar`
        # `repo_item_path` would be `my-repo/path/to` and `item_name` would be `file.jar`
        full_artifact_path_for_delete = f"{repo_item_path}/{item_name}"
        logger.debug(f"Attempting to delete item: {full_artifact_path_for_delete}")

        try:
            # Artifactory REST API for deleting an item: DELETE /{repoKey}/{itemPath}
            # The _make_request method constructs the full URL using self.base_url and the provided endpoint.
            self._make_request('DELETE', full_artifact_path_for_delete)
            logger.debug(f"Successfully sent delete request for {full_artifact_path_for_delete}")
            return True
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                logger.warning(f"Artifact '{full_artifact_path_for_delete}' not found during deletion attempt (404). "
                               f"It might have been deleted already or never existed. Treating as successful.")
                return True # If it's not there, our goal of it being absent is met.
            logger.error(f"Failed to delete artifact '{full_artifact_path_for_delete}': "
                         f"HTTP Error {e.response.status_code} - {e.response.text}")
            return False
        except requests.exceptions.RequestException as e:
            logger.error(f"An API request error occurred while trying to delete '{full_artifact_path_for_delete}': {e}", exc_info=True)
            return False
        except Exception as e:
            logger.error(f"An unexpected error occurred during deletion of '{full_artifact_path_for_delete}': {e}", exc_info=True)
            return False


# --- Artifact Data Structure ---
class FoundArtifact:
    """
    A class to encapsulate and manage the metadata of a single artifact found
    in the repository. It includes parsing dates, calculating human-readable sizes,
    and determining deletion eligibility based on defined rules.
    """
    def __init__(self,
                 path: str,
                 name: str,
                 repo: str,
                 size: int,
                 created: str,
                 modified: str,
                 downloaded: str = None,
                 download_count: int = 0,
                 sha1: str = None):
        """
        Initializes a FoundArtifact object with its detailed properties.

        Args:
            path (str): The repository-relative path to the artifact's containing directory
                        (e.g., 'org/mycompany' for a file 'org/mycompany/app.jar').
            name (str): The file name of the artifact (e.g., 'my-app-1.0-SNAPSHOT.jar').
            repo (str): The key or name of the repository where this artifact is stored.
            size (int): The size of the artifact file in bytes. Defaults to 0 if not provided.
            created (str): ISO 8601 formatted string representing the artifact's creation timestamp.
            modified (str): ISO 8601 formatted string representing the artifact's last modification timestamp.
            downloaded (str, optional): ISO 8601 formatted string of the artifact's last download timestamp.
                                        Can be None if never downloaded.
            download_count (int, optional): The number of times this artifact has been downloaded. Defaults to 0.
            sha1 (str, optional): The SHA1 checksum of the artifact. Defaults to None.
        """
        self.path = path
        self.name = name
        self.repo = repo
        self.size = size if size is not None else 0
        self.created = self._parse_date(created, "creation_date")
        self.modified = self._parse_date(modified, "modification_date")
        self.downloaded = self._parse_date(downloaded, "download_date") if downloaded else None
        self.download_count = download_count if download_count is not None else 0
        self.sha1 = sha1
        
        # Construct the full path including the repository name, useful for logging and deletion
        self.full_repo_path = f"{self.repo}/{self.path}/{self.name}" 

        logger.debug(f"Initialized FoundArtifact: {self.full_repo_path} "
                     f"(Created: {self.created}, Downloaded: {self.downloaded or 'Never'}, "
                     f"Size: {self.size_human_readable()})")

    def _parse_date(self, date_str: str, date_type: str = "unknown_date") -> datetime.datetime:
        """
        A robust private helper to parse an ISO 8601 date string into a timezone-aware
        datetime object, specifically handling the 'Z' suffix for UTC.

        Args:
            date_str (str): The ISO 8601 formatted date string to parse (e.g., '2023-10-26T10:30:00.123Z').
            date_type (str): A descriptive string for logging purposes (e.g., "creation_date").

        Returns:
            datetime.datetime: A timezone-aware datetime object. If parsing fails, it logs an
                               error and returns a "min" datetime in UTC as a sentinel value.
        """
        if not date_str:
            return None # Return None for empty date strings

        try:
            # `datetime.fromisoformat` handles most ISO 8601 formats.
            # Replace 'Z' (Zulu time, synonymous with UTC) with '+00:00' for full compatibility.
            parsed_date = datetime.datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            
            # Ensure the datetime object is timezone-aware. If it's naive, assume UTC.
            if parsed_date.tzinfo is None:
                parsed_date = parsed_date.replace(tzinfo=datetime.timezone.utc)
            return parsed_date
        except ValueError as e:
            logger.error(f"Failed to parse {date_type} string '{date_str}' for artifact '{self.full_repo_path}': {e}. "
                         f"Using minimum UTC datetime as fallback.")
            # Return a minimum possible UTC datetime as a safe fallback to prevent crashes,
            # though this might cause incorrect filtering for this specific artifact.
            return datetime.datetime.min.replace(tzinfo=datetime.timezone.utc)
        except Exception as e:
            logger.error(f"An unexpected error occurred while parsing {date_type} string '{date_str}' "
                         f"for artifact '{self.full_repo_path}': {e}", exc_info=True)
            return datetime.datetime.min.replace(tzinfo=datetime.timezone.utc)

    def size_human_readable(self) -> str:
        """
        Converts the artifact's size from bytes into a human-readable format
        (e.g., 10.5 KB, 2.3 MB, 1.1 GB).

        Returns:
            str: A formatted string representing the artifact's size.
        """
        if self.size is None:
            return "N/A"
        size_bytes = self.size
        # Define units for size conversion
        for unit in ['B', 'KB', 'MB', 'GB', 'TB', 'PB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} EB" # For extremely large files, though unlikely for artifacts

    def is_eligible_for_deletion(self,
                                  min_artifact_age_days: int,
                                  min_download_age_days: int,
                                  snapshot_pattern: str = None) -> bool:
        """
        Determines if this specific artifact meets all the configured criteria
        to be considered eligible for deletion. This is a crucial filtering step.

        The criteria checked are:
        1.  **Snapshot Pattern Match**: If `snapshot_pattern` is provided, the artifact's name
            must contain this pattern. If `snapshot_pattern` is None or empty, this check is skipped.
        2.  **Artifact Creation Age**: The artifact's creation date (`self.created`) must be older
            than `min_artifact_age_days` from the current time.
        3.  **Last Download Age**:
            *   If the artifact has been downloaded (`self.downloaded` is not None), its last
                download date must be older than `min_download_age_days` from the current time.
            *   If the artifact has *never* been downloaded (`self.downloaded` is None),
                it automatically passes this download age criterion, meaning its eligibility
                then depends solely on the artifact creation age and snapshot pattern.

        Args:
            min_artifact_age_days (int): The minimum number of days an artifact must have existed
                                         before being considered for deletion.
            min_download_age_days (int): The minimum number of days since an artifact was last
                                         downloaded before being considered for deletion.
            snapshot_pattern (str, optional): The pattern to match in the artifact's name.
                                              If None or empty, this check is bypassed.

        Returns:
            bool: True if the artifact satisfies ALL specified deletion criteria, False otherwise.
        """
        now = datetime.datetime.now(datetime.timezone.utc) # Get current time in UTC for consistent comparison

        # CRITERION 1: Snapshot Pattern Check
        if snapshot_pattern and snapshot_pattern not in self.name:
            logger.debug(f"Excluding {self.full_repo_path}: Does not match configured snapshot pattern '{snapshot_pattern}'.")
            return False # Not eligible if it doesn't match the required pattern

        # CRITERION 2: Artifact Creation Age Check
        artifact_age_threshold = now - datetime.timedelta(days=min_artifact_age_days)
        if self.created > artifact_age_threshold:
            logger.debug(f"Excluding {self.full_repo_path}: Created too recently "
                         f"(Created: {self.created.strftime('%Y-%m-%d %H:%M:%S%Z')}). "
                         f"Threshold: {artifact_age_threshold.strftime('%Y-%m-%d %H:%M:%S%Z')}.")
            return False # Not eligible if created too recently

        # CRITERION 3: Last Download Age Check
        # If the artifact has a recorded download date:
        if self.downloaded:
            download_age_threshold = now - datetime.timedelta(days=min_download_age_days)
            if self.downloaded > download_age_threshold:
                logger.debug(f"Excluding {self.full_repo_path}: Downloaded too recently "
                             f"(Last Downloaded: {self.downloaded.strftime('%Y-%m-%d %H:%M:%S%Z')}). "
                             f"Threshold: {download_age_threshold.strftime('%Y-%m-%d %H:%M:%S%Z')}.")
                return False # Not eligible if downloaded too recently
            else:
                logger.debug(f"Including {self.full_repo_path}: Last downloaded before threshold "
                             f"({self.downloaded.strftime('%Y-%m-%d %H:%M:%S%Z')}).")
        else:
            # If the artifact has never been downloaded, it automatically satisfies the download age criterion.
            logger.debug(f"Including {self.full_repo_path}: Never downloaded. Meets download age criterion by default.")

        # If the artifact passes all of the above checks, it is eligible for deletion.
        logger.debug(f"Artifact {self.full_repo_path} IS eligible for deletion based on all criteria.")
        return True

    def __repr__(self) -> str:
        """
        Provides a concise string representation of the FoundArtifact object,
        useful for debugging and logging.
        """
        return (f"FoundArtifact(repo='{self.repo}', path='{self.path}', name='{self.name}', "
                f"size={self.size_human_readable()}, created='{self.created.isoformat()}', "
                f"downloaded='{self.downloaded.isoformat() if self.downloaded else 'Never'}', "
                f"downloads={self.download_count})")


# --- Main Cleaning Logic ---
class RepositoryCleaner:
    """
    The core orchestrator for the artifact cleaning process. It manages the lifecycle
    from connecting to the repository, to querying for candidates, filtering them
    based on policy, and finally performing (or simulating) deletions.
    """
    def __init__(self, config: CleanerConfig):
        """
        Initializes the RepositoryCleaner with the validated configuration and
        sets up the Artifactory client.

        Args:
            config (CleanerConfig): The validated configuration object containing all
                                    settings for the cleaning operation.
        """
        self.config = config
        self.client = ArtifactoryClient(
            base_url=config.repo_url,
            username=config.username,
            api_key=config.api_key,
            timeout=config.api_timeout
        )
        self.artifacts_identified_for_deletion = [] # Stores FoundArtifact objects eligible for deletion
        self.deleted_artifacts_count = 0
        self.total_reclaimed_size_bytes = 0
        logger.info(f"RepositoryCleaner initialized. Operating in Dry-Run Mode: {'ENABLED' if self.config.dry_run else 'DISABLED (Actual Deletions WILL occur)'}")

    def run_cleaning_process(self) -> None:
        """
        Executes the entire artifact cleaning workflow in a sequential manner.
        This includes:
        1.  Performing a connection test to the repository.
        2.  Iterating through each configured target repository.
        3.  For each repository, fetching potential candidate artifacts using Artifactory AQL.
        4.  Applying granular filtering criteria (age, download status, pattern) locally in Python.
        5.  Performing the deletion of eligible artifacts (or simulating it in dry-run mode).
        6.  Generating a detailed summary report at the end of the process.
        """
        logger.info("Starting the artifact cleaning process now...")

        # Step 1: Test connectivity to the repository first
        if not self.client.test_connection():
            logger.critical("Initial connection test to the repository failed. Aborting cleaning process.")
            sys.exit(1) # Critical failure, exit immediately

        # Step 2: Iterate through each target repository specified in the configuration
        for repo_name in self.config.target_repositories:
            logger.info(f"\n--- Scanning Repository: '{repo_name}' ---")
            try:
                # Step 3: Fetch candidate artifacts using AQL as an initial broad filter
                # AQL is efficient for server-side filtering on created date and name patterns.
                all_candidate_artifacts = self._fetch_artifacts_for_repo(repo_name)
                logger.info(f"Initial AQL query identified {len(all_candidate_artifacts)} candidate artifacts in '{repo_name}'.")

                # Step 4: Apply detailed, client-side filtering based on all defined criteria
                # This includes download age and any patterns not perfectly expressible in AQL.
                eligible_artifacts = self._filter_eligible_artifacts(all_candidate_artifacts)
                logger.info(f"After applying all criteria, {len(eligible_artifacts)} artifacts are eligible for deletion in '{repo_name}'.")
                
                # Step 5: Process deletions (or simulate in dry-run) for the eligible artifacts
                if eligible_artifacts:
                    logger.info(f"Proceeding to {'simulate deletion of' if self.config.dry_run else 'delete'} "
                                f"{len(eligible_artifacts)} artifacts from '{repo_name}'...")
                    for artifact in eligible_artifacts:
                        if self._perform_deletion(artifact):
                            # Add artifact to report list regardless of dry-run, for summary
                            self.artifacts_identified_for_deletion.append(artifact)
                        else:
                            logger.warning(f"Failed to {'simulate' if self.config.dry_run else 'perform actual'} deletion for '{artifact.full_repo_path}'. Skipping.")
                else:
                    logger.info(f"No artifacts were found eligible for deletion in repository '{repo_name}' after full evaluation.")

            except Exception as e:
                # Log the error but continue to the next repository if one fails
                logger.error(f"An unhandled error occurred while processing repository '{repo_name}': {e}", exc_info=True)
                logger.warning(f"Skipping further processing for repository '{repo_name}' due to error.")
                continue # Move to the next repository in the list

        # Step 6: Generate and display the final summary report
        self._generate_report()
        logger.info("Artifact cleaning process completed for all configured repositories.")

    def _build_aql_query(self, repo_name: str) -> str:
        """
        Constructs a robust Artifactory Query Language (AQL) query string.
        This AQL query serves as an initial, efficient filter to retrieve a superset of
        artifacts that *might* be eligible for deletion, primarily based on:
        -   The target repository.
        -   An initial creation date threshold.
        -   Optionally, a name pattern for snapshots (if configured).

        Further, more precise filtering (especially on last download date) is handled
        by the Python application logic after fetching the results.

        Args:
            repo_name (str): The name of the repository for which to build the AQL query.

        Returns:
            str: The fully constructed AQL query string.
        """
        logger.debug(f"Constructing AQL query for repository: '{repo_name}'")
        
        # Calculate the 'created before' date threshold for the AQL query.
        # This reduces the number of items fetched from Artifactory.
        created_before_date = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
            days=self.config.min_artifact_age_days
        )
        # Format the date into ISO 8601 string suitable for AQL, with 'Z' for UTC.
        created_before_iso = created_before_date.isoformat(timespec='seconds').replace('+00:00', 'Z')

        query_conditions = [
            f'"repo": {{"$eq": "{repo_name}"}}',
            f'"created": {{"$lt": "{created_before_iso}"}}' # Filter for items created before the threshold
        ]

        # If a snapshot pattern is configured, add it to the AQL query for initial filtering.
        # Using "$match" provides a wildcard-like search.
        if self.config.snapshot_pattern:
            query_conditions.append(f'"name": {{"$match": "*{self.config.snapshot_pattern}*"}}')
            logger.debug(f"AQL query refined with snapshot pattern: '*{self.config.snapshot_pattern}*'")

        # Define the structure of the AQL query, requesting specific properties.
        # 'actual_created', 'actual_last_downloaded', and 'download_count' are preferred
        # for file-level metadata in Artifactory over their less specific counterparts.
        aql_template = """
        items.find({{{query_conditions}}}).include(
            "repo", "path", "name", "size", "created", "modified", "actual_created", "actual_last_downloaded", "download_count", "sha1"
        )
        """
        full_query_conditions_str = ", ".join(query_conditions)
        final_aql_query = aql_template.format(query_conditions=full_query_conditions_str)
        logger.debug(f"Final AQL query generated:\n{final_aql_query}")
        return final_aql_query

    def _fetch_artifacts_for_repo(self, repo_name: str) -> list[FoundArtifact]:
        """
        Fetches a list of candidate artifacts for a given repository by executing an AQL query.
        It then parses the raw JSON results from Artifactory into `FoundArtifact` objects.

        Args:
            repo_name (str): The name of the repository to query.

        Returns:
            list[FoundArtifact]: A list of `FoundArtifact` objects representing the artifacts
                                 retrieved from Artifactory based on the initial AQL filter.
                                 Returns an empty list if no artifacts are found or an error occurs.
        """
        logger.debug(f"Initiating artifact fetch for repository '{repo_name}' using AQL...")
        aql_query = self._build_aql_query(repo_name)
        
        try:
            raw_results = self.client.find_artifacts_aql(aql_query)
        except Exception as e:
            logger.error(f"Failed to fetch artifacts from '{repo_name}' using AQL. Error: {e}")
            return [] # Return empty list on API communication error

        artifacts = []
        # Validate the structure of the AQL response
        if not raw_results or not isinstance(raw_results, dict) or 'results' not in raw_results:
            logger.warning(f"AQL query for '{repo_name}' returned no results or an unexpected/malformed response: {raw_results}. "
                           f"Returning an empty list of artifacts.")
            return []

        # Iterate through each item in the AQL results and create FoundArtifact objects
        for item in raw_results['results']:
            try:
                # Prioritize 'actual_created' and 'actual_last_downloaded' as they are more accurate
                # for file-level metadata compared to 'created' and 'last_downloaded' which can refer to folders.
                created_date = item.get('actual_created') or item.get('created')
                downloaded_date = item.get('actual_last_downloaded') or item.get('last_downloaded')

                # Perform basic data integrity checks before creating an object
                if not all(k in item for k in ['path', 'name', 'repo', 'modified']) or not created_date:
                    logger.warning(f"Skipping malformed artifact record from Artifactory due to missing essential fields: {item}")
                    continue # Skip to the next item if critical data is missing

                artifacts.append(
                    FoundArtifact(
                        path=item['path'],
                        name=item['name'],
                        repo=item['repo'],
                        size=item.get('size', 0), # Default size to 0 if not present
                        created=created_date,
                        modified=item['modified'],
                        downloaded=downloaded_date,
                        download_count=item.get('download_count', 0), # Default count to 0
                        sha1=item.get('sha1')
                    )
                )
            except Exception as e:
                logger.error(f"An error occurred while processing a specific AQL result item: {item}. Error: {e}", exc_info=True)
                continue # Continue processing other items even if one fails
        
        logger.debug(f"Successfully processed {len(artifacts)} artifact records from AQL results for '{repo_name}'.")
        return artifacts

    def _filter_eligible_artifacts(self, candidate_artifacts: list[FoundArtifact]) -> list[FoundArtifact]:
        """
        Applies the detailed, client-side filtering logic to a list of candidate artifacts.
        This function uses the `is_eligible_for_deletion` method of each `FoundArtifact` object
        to determine final eligibility based on all configured criteria (age, download status, pattern).

        Args:
            candidate_artifacts (list[FoundArtifact]): A list of `FoundArtifact` objects
                                                      that passed the initial AQL filtering.

        Returns:
            list[FoundArtifact]: A refined list containing only the artifacts that are
                                 fully eligible for deletion according to all policies.
        """
        logger.debug(f"Initiating detailed filtering for {len(candidate_artifacts)} candidate artifacts.")
        eligible = []
        for artifact in candidate_artifacts:
            if artifact.is_eligible_for_deletion(
                min_artifact_age_days=self.config.min_artifact_age_days,
                min_download_age_days=self.config.min_download_age_days,
                snapshot_pattern=self.config.snapshot_pattern
            ):
                eligible.append(artifact)
            # Detailed logging for excluded artifacts is handled within FoundArtifact.is_eligible_for_deletion
        logger.info(f"Detailed filtering complete. {len(eligible)} artifacts remain eligible for deletion.")
        return eligible

    def _perform_deletion(self, artifact: FoundArtifact) -> bool:
        """
        Either performs the actual deletion of an artifact from Artifactory or
        simulates the deletion if the script is running in dry-run mode.

        Args:
            artifact (FoundArtifact): The `FoundArtifact` object representing the artifact to be deleted.

        Returns:
            bool: True if the deletion (or simulated deletion) operation was successful,
                  False if an error occurred during actual deletion.
        """
        size_hr = artifact.size_human_readable()
        full_path_for_log = artifact.full_repo_path # Use this for logging clarity

        if self.config.dry_run:
            logger.info(f"DRY-RUN: Would delete artifact: '{full_path_for_log}' "
                        f"(Size: {size_hr}, Created: {artifact.created.strftime('%Y-%m-%d %H:%M:%S%Z')}, "
                        f"Downloaded: {artifact.downloaded.strftime('%Y-%m-%d %H:%M:%S%Z') if artifact.downloaded else 'Never'}, "
                        f"Downloads: {artifact.download_count})")
            # In dry-run mode, we simulate success and update counters for the final report
            self.deleted_artifacts_count += 1
            self.total_reclaimed_size_bytes += artifact.size
            return True # Simulate success for dry-run
        else:
            logger.warning(f"ATTEMPTING ACTUAL DELETION of artifact: '{full_path_for_log}' "
                           f"(Size: {size_hr}, Created: {artifact.created.strftime('%Y-%m-%d %H:%M:%S%Z')}, "
                           f"Downloaded: {artifact.downloaded.strftime('%Y-%m-%d %H:%M:%S%Z') if artifact.downloaded else 'Never'})")
            try:
                # Call the client's delete method. The client handles its own error logging.
                if self.client.delete_artifact(f"{artifact.repo}/{artifact.path}", artifact.name):
                    logger.info(f"Successfully deleted artifact: '{full_path_for_log}'")
                    self.deleted_artifacts_count += 1
                    self.total_reclaimed_size_bytes += artifact.size
                    return True
                else:
                    logger.error(f"Client reported failure to delete artifact: '{full_path_for_log}'. See previous logs for details.")
                    return False
            except Exception as e:
                logger.error(f"An unexpected error occurred during ACTUAL deletion of '{full_path_for_log}': {e}", exc_info=True)
                return False

    def _generate_report(self) -> None:
        """
        Generates and prints a comprehensive summary report of the entire cleaning operation.
        This report details the configuration used, the number of artifacts processed,
        the amount of storage reclaimed (or that would be reclaimed), and a list of
        all artifacts that were identified for deletion.
        """
        logger.info("\n" + "=" * 50)
        logger.info("--- ARTIFACT CLEANING PROCESS SUMMARY REPORT ---")
        logger.info("=" * 50)
        
        # Report Configuration Details
        logger.info(f"Operational Mode:  {'DRY-RUN (NO DELETIONS PERFORMED)' if self.config.dry_run else 'ACTIVE (ACTUAL DELETIONS PERFORMED)'}")
        logger.info(f"Repository URL:    {self.config.repo_url}")
        logger.info(f"Target Repositories: {', '.join(self.config.target_repositories)}")
        logger.info(f"Min. Artifact Age: {self.config.min_artifact_age_days} days (based on creation date)")
        logger.info(f"Min. Download Age: {self.config.min_download_age_days} days (based on last download date)")
        logger.info(f"Snapshot Pattern:  '{self.config.snapshot_pattern}'" if self.config.snapshot_pattern else "Snapshot Pattern: Disabled")
        logger.info(f"Log Level:         {self.config.log_level}")
        logger.info(f"API Timeout:       {self.config.api_timeout} seconds")
        logger.info("-" * 50)

        # Calculate total potential reclaimed size for reporting
        total_potential_reclaimed_size = sum(a.size for a in self.artifacts_identified_for_deletion)
        # Use a dummy FoundArtifact to leverage its human-readable size formatting
        reclaimed_size_hr = FoundArtifact(
            path='', name='', repo='', size=total_potential_reclaimed_size,
            created=datetime.datetime.now().isoformat(), modified=datetime.datetime.now().isoformat()
        ).size_human_readable()

        # Report Action Statistics
        logger.info(f"Total Artifacts Identified for Deletion: {len(self.artifacts_identified_for_deletion)}")
        logger.info(f"Total Artifacts {'Would Be' if self.config.dry_run else 'Actually'} Deleted: {self.deleted_artifacts_count}")
        logger.info(f"Total Storage {'Would Be' if self.config.dry_run else 'Actually'} Reclaimed: {reclaimed_size_hr}")
        logger.info("-" * 50)

        # Detail individual artifacts identified for deletion, if any
        if self.artifacts_identified_for_deletion:
            logger.info("Detailed list of artifacts identified for deletion:")
            # Sort artifacts for consistent reporting
            sorted_artifacts = sorted(self.artifacts_identified_for_deletion, key=lambda x: x.full_repo_path)
            for i, artifact in enumerate(sorted_artifacts):
                logger.info(f"  {i+1}. {artifact.full_repo_path} "
                            f"(Size: {artifact.size_human_readable()}, "
                            f"Created: {artifact.created.strftime('%Y-%m-%d')}, "
                            f"Downloaded: {artifact.downloaded.strftime('%Y-%m-%d') if artifact.downloaded else 'Never'}, "
                            f"Downloads: {artifact.download_count})")
        else:
            logger.info("No artifacts were identified for deletion based on the specified criteria and policies.")

        logger.info("=" * 50)
        logger.info("--- END OF REPORT ---")
        logger.info("=" * 50)


# --- Main Execution Block ---
def main():
    """
    Main entry point for the `artifact-repository-cleaner` script.
    It orchestrates the overall flow:
    1.  Initializes basic logging.
    2.  Loads and validates the application's configuration from various sources.
    3.  Instantiates the `RepositoryCleaner` with the validated configuration.
    4.  Executes the cleaning process.
    5.  Handles top-level exceptions, including user interruptions.
    """
    # 1. Initialize logging with a default level. This is temporary until the
    #    actual log level from configuration is determined.
    setup_logging(DEFAULT_LOG_LEVEL)
    logger.info("Starting artifact-repository-cleaner script initialization...")

    try:
        # 2. Load the full application configuration. This function also
        #    re-configures the logger with the final determined log level.
        config = load_configuration()
        
        # 3. Instantiate the RepositoryCleaner with the validated configuration.
        cleaner = RepositoryCleaner(config)
        
        # 4. Run the main cleaning process.
        cleaner.run_cleaning_process()

    except SystemExit as se:
        # SystemExit is raised for intentional exits (e.g., config error, argparse help).
        # The relevant message should have already been logged.
        logger.error(f"Script terminated with exit code: {se.code}. Check logs for details.")
        # Ensure the script exits with the specific code if provided by SystemExit
        sys.exit(se.code) 
    except KeyboardInterrupt:
        # Handle graceful shutdown on Ctrl+C
        logger.warning("Cleaning process interrupted by user (KeyboardInterrupt). Exiting gracefully.")
        sys.exit(130) # Standard exit code for Ctrl+C
    except Exception as e:
        # Catch any other unexpected exceptions and log them critically
        logger.critical(f"An unhandled and unexpected error occurred during script execution: {e}", exc_info=True)
        sys.exit(1) # Indicate an abnormal script termination
    
    logger.info("Artifact-repository-cleaner script finished successfully.")

if __name__ == "__main__":
    main()