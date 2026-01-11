import configparser
import logging
import time
import os
import signal
import sys
from datetime import datetime, timedelta
import json
from abc import ABC, abstractmethod

# Third-party library required for HTTP requests: 'requests'
# pip install requests
import requests

# --- Configuration Constants and Defaults ---
CONFIG_FILE = 'config.ini'
LOG_FILE = 'canary_monitor.log'
DEFAULT_POLL_INTERVAL_SECONDS = 60
DEFAULT_STABILIZATION_PERIOD_MINUTES = 5
DEFAULT_FAILURE_WINDOW_COUNT = 3
DEFAULT_MAX_DEVIATION_PERCENT = 10.0
DEFAULT_ABSOLUTE_ERROR_THRESHOLD = 0.5 # Example: 0.5% error rate
DEFAULT_HTTP_TIMEOUT_SECONDS = 15
DEFAULT_MAX_RETRIES = 5
DEFAULT_RETRY_BACKOFF_FACTOR = 0.5 # For exponential backoff: {backoff_factor} * (2 ** ({number of total retries} - 1))

# --- Global Logger Instance ---
logger = None

def setup_logging(log_level_str='INFO'):
    """
    Sets up a robust logging system with console and file handlers.
    Logs INFO level and above to console, DEBUG and above to file.
    """
    global logger
    if logger is not None:
        return logger # Logger already initialized

    logger = logging.getLogger('CanaryHealthMonitor')
    log_level = getattr(logging, log_level_str.upper(), logging.INFO)
    logger.setLevel(logging.DEBUG) # Catch all messages for file logging

    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
    )

    # Console Handler (INFO level)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(log_level)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # File Handler (DEBUG level)
    fh = logging.FileHandler(LOG_FILE)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    logger.info(f"Logging initialized. Console level: {log_level_str}, File: {LOG_FILE}")
    return logger

def load_configuration(config_filepath=CONFIG_FILE):
    """
    Loads configuration from the specified INI file.
    Returns a dictionary of parsed configuration values.
    Raises ValueError if critical configurations are missing or invalid.
    """
    config = configparser.ConfigParser()
    if not os.path.exists(config_filepath):
        logger.error(f"Configuration file not found: {config_filepath}")
        raise FileNotFoundError(f"Configuration file '{config_filepath}' is missing. Please create it.")

    try:
        config.read(config_filepath)
        logger.info(f"Successfully loaded configuration from {config_filepath}")
    except configparser.Error as e:
        logger.critical(f"Error parsing configuration file {config_filepath}: {e}")
        raise ValueError(f"Configuration file parsing error: {e}")

    settings = {}

    # --- General Settings ---
    settings['monitor_enabled'] = config.getboolean('General', 'enabled', fallback=True)
    settings['poll_interval_seconds'] = config.getint('General', 'poll_interval_seconds', fallback=DEFAULT_POLL_INTERVAL_SECONDS)
    settings['stabilization_period_minutes'] = config.getint('General', 'stabilization_period_minutes', fallback=DEFAULT_STABILIZATION_PERIOD_MINUTES)
    settings['failure_window_count'] = config.getint('General', 'failure_window_count', fallback=DEFAULT_FAILURE_WINDOW_COUNT)
    settings['http_timeout_seconds'] = config.getint('General', 'http_timeout_seconds', fallback=DEFAULT_HTTP_TIMEOUT_SECONDS)
    settings['max_retries'] = config.getint('General', 'max_retries', fallback=DEFAULT_MAX_RETRIES)
    settings['retry_backoff_factor'] = config.getfloat('General', 'retry_backoff_factor', fallback=DEFAULT_RETRY_BACKOFF_FACTOR)
    settings['log_level'] = config.get('General', 'log_level', fallback='INFO')

    # --- Metric Provider Settings ---
    settings['metric_provider_type'] = config.get('Metrics', 'provider_type', fallback='Prometheus').lower()
    if settings['metric_provider_type'] not in ['prometheus', 'datadog']:
        logger.error(f"Invalid metric_provider_type: {settings['metric_provider_type']}. Must be 'Prometheus' or 'Datadog'.")
        raise ValueError("Invalid metric_provider_type specified in configuration.")

    settings['canary_error_query'] = config.get('Metrics', 'canary_error_query')
    settings['primary_error_query'] = config.get('Metrics', 'primary_error_query')
    if not settings['canary_error_query'] or not settings['primary_error_query']:
        logger.error("Missing 'canary_error_query' or 'primary_error_query' in [Metrics] section.")
        raise ValueError("Metric queries are mandatory.")

    settings['max_deviation_percent'] = config.getfloat('Metrics', 'max_deviation_percent', fallback=DEFAULT_MAX_DEVIATION_PERCENT)
    settings['absolute_error_threshold'] = config.getfloat('Metrics', 'absolute_error_threshold', fallback=DEFAULT_ABSOLUTE_ERROR_THRESHOLD)
    settings['query_time_range'] = config.get('Metrics', 'query_time_range', fallback='5m') # e.g., '5m', '1h'

    if settings['metric_provider_type'] == 'prometheus':
        settings['prometheus_url'] = config.get('Prometheus', 'url')
        if not settings['prometheus_url']:
            logger.error("Prometheus URL is required for Prometheus provider.")
            raise ValueError("Prometheus URL is mandatory for Prometheus provider.")
    elif settings['metric_provider_type'] == 'datadog':
        settings['datadog_api_key'] = os.environ.get('DATADOG_API_KEY', config.get('Datadog', 'api_key', fallback=None))
        settings['datadog_app_key'] = os.environ.get('DATADOG_APP_KEY', config.get('Datadog', 'app_key', fallback=None))
        settings['datadog_api_url'] = config.get('Datadog', 'api_url', fallback='https://api.datadoghq.com/api/v1/query')
        if not settings['datadog_api_key'] or not settings['datadog_app_key']:
            logger.error("Datadog API and App keys are required for Datadog provider (or set DATADOG_API_KEY/DATADOG_APP_KEY env vars).")
            raise ValueError("Datadog API and App keys are mandatory for Datadog provider.")

    # --- Rollback Settings ---
    settings['rollback_enabled'] = config.getboolean('Rollback', 'enabled', fallback=True)
    settings['rollback_api_url'] = config.get('Rollback', 'api_url', fallback=None)
    settings['rollback_method'] = config.get('Rollback', 'method', fallback='POST').upper()
    settings['rollback_payload_json'] = config.get('Rollback', 'payload_json', fallback='{}')
    settings['rollback_auth_header'] = config.get('Rollback', 'auth_header', fallback=None) # e.g., "Authorization: Bearer <token>"
    settings['rollback_dry_run'] = config.getboolean('Rollback', 'dry_run', fallback=True)

    if settings['rollback_enabled'] and not settings['rollback_api_url']:
        logger.warning("Rollback is enabled but 'rollback_api_url' is missing. Rollbacks will not be possible.")
        settings['rollback_enabled'] = False # Disable rollback if URL is missing

    # Validate rollback method
    if settings['rollback_method'] not in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
        logger.error(f"Invalid rollback method: {settings['rollback_method']}. Must be one of GET, POST, PUT, DELETE, PATCH.")
        raise ValueError("Invalid rollback_method specified in configuration.")

    logger.debug(f"Loaded configuration details: {json.dumps(settings, indent=2)}")
    return settings

class RetryableHTTPClient:
    """
    A simple HTTP client with built-in retry logic and exponential backoff.
    """
    def __init__(self, max_retries=DEFAULT_MAX_RETRIES, backoff_factor=DEFAULT_RETRY_BACKOFF_FACTOR, timeout=DEFAULT_HTTP_TIMEOUT_SECONDS):
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.timeout = timeout
        self.session = requests.Session() # Use a session for connection pooling

    def _make_request(self, method, url, **kwargs):
        """Internal method to make a single HTTP request."""
        try:
            response = self.session.request(method, url, timeout=self.timeout, **kwargs)
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            return response
        except requests.exceptions.Timeout:
            logger.warning(f"Request timed out after {self.timeout}s for {method} {url}")
            raise
        except requests.exceptions.ConnectionError:
            logger.warning(f"Connection error for {method} {url}")
            raise
        except requests.exceptions.HTTPError as e:
            logger.warning(f"HTTP error {e.response.status_code} for {method} {url}: {e.response.text}")
            raise
        except requests.exceptions.RequestException as e:
            logger.warning(f"An unexpected request error occurred: {e}")
            raise

    def request_with_retries(self, method, url, **kwargs):
        """
        Attempts an HTTP request with retries and exponential backoff.
        """
        for i in range(self.max_retries):
            try:
                logger.debug(f"Attempt {i + 1}/{self.max_retries} for {method} {url}")
                return self._make_request(method, url, **kwargs)
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.exceptions.HTTPError) as e:
                if i < self.max_retries - 1:
                    sleep_time = self.backoff_factor * (2 ** i)
                    logger.warning(f"Retrying {method} {url} in {sleep_time:.2f} seconds due to: {e}")
                    time.sleep(sleep_time)
                else:
                    logger.error(f"Failed {method} {url} after {self.max_retries} attempts: {e}")
                    raise
            except requests.exceptions.RequestException as e:
                logger.error(f"Critical request error for {method} {url}: {e}")
                raise

class MetricProvider(ABC):
    """
    Abstract Base Class for metric providers.
    Defines the interface for fetching canary and primary error rates.
    """
    def __init__(self, config, http_client):
        self.config = config
        self.http_client = http_client
        self.query_time_range = config.get('query_time_range')
        self.canary_error_query_template = config.get('canary_error_query')
        self.primary_error_query_template = config.get('primary_error_query')
        logger.info(f"Initialized MetricProvider of type {self.__class__.__name__}")

    @abstractmethod
    def get_canary_error_rate(self) -> float:
        """Fetches the error rate for the canary deployment."""
        pass

    @abstractmethod
    def get_primary_error_rate(self) -> float:
        """Fetches the error rate for the primary deployment."""
        pass

    @abstractmethod
    def _fetch_and_parse_metric(self, query: str) -> float:
        """Internal method to fetch raw metric data and parse it."""
        pass

class PrometheusProvider(MetricProvider):
    """
    Metric provider implementation for Prometheus.
    Uses Prometheus Query API to fetch error rates.
    """
    def __init__(self, config, http_client: RetryableHTTPClient):
        super().__init__(config, http_client)
        self.prometheus_url = config.get('prometheus_url')
        if not self.prometheus_url:
            raise ValueError("Prometheus URL is not configured.")
        logger.info(f"PrometheusProvider initialized with URL: {self.prometheus_url}")

    def _build_prometheus_query_url(self, query: str) -> str:
        """Constructs the Prometheus API query URL."""
        # Example: /api/v1/query?query=rate(http_requests_total{job="canary", status="5xx"}[5m])/rate(http_requests_total{job="canary"}[5m])
        # Note: 'time' parameter can be used for specific timestamps, but for 'range' queries, 'start', 'end', 'step' are more common
        # For instant query, 'query' and 'time' are used. Here we assume queries are pre-formatted with time ranges like `[5m]`.
        params = {'query': query}
        full_url = f"{self.prometheus_url}/api/v1/query"
        logger.debug(f"Prometheus query URL: {full_url}?query={query}")
        return full_url, params

    def _fetch_and_parse_metric(self, query: str) -> float:
        """
        Fetches metric data from Prometheus and parses the result.
        Returns the value as a float, or 0.0 if data is missing/invalid.
        """
        try:
            url, params = self._build_prometheus_query_url(query)
            response = self.http_client.request_with_retries(
                'GET',
                url,
                params=params
            )
            data = response.json()
            logger.debug(f"Prometheus raw response for query '{query}': {json.dumps(data, indent=2)}")

            if data['status'] == 'success' and data['data']['result']:
                # Prometheus instant query result structure:
                # { "status": "success", "data": { "resultType": "vector", "result": [ { "metric": {}, "value": [ <timestamp>, "<value>" ] } ] } }
                # We expect a single value for an error rate.
                metric_value_str = data['data']['result'][0]['value'][1]
                error_rate = float(metric_value_str)
                logger.info(f"Successfully fetched Prometheus metric for query '{query}': {error_rate:.4f}")
                return error_rate
            else:
                logger.warning(f"Prometheus query '{query}' returned no data or non-success status: {data.get('status', 'N/A')}")
                return 0.0
        except (requests.exceptions.RequestException, ValueError, KeyError, IndexError) as e:
            logger.error(f"Failed to fetch or parse Prometheus metric for query '{query}': {e}")
            return 0.0

    def get_canary_error_rate(self) -> float:
        """Fetches the canary error rate from Prometheus."""
        return self._fetch_and_parse_metric(self.canary_error_query_template)

    def get_primary_error_rate(self) -> float:
        """Fetches the primary error rate from Prometheus."""
        return self._fetch_and_parse_metric(self.primary_error_query_template)

class DatadogProvider(MetricProvider):
    """
    Metric provider implementation for Datadog.
    Uses Datadog Metrics API to fetch error rates.
    """
    def __init__(self, config, http_client: RetryableHTTPClient):
        super().__init__(config, http_client)
        self.api_key = config.get('datadog_api_key')
        self.app_key = config.get('datadog_app_key')
        self.datadog_api_url = config.get('datadog_api_url')

        if not self.api_key or not self.app_key or not self.datadog_api_url:
            raise ValueError("Datadog API key, App key, or URL is not configured.")

        self.headers = {
            'Accept': 'application/json',
            'DD-API-KEY': self.api_key,
            'DD-APPLICATION-KEY': self.app_key
        }
        logger.info(f"DatadogProvider initialized with API URL: {self.datadog_api_url}")

    def _build_datadog_query_params(self, query: str) -> dict:
        """Constructs the Datadog API query parameters."""
        # Datadog API expects 'from' and 'to' timestamps (in seconds since epoch)
        # We need to parse self.query_time_range (e.g., '5m') to determine the 'from' time.
        # This is a simplified approach, a more robust parsing might be needed.
        now = int(datetime.now().timestamp())
        end_time = now

        time_range_value = int(self.query_time_range[:-1])
        time_range_unit = self.query_time_range[-1]

        start_time = now
        if time_range_unit == 'm':
            start_time = int((datetime.now() - timedelta(minutes=time_range_value)).timestamp())
        elif time_range_unit == 'h':
            start_time = int((datetime.now() - timedelta(hours=time_range_value)).timestamp())
        elif time_range_unit == 's':
            start_time = int((datetime.now() - timedelta(seconds=time_range_value)).timestamp())
        else:
            logger.warning(f"Unsupported query_time_range unit for Datadog: {self.query_time_range}. Defaulting to 5 minutes.")
            start_time = int((datetime.now() - timedelta(minutes=5)).timestamp())

        params = {
            'query': query,
            'from': start_time,
            'to': end_time
        }
        logger.debug(f"Datadog query parameters: {params}")
        return params

    def _fetch_and_parse_metric(self, query: str) -> float:
        """
        Fetches metric data from Datadog and parses the result.
        Returns the value as a float, or 0.0 if data is missing/invalid.
        """
        try:
            params = self._build_datadog_query_params(query)
            response = self.http_client.request_with_retries(
                'GET',
                self.datadog_api_url,
                params=params,
                headers=self.headers
            )
            data = response.json()
            logger.debug(f"Datadog raw response for query '{query}': {json.dumps(data, indent=2)}")

            if data and data.get('status') == 'ok' and data.get('series'):
                # Datadog API can return multiple series and points.
                # We assume the query is crafted to return a single relevant value (e.g., avg, sum)
                # within the specified time range.
                # We'll take the latest point from the first series for simplicity.
                # A more robust solution might aggregate or check multiple points.
                latest_value = 0.0
                if data['series'][0]['pointlist']:
                    # pointlist is a list of [timestamp, value]
                    # We take the value of the latest point
                    latest_value = data['series'][0]['pointlist'][-1][1]
                    if latest_value is None: # Handle null values from Datadog
                        latest_value = 0.0
                        logger.warning(f"Datadog query '{query}' returned a null value for the latest point. Treating as 0.0.")

                error_rate = float(latest_value)
                logger.info(f"Successfully fetched Datadog metric for query '{query}': {error_rate:.4f}")
                return error_rate
            else:
                logger.warning(f"Datadog query '{query}' returned no data or non-ok status: {data.get('status', 'N/A')}")
                return 0.0
        except (requests.exceptions.RequestException, ValueError, KeyError, TypeError) as e:
            logger.error(f"Failed to fetch or parse Datadog metric for query '{query}': {e}")
            return 0.0

    def get_canary_error_rate(self) -> float:
        """Fetches the canary error rate from Datadog."""
        return self._fetch_and_parse_metric(self.canary_error_query_template)

    def get_primary_error_rate(self) -> float:
        """Fetches the primary error rate from Datadog."""
        return self._fetch_and_parse_metric(self.primary_error_query_template)

class RollbackManager:
    """
    Manages the triggering of the rollback API.
    """
    def __init__(self, config, http_client: RetryableHTTPClient):
        self.config = config
        self.http_client = http_client
        self.rollback_enabled = config.get('rollback_enabled')
        self.rollback_api_url = config.get('rollback_api_url')
        self.rollback_method = config.get('rollback_method')
        self.rollback_payload_json = config.get('rollback_payload_json')
        self.rollback_auth_header = config.get('rollback_auth_header')
        self.rollback_dry_run = config.get('rollback_dry_run')

        if self.rollback_dry_run:
            logger.warning("Rollback is in DRY-RUN mode. No actual rollback API calls will be made.")
        if not self.rollback_enabled:
            logger.info("Rollback feature is disabled in configuration.")
        else:
            logger.info(f"RollbackManager initialized. Target URL: {self.rollback_api_url}, Method: {self.rollback_method}")

    def _build_rollback_request_params(self):
        """Constructs headers and payload for the rollback request."""
        headers = {'Content-Type': 'application/json'}
        if self.rollback_auth_header:
            try:
                # Expecting "Header-Name: Value" format for auth_header
                header_name, header_value = self.rollback_auth_header.split(':', 1)
                headers[header_name.strip()] = header_value.strip()
            except ValueError:
                logger.error(f"Invalid rollback_auth_header format: '{self.rollback_auth_header}'. Expected 'Name: Value'.")
                # Continue without auth header if invalid format
        
        payload = {}
        try:
            if self.rollback_payload_json:
                payload = json.loads(self.rollback_payload_json)
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON for rollback_payload_json: {self.rollback_payload_json}. Error: {e}")

        return headers, payload

    def trigger_rollback(self, reason: str) -> bool:
        """
        Triggers the configured rollback API.
        Returns True if the rollback was successfully initiated (or dry-run simulated), False otherwise.
        """
        if not self.rollback_enabled:
            logger.info(f"Rollback requested for reason: '{reason}', but rollback is disabled in configuration.")
            return False

        if self.rollback_dry_run:
            logger.warning(f"DRY-RUN: Would have triggered rollback API: {self.rollback_method} {self.rollback_api_url} due to: {reason}")
            logger.warning(f"DRY-RUN: Payload: {self.rollback_payload_json}, Auth Header present: {bool(self.rollback_auth_header)}")
            return True # Simulate success in dry-run mode

        if not self.rollback_api_url:
            logger.error(f"Rollback API URL is not configured. Cannot trigger rollback for reason: {reason}")
            return False

        logger.critical(f"Attempting to trigger actual rollback for reason: {reason}")
        headers, payload = self._build_rollback_request_params()

        try:
            response = self.http_client.request_with_retries(
                self.rollback_method,
                self.rollback_api_url,
                headers=headers,
                json=payload if self.rollback_method in ['POST', 'PUT', 'PATCH'] else None
            )

            # Check for a successful status code (e.g., 200, 202, 204)
            if 200 <= response.status_code < 300:
                logger.critical(f"Rollback API successfully triggered! Status: {response.status_code}, Response: {response.text}")
                return True
            else:
                logger.error(f"Rollback API call failed with status {response.status_code}. Response: {response.text}")
                return False
        except requests.exceptions.RequestException as e:
            logger.error(f"Error communicating with rollback API: {e}")
            return False
        except Exception as e:
            logger.critical(f"An unexpected error occurred during rollback: {e}")
            return False

class CanaryMonitor:
    """
    The main monitoring class that orchestrates metric fetching, comparison,
    and rollback triggering.
    """
    def __init__(self, config: dict, metric_provider: MetricProvider, rollback_manager: RollbackManager):
        self.config = config
        self.metric_provider = metric_provider
        self.rollback_manager = rollback_manager

        self.poll_interval = config['poll_interval_seconds']
        self.stabilization_period = timedelta(minutes=config['stabilization_period_minutes'])
        self.failure_window_count = config['failure_window_count']
        self.max_deviation_percent = config['max_deviation_percent']
        self.absolute_error_threshold = config['absolute_error_threshold']
        self.monitor_enabled = config['monitor_enabled']

        self._initialization_timestamp = datetime.now()
        self._monitoring_active = False
        self._consecutive_failures = 0
        self._rollback_triggered = False
        self._last_canary_error_rate = 0.0
        self._last_primary_error_rate = 0.0

        logger.info(f"CanaryMonitor initialized with poll_interval={self.poll_interval}s, "
                    f"stabilization_period={self.stabilization_period}, "
                    f"failure_window_count={self.failure_window_count}, "
                    f"max_deviation_percent={self.max_deviation_percent}%, "
                    f"absolute_error_threshold={self.absolute_error_threshold}%")

    def _is_stabilization_complete(self) -> bool:
        """Checks if the stabilization period has passed."""
        if not self._monitoring_active:
            elapsed_time = datetime.now() - self._initialization_timestamp
            if elapsed_time >= self.stabilization_period:
                self._monitoring_active = True
                logger.info(f"Stabilization period of {self.stabilization_period} completed. Starting active monitoring.")
            else:
                logger.info(f"Monitoring is in stabilization phase. Elapsed: {elapsed_time}, Remaining: {self.stabilization_period - elapsed_time}")
        return self._monitoring_active

    def _fetch_metrics(self) -> tuple[float, float]:
        """Fetches the current error rates for canary and primary deployments."""
        try:
            canary_rate = self.metric_provider.get_canary_error_rate()
            primary_rate = self.metric_provider.get_primary_error_rate()
            self._last_canary_error_rate = canary_rate
            self._last_primary_error_rate = primary_rate
            logger.debug(f"Fetched metrics: Canary={canary_rate:.4f}%, Primary={primary_rate:.4f}%")
            return canary_rate, primary_rate
        except Exception as e:
            logger.error(f"Error fetching metrics: {e}")
            # Consider this a temporary issue and return current values, or 0.0 if first attempt.
            return self._last_canary_error_rate, self._last_primary_error_rate

    def _evaluate_rollback_condition(self, canary_rate: float, primary_rate: float) -> tuple[bool, str]:
        """
        Compares canary error rate against primary and thresholds to determine if a rollback is needed.
        Returns (True, reason) if rollback is needed, else (False, "").
        """
        # 1. Absolute Threshold Check
        if canary_rate > self.absolute_error_threshold:
            logger.warning(f"Canary error rate ({canary_rate:.4f}%) exceeds absolute threshold ({self.absolute_error_threshold:.4f}%).")
            return True, f"Absolute canary error rate {canary_rate:.4f}% exceeded {self.absolute_error_threshold:.4f}%"

        # 2. Relative Deviation Check
        if primary_rate < 0.0001: # Avoid division by zero or near-zero primary rates
            logger.debug(f"Primary error rate ({primary_rate:.4f}%) is very low. "
                         f"Only checking absolute threshold for canary.")
            return False, "" # If primary is zero, only absolute threshold applies (already checked above)

        deviation = ((canary_rate - primary_rate) / primary_rate) * 100
        if deviation > self.max_deviation_percent:
            logger.warning(f"Canary error rate ({canary_rate:.4f}%) is {deviation:.2f}% higher than "
                           f"primary ({primary_rate:.4f}%), exceeding max allowed deviation ({self.max_deviation_percent:.2f}%).")
            return True, f"Canary error rate {canary_rate:.4f}% deviated by {deviation:.2f}% from primary {primary_rate:.4f}%"

        logger.info(f"Canary error rate ({canary_rate:.4f}%) within acceptable limits "
                    f"(vs. Primary={primary_rate:.4f}%, Deviation={deviation:.2f}%, Threshold={self.max_deviation_percent:.2f}%).")
        return False, ""

    def _monitor_step(self):
        """Executes a single monitoring cycle."""
        if self._rollback_triggered:
            logger.info("Rollback already triggered. Monitoring loop stopping.")
            return

        if not self._is_stabilization_complete():
            return # Still in stabilization, do not evaluate metrics

        canary_rate, primary_rate = self._fetch_metrics()

        # If metric fetching failed (returned 0.0 or previous values), don't increment failure window
        if canary_rate == 0.0 and primary_rate == 0.0 and self._last_canary_error_rate == 0.0:
            logger.warning("Metrics fetched as 0.0 or failed to retrieve. Skipping comparison for this cycle.")
            return # Don't trigger rollback on initial no-data.

        needs_rollback, reason = self._evaluate_rollback_condition(canary_rate, primary_rate)

        if needs_rollback:
            self._consecutive_failures += 1
            logger.warning(f"Consecutive failures: {self._consecutive_failures}/{self.failure_window_count}. Reason: {reason}")

            if self._consecutive_failures >= self.failure_window_count:
                logger.critical(f"Rollback condition met after {self._consecutive_failures} consecutive failures. Triggering rollback!")
                success = self.rollback_manager.trigger_rollback(reason)
                if success:
                    self._rollback_triggered = True
                    logger.critical("Canary health monitor has successfully initiated a rollback. Exiting.")
                    sys.exit(0) # Exit after successful rollback
                else:
                    logger.error("Rollback initiation failed. Will continue monitoring and retry rollback if condition persists.")
                    # Do not reset consecutive_failures, allow it to try again
            else:
                logger.warning(f"Rollback condition met but not enough consecutive failures yet. "
                               f"Current: {self._consecutive_failures}, Required: {self.failure_window_count}")
        else:
            if self._consecutive_failures > 0:
                logger.info(f"Canary health restored. Resetting consecutive failure count from {self._consecutive_failures} to 0.")
            self._consecutive_failures = 0

    def run(self):
        """
        Starts the main monitoring loop. Handles graceful shutdown.
        """
        if not self.monitor_enabled:
            logger.warning("Canary monitoring is disabled in configuration. Exiting.")
            return

        logger.info("Starting Canary Health Monitor...")
        self._initialization_timestamp = datetime.now() # Reset for each run() call

        # Signal handler for graceful shutdown
        def signal_handler(sig, frame):
            logger.info(f"Received signal {sig}. Shutting down gracefully...")
            self.shutdown()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)  # Ctrl+C
        signal.signal(signal.SIGTERM, signal_handler) # kill command

        while not self._rollback_triggered:
            try:
                self._monitor_step()
            except Exception as e:
                logger.exception(f"An unexpected error occurred in the monitoring loop: {e}")
            finally:
                if not self._rollback_triggered: # Only sleep if not shutting down
                    logger.debug(f"Sleeping for {self.poll_interval} seconds...")
                    time.sleep(self.poll_interval)

    def shutdown(self):
        """Performs cleanup tasks before exiting."""
        logger.info("Canary Health Monitor is shutting down.")
        # Any other cleanup like closing connections can go here.

if __name__ == "__main__":
    # Ensure logging is set up very early.
    logger = setup_logging()

    try:
        # 1. Load Configuration
        app_config = load_configuration()
        # Re-configure logging with the specified log level from config
        logger = setup_logging(app_config.get('log_level', 'INFO'))
        logger.info("Configuration loaded successfully. Initializing components.")

        # 2. Initialize HTTP Client
        http_client = RetryableHTTPClient(
            max_retries=app_config['max_retries'],
            backoff_factor=app_config['retry_backoff_factor'],
            timeout=app_config['http_timeout_seconds']
        )
        logger.info("HTTP client initialized.")

        # 3. Initialize Metric Provider
        metric_provider = None
        if app_config['metric_provider_type'] == 'prometheus':
            metric_provider = PrometheusProvider(app_config, http_client)
        elif app_config['metric_provider_type'] == 'datadog':
            metric_provider = DatadogProvider(app_config, http_client)
        else:
            raise ValueError(f"Unsupported metric provider type: {app_config['metric_provider_type']}")
        logger.info(f"Metric provider '{app_config['metric_provider_type']}' configured.")

        # 4. Initialize Rollback Manager
        rollback_manager = RollbackManager(app_config, http_client)
        logger.info("Rollback manager configured.")

        # 5. Initialize and Run Canary Monitor
        monitor = CanaryMonitor(app_config, metric_provider, rollback_manager)
        monitor.run()

    except FileNotFoundError as fnfe:
        logger.critical(f"Setup failed: {fnfe}")
        sys.exit(1)
    except ValueError as ve:
        logger.critical(f"Configuration or initialization error: {ve}")
        sys.exit(1)
    except Exception as e:
        logger.critical(f"An unhandled error occurred during startup or runtime: {e}", exc_info=True)
        sys.exit(1)
    finally:
        if 'monitor' in locals() and monitor is not None:
            monitor.shutdown()
        logger.info("Application finished.")

# Example config.ini structure (to be placed in the same directory):
"""
[General]
enabled = True
poll_interval_seconds = 30
stabilization_period_minutes = 2
failure_window_count = 3
http_timeout_seconds = 10
max_retries = 3
retry_backoff_factor = 0.5
log_level = INFO # DEBUG, INFO, WARNING, ERROR, CRITICAL

[Metrics]
provider_type = Prometheus ; or Datadog
canary_error_query = rate(http_requests_total{job="canary", status=~"5..|429"}[5m]) / rate(http_requests_total{job="canary"}[5m])
primary_error_query = rate(http_requests_total{job="primary", status=~"5..|429"}[5m]) / rate(http_requests_total{job="primary"}[5m])
max_deviation_percent = 25.0 ; Canary error rate can be up to 25% higher than primary
absolute_error_threshold = 0.5 ; Canary error rate cannot exceed 0.5% regardless of primary
query_time_range = 5m

[Prometheus]
url = http://localhost:9090 ; Your Prometheus API endpoint

[Datadog]
;api_key = your_datadog_api_key ; It's recommended to use environment variables for keys: DATADOG_API_KEY
;app_key = your_datadog_app_key ; DATADOG_APP_KEY
api_url = https://api.datadoghq.com/api/v1/query ; Datadog Metrics query API endpoint

[Rollback]
enabled = True
api_url = http://localhost:8080/rollback/canary-service
method = POST
payload_json = {"service_name": "canary-service", "reason": "canary_health_degraded", "action": "rollback"}
auth_header = Authorization: Bearer your_rollback_api_token
dry_run = True ; Set to False to enable actual rollbacks
"""