import os
import sys
import datetime
import decimal
import json
import logging
import smtplib
import argparse
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import defaultdict
from typing import Dict, List, Any, Optional, Tuple, Type, Union

# Third-party libraries that will be used:
# boto3: For AWS API interaction
# azure-identity: For Azure authentication
# azure-mgmt-consumption: For Azure cost management API interaction

# --- Global Logger Setup ---
def setup_logging(level: int = logging.INFO) -> logging.Logger:
    """
    Configures and returns a global logger instance for the application.
    Logs to console and a file.
    """
    logger = logging.getLogger("CloudCostAnomalyDetector")
    logger.setLevel(level)

    # Prevent duplicate handlers if called multiple times
    if not logger.handlers:
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s')
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)

        # File handler
        log_dir = "logs"
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, "anomaly_detector.log")
        file_handler = logging.FileHandler(log_file)
        file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    return logger

# Initialize the logger
logger = setup_logging()

# --- Configuration Management ---
class ConfigurationManager:
    """
    Manages application configuration, loading settings from environment variables
    and providing default values.
    """
    def __init__(self):
        self._config = {}
        self._load_configuration()

    def _load_configuration(self) -> None:
        """
        Loads configuration settings from environment variables.
        Expected environment variables:
        - CLOUD_PROVIDER: 'aws' or 'azure'
        - ANOMALY_THRESHOLD_PERCENT: e.g., '20' (for 20%)
        - LOOKBACK_DAYS_FOR_AVERAGE: e.g., '7' (for 7-day moving average)
        - ALERT_RECIPIENTS: Comma-separated email addresses
        - SENDER_EMAIL: Email address from which alerts are sent
        - SENDER_EMAIL_PASSWORD: Password for the sender email (if using SMTP directly)
        - SMTP_SERVER: SMTP server address, e.g., 'smtp.gmail.com'
        - SMTP_PORT: SMTP server port, e.g., '587'
        - AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION: For AWS
        - AZURE_SUBSCRIPTION_ID, AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET: For Azure
        """
        logger.info("Loading application configuration from environment variables.")

        # General settings
        self._config['CLOUD_PROVIDER'] = os.getenv('CLOUD_PROVIDER', 'aws').lower()
        self._config['ANOMALY_THRESHOLD_PERCENT'] = decimal.Decimal(os.getenv('ANOMALY_THRESHOLD_PERCENT', '20'))
        self._config['LOOKBACK_DAYS_FOR_AVERAGE'] = int(os.getenv('LOOKBACK_DAYS_FOR_AVERAGE', '7'))
        self._config['LOOKBACK_DAYS_FOR_HISTORY'] = int(os.getenv('LOOKBACK_DAYS_FOR_HISTORY', '30')) # For initial data fetch

        # Alerting settings
        self._config['ALERT_RECIPIENTS'] = [e.strip() for e in os.getenv('ALERT_RECIPIENTS', '').split(',') if e.strip()]
        self._config['SENDER_EMAIL'] = os.getenv('SENDER_EMAIL')
        self._config['SENDER_EMAIL_PASSWORD'] = os.getenv('SENDER_EMAIL_PASSWORD') # Consider app-specific passwords or secret managers
        self._config['SMTP_SERVER'] = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
        self._config['SMTP_PORT'] = int(os.getenv('SMTP_PORT', '587'))
        self._config['SMTP_USE_TLS'] = os.getenv('SMTP_USE_TLS', 'True').lower() == 'true'

        # AWS specific settings
        self._config['AWS_ACCESS_KEY_ID'] = os.getenv('AWS_ACCESS_KEY_ID')
        self._config['AWS_SECRET_ACCESS_KEY'] = os.getenv('AWS_SECRET_ACCESS_KEY')
        self._config['AWS_DEFAULT_REGION'] = os.getenv('AWS_DEFAULT_REGION', 'us-east-1')

        # Azure specific settings
        self._config['AZURE_SUBSCRIPTION_ID'] = os.getenv('AZURE_SUBSCRIPTION_ID')
        # For Service Principal authentication (recommended for automation)
        self._config['AZURE_TENANT_ID'] = os.getenv('AZURE_TENANT_ID')
        self._config['AZURE_CLIENT_ID'] = os.getenv('AZURE_CLIENT_ID')
        self._config['AZURE_CLIENT_SECRET'] = os.getenv('AZURE_CLIENT_SECRET')

        self._validate_configuration()

    def _validate_configuration(self) -> None:
        """
        Performs basic validation on loaded configuration.
        """
        if not self._config['ALERT_RECIPIENTS']:
            logger.warning("No ALERT_RECIPIENTS specified. Email alerts will not be sent.")
        if self._config['SENDER_EMAIL'] and not self._config['SENDER_EMAIL_PASSWORD']:
            logger.warning("SENDER_EMAIL is set, but SENDER_EMAIL_PASSWORD is not. Email sending might fail.")
        
        if self._config['CLOUD_PROVIDER'] == 'azure' and not self._config['AZURE_SUBSCRIPTION_ID']:
            logger.error("AZURE_SUBSCRIPTION_ID is required for Azure provider.")
            raise ValueError("Missing AZURE_SUBSCRIPTION_ID for Azure configuration.")
        
        # For simplicity, if client secret is provided, assume service principal.
        # Otherwise, DefaultAzureCredential will try other methods (Managed Identity, CLI, etc.)
        if self._config['CLOUD_PROVIDER'] == 'azure' and self._config['AZURE_CLIENT_ID'] and \
           self._config['AZURE_TENANT_ID'] and not self._config['AZURE_CLIENT_SECRET']:
            logger.warning("AZURE_CLIENT_SECRET not found for service principal. DefaultAzureCredential will attempt other methods.")

        logger.info("Configuration loaded successfully.")
        logger.debug(f"Loaded config: {json.dumps({k: '***REDACTED***' if 'PASSWORD' in k or 'SECRET' in k else v for k, v in self._config.items()}, indent=2)}")


    def get(self, key: str, default: Any = None) -> Any:
        """
        Retrieves a configuration value by key.
        """
        return self._config.get(key, default)

    def __getattr__(self, name: str) -> Any:
        """
        Allows accessing configuration values as attributes (e.g., config.CLOUD_PROVIDER).
        """
        if name in self._config:
            return self._config[name]
        raise AttributeError(f"Configuration '{name}' not found.")

# --- Helper Functions ---
def get_date_range(days: int = 7) -> Tuple[datetime.date, datetime.date]:
    """
    Calculates a date range for a specified number of past days relative to today.
    Returns (start_date, end_date) as datetime.date objects.
    """
    end_date = datetime.date.today()
    start_date = end_date - datetime.timedelta(days=days)
    logger.debug(f"Calculated date range: From {start_date} to {end_date} (inclusive).")
    return start_date, end_date

def format_cost(amount: Union[decimal.Decimal, float]) -> str:
    """
    Formats a decimal or float cost amount to a string with 2 decimal places.
    """
    return f"${decimal.Decimal(amount):,.2f}"

# --- Cloud Billing Service Abstraction ---
class CloudBillingService:
    """
    Abstract base class for cloud billing services.
    Defines the interface for fetching daily service costs.
    """
    def __init__(self, config: ConfigurationManager):
        self.config = config

    def fetch_daily_service_costs(self, start_date: datetime.date, end_date: datetime.date) -> Dict[str, List[Dict[str, Any]]]:
        """
        Fetches daily cost data aggregated by service for the given date range.
        Returns a dictionary where keys are service names and values are lists
        of dictionaries, each containing 'Date' and 'Cost'.
        Example:
        {
            "EC2": [{"Date": "2023-01-01", "Cost": 12.34}],
            "S3": [{"Date": "2023-01-01", "Cost": 5.67}]
        }
        """
        raise NotImplementedError("Subclasses must implement fetch_daily_service_costs method.")

# --- AWS Billing Service Implementation ---
class AwsBillingService(CloudBillingService):
    """
    AWS implementation of CloudBillingService, using boto3 for Cost Explorer API.
    """
    def __init__(self, config: ConfigurationManager):
        super().__init__(config)
        try:
            import boto3
            self._session = boto3.Session(
                aws_access_key_id=self.config.AWS_ACCESS_KEY_ID,
                aws_secret_access_key=self.config.AWS_SECRET_ACCESS_KEY,
                region_name=self.config.AWS_DEFAULT_REGION
            )
            self._ce_client = self._session.client('ce')
            logger.info("Initialized AWS Cost Explorer client.")
        except ImportError:
            logger.error("boto3 library not found. Please install it: pip install boto3")
            raise
        except Exception as e:
            logger.error(f"Failed to initialize AWS boto3 session or client: {e}")
            raise

    def _call_get_cost_and_usage(self, start_date_str: str, end_date_str: str, next_page_token: Optional[str] = None) -> Dict[str, Any]:
        """
        Helper to make the actual boto3.client('ce').get_cost_and_usage call.
        """
        params = {
            'TimePeriod': {
                'Start': start_date_str,
                'End': end_date_str
            },
            'Granularity': 'DAILY',
            'Metrics': ['UnblendedCost'],
            'GroupBy': [{'Type': 'DIMENSION', 'Key': 'SERVICE'}]
        }
        if next_page_token:
            params['NextPageToken'] = next_page_token
        
        logger.debug(f"Calling get_cost_and_usage with params: {params}")
        return self._ce_client.get_cost_and_usage(**params)


    def fetch_daily_service_costs(self, start_date: datetime.date, end_date: datetime.date) -> Dict[str, List[Dict[str, Any]]]:
        """
        Fetches daily AWS cost data aggregated by service using Cost Explorer API.
        """
        start_date_str = start_date.isoformat()
        end_date_str = end_date.isoformat() # Cost Explorer end date is exclusive, so we add 1 day internally
        ce_end_date_str = (end_date + datetime.timedelta(days=1)).isoformat()

        logger.info(f"Fetching AWS daily cost data from {start_date_str} to {end_date_str} (exclusive for CE: {ce_end_date_str}).")
        
        all_service_costs: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        next_page_token: Optional[str] = None
        page_num = 0

        try:
            while True:
                page_num += 1
                response = self._call_get_cost_and_usage(start_date_str, ce_end_date_str, next_page_token)

                for result_by_time in response.get('ResultsByTime', []):
                    current_date = datetime.datetime.strptime(result_by_time['TimePeriod']['Start'], '%Y-%m-%d').date()
                    for group in result_by_time.get('Groups', []):
                        service_name = group['Keys'][0]
                        cost_amount = decimal.Decimal(group['Metrics']['UnblendedCost']['Amount'])
                        
                        # Only include services with actual cost
                        if cost_amount > 0:
                            all_service_costs[service_name].append({
                                'Date': current_date.isoformat(),
                                'Cost': cost_amount
                            })
                            logger.debug(f"AWS Data: Date={current_date}, Service={service_name}, Cost={cost_amount}")

                next_page_token = response.get('NextPageToken')
                if not next_page_token:
                    break
                logger.debug(f"Fetched page {page_num}, more results available. Fetching next page...")

        except self._session.client('ce').exceptions.DataUnavailableException as e:
            logger.warning(f"AWS Cost Explorer data unavailable for the requested period: {e}")
            return {}
        except Exception as e:
            logger.error(f"Error fetching AWS cost data: {e}", exc_info=True)
            raise

        logger.info(f"Finished fetching AWS daily cost data. Total services found: {len(all_service_costs)}.")
        return dict(all_service_costs)

# --- Azure Billing Service Implementation ---
class AzureBillingService(CloudBillingService):
    """
    Azure implementation of CloudBillingService, using Azure SDK for Cost Management API.
    """
    def __init__(self, config: ConfigurationManager):
        super().__init__(config)
        try:
            from azure.identity import DefaultAzureCredential, ClientSecretCredential
            from azure.mgmt.consumption import ConsumptionManagementClient

            self._subscription_id = self.config.AZURE_SUBSCRIPTION_ID

            if not self._subscription_id:
                raise ValueError("AZURE_SUBSCRIPTION_ID must be set for Azure billing service.")

            # Prioritize ClientSecretCredential if details are provided, otherwise use DefaultAzureCredential
            if self.config.AZURE_CLIENT_ID and self.config.AZURE_TENANT_ID and self.config.AZURE_CLIENT_SECRET:
                self._credential = ClientSecretCredential(
                    tenant_id=self.config.AZURE_TENANT_ID,
                    client_id=self.config.AZURE_CLIENT_ID,
                    client_secret=self.config.AZURE_CLIENT_SECRET
                )
                logger.info("Using ClientSecretCredential for Azure authentication.")
            else:
                self._credential = DefaultAzureCredential()
                logger.info("Using DefaultAzureCredential for Azure authentication (will try various methods).")

            self._consumption_client = ConsumptionManagementClient(self._credential, self._subscription_id)
            logger.info("Initialized Azure Consumption Management client.")
        except ImportError:
            logger.error("Azure SDK libraries not found. Please install them: pip install azure-identity azure-mgmt-consumption")
            raise
        except Exception as e:
            logger.error(f"Failed to initialize Azure SDK client: {e}")
            raise

    def fetch_daily_service_costs(self, start_date: datetime.date, end_date: datetime.date) -> Dict[str, List[Dict[str, Any]]]:
        """
        Fetches daily Azure cost data aggregated by service using Consumption Management API.
        The 'usage details' API provides more granular data, which we'll then aggregate.
        Azure APIs typically return costs per meter or resource, not directly per service.
        We'll group by 'Service Family' or 'Service Name' if available in usage details.
        """
        start_date_str = start_date.isoformat()
        end_date_str = end_date.isoformat()

        logger.info(f"Fetching Azure daily usage details from {start_date_str} to {end_date_str}.")
        
        all_service_costs: Dict[str, List[Dict[str, Any]]] = defaultdict(lambda: defaultdict(decimal.Decimal))
        
        scope = f"/subscriptions/{self._subscription_id}"
        filter_str = f"properties/usageStart ge '{start_date_str}' and properties/usageEnd le '{end_date_str}'"
        
        try:
            # The Azure API for usage details can be quite slow and return large amounts of data.
            # We're iterating through pages.
            # Note: Azure's 'usage details' API might require 'properties/usageStart' and 'properties/usageEnd'
            # to be inclusive. We'll fetch for the requested dates.
            # The 'actual_cost' property is often preferred over 'pretax_cost' for actual billing.
            usage_details = self._consumption_client.usage_details.list(
                scope=scope,
                filter=filter_str,
                expand="properties/meterDetails,properties/billingProperties" # To get service family/name
            )
            
            page_count = 0
            for usage_detail in usage_details:
                page_count += 1
                usage_date = usage_detail.usage_start.date() # usage_start is datetime object
                cost_amount = decimal.Decimal(usage_detail.properties.billing_currency_actual_cost) # Use actual_cost

                # Determine service name from meterDetails or billingProperties
                service_name = "Unknown Azure Service"
                if usage_detail.properties and usage_detail.properties.meter_details:
                    service_name = usage_detail.properties.meter_details.service_family or usage_detail.properties.meter_details.service_name or service_name
                elif usage_detail.properties and usage_detail.properties.billing_properties:
                     service_name = usage_detail.properties.billing_properties.service_family or usage_detail.properties.billing_properties.service_name or service_name
                
                service_name = service_name.strip()
                if not service_name:
                    service_name = "Other Azure Service"

                # Aggregate cost by service and by date
                all_service_costs[service_name][usage_date.isoformat()] += cost_amount
                
                if page_count % 1000 == 0:
                    logger.debug(f"Processed {page_count} usage details records for Azure. Current Service: {service_name}, Date: {usage_date}, Cost: {cost_amount}")

        except Exception as e:
            logger.error(f"Error fetching Azure cost data: {e}", exc_info=True)
            raise

        # Convert the aggregated data into the standard format
        formatted_costs: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for service, daily_costs in all_service_costs.items():
            for date_str, cost in daily_costs.items():
                if cost > 0: # Only include services with actual cost
                    formatted_costs[service].append({
                        'Date': date_str,
                        'Cost': cost
                    })
        
        # Sort costs by date for each service
        for service in formatted_costs:
            formatted_costs[service].sort(key=lambda x: x['Date'])

        logger.info(f"Finished fetching Azure daily cost data. Total services found: {len(formatted_costs)}.")
        return dict(formatted_costs)


# --- Cost Anomaly Detection Logic ---
class CostAnomalyDetector:
    """
    Orchestrates the process of fetching cost data, calculating moving averages,
    and detecting anomalies.
    """
    def __init__(self, config: ConfigurationManager, billing_service: CloudBillingService):
        self.config = config
        self.billing_service = billing_service
        self.historical_data: Dict[str, Dict[str, decimal.Decimal]] = defaultdict(lambda: defaultdict(decimal.Decimal)) # service -> date -> cost
        self.anomalies: List[Dict[str, Any]] = []

        self.lookback_days_for_average = self.config.LOOKBACK_DAYS_FOR_AVERAGE
        self.anomaly_threshold_percent = self.config.ANOMALY_THRESHOLD_PERCENT

        # Ensure Decimal context for consistent arithmetic
        decimal.getcontext().prec = 4

    def _get_history_date_range(self) -> Tuple[datetime.date, datetime.date]:
        """
        Determines the date range needed to fetch all historical data,
        including the lookback period for averages and the current day.
        """
        end_date = datetime.date.today()
        # We need data for (LOOKBACK_DAYS_FOR_AVERAGE - 1) days prior to the current day
        # plus the current day itself to check for anomalies.
        # Also need more historical data to ensure we have a full N-day average.
        # So fetch (LOOKBACK_DAYS_FOR_HISTORY) days prior to today.
        start_date = end_date - datetime.timedelta(days=self.config.LOOKBACK_DAYS_FOR_HISTORY)
        logger.debug(f"Determined historical data fetch range: {start_date} to {end_date}")
        return start_date, end_date

    def _fetch_and_store_historical_data(self) -> None:
        """
        Fetches historical daily cost data for all services and stores it
        in a structured dictionary.
        """
        start_date, end_date = self._get_history_date_range()
        logger.info(f"Fetching historical cost data from {start_date} to {end_date}.")
        
        raw_data = self.billing_service.fetch_daily_service_costs(start_date, end_date)

        if not raw_data:
            logger.warning("No historical data fetched. Cannot perform anomaly detection.")
            return

        for service_name, daily_costs_list in raw_data.items():
            for entry in daily_costs_list:
                date_str = entry['Date']
                cost = decimal.Decimal(str(entry['Cost'])) # Ensure Decimal type for calculations
                self.historical_data[service_name][date_str] = cost
        
        logger.info(f"Stored historical data for {len(self.historical_data)} services.")
        # logger.debug(f"Historical data snapshot: {json.dumps({s: {d: format_cost(c) for d,c in d_c.items()} for s, d_c in self.historical_data.items()}, indent=2)}")

    def _calculate_seven_day_moving_average(self, service_name: str, target_date: datetime.date) -> Optional[decimal.Decimal]:
        """
        Calculates the 7-day moving average cost for a given service,
        ending on the day *before* the target_date.
        This means it uses data from (target_date - N days) to (target_date - 1 day).
        Returns None if not enough data is available for the average.
        """
        history_for_service = self.historical_data.get(service_name, {})
        
        if not history_for_service:
            logger.debug(f"No historical data for service '{service_name}' to calculate average.")
            return None

        total_cost = decimal.Decimal(0)
        days_counted = 0
        
        # Calculate average for the N days *before* the target_date
        for i in range(1, self.lookback_days_for_average + 1):
            date_to_check = target_date - datetime.timedelta(days=i)
            date_str = date_to_check.isoformat()
            if date_str in history_for_service:
                total_cost += history_for_service[date_str]
                days_counted += 1
            else:
                logger.debug(f"Missing data for {service_name} on {date_str} for average calculation.")

        if days_counted < self.lookback_days_for_average:
            logger.warning(f"Not enough data for {service_name} to calculate {self.lookback_days_for_average}-day average for {target_date}. Only {days_counted} days available.")
            return None # Not enough data for a robust average

        average = total_cost / decimal.Decimal(days_counted)
        logger.debug(f"Service '{service_name}': {days_counted}-day average ending {target_date - datetime.timedelta(days=1)} is {format_cost(average)} (Total: {format_cost(total_cost)})")
        return average

    def _check_for_anomalies(self) -> None:
        """
        Compares today's cost for each service against its 7-day moving average.
        Records anomalies if the spike exceeds the configured threshold.
        """
        today = datetime.date.today()
        today_str = today.isoformat()
        
        logger.info(f"Starting anomaly check for today's date: {today_str}.")

        for service_name in self.historical_data.keys():
            current_day_cost = self.historical_data[service_name].get(today_str)
            
            if current_day_cost is None:
                logger.debug(f"No cost data for '{service_name}' on {today_str}. Skipping anomaly check.")
                continue
            
            if current_day_cost <= 0:
                logger.debug(f"Cost for '{service_name}' on {today_str} is zero or negative ({format_cost(current_day_cost)}). Skipping anomaly check.")
                continue

            moving_average = self._calculate_seven_day_moving_average(service_name, today)

            if moving_average is None:
                logger.warning(f"Cannot calculate moving average for '{service_name}' for {today_str} due to insufficient historical data. Skipping.")
                continue
            
            if moving_average <= 0:
                logger.debug(f"Moving average for '{service_name}' is zero or negative ({format_cost(moving_average)}). Skipping anomaly check to avoid division by zero or misleading alerts.")
                continue

            # Calculate percentage change
            percentage_change = ((current_day_cost - moving_average) / moving_average) * decimal.Decimal(100)

            logger.debug(f"Service: {service_name}, Today's Cost: {format_cost(current_day_cost)}, Avg Cost: {format_cost(moving_average)}, Change: {percentage_change:.2f}%")

            if percentage_change > self.anomaly_threshold_percent:
                anomaly_details = {
                    'service': service_name,
                    'date': today_str,
                    'current_cost': current_day_cost,
                    'average_cost': moving_average,
                    'percentage_change': percentage_change,
                    'threshold': self.anomaly_threshold_percent
                }
                self.anomalies.append(anomaly_details)
                logger.warning(f"ANOMALY DETECTED for service '{service_name}': Today's cost {format_cost(current_day_cost)} "
                               f"is {percentage_change:.2f}% higher than 7-day average {format_cost(moving_average)}.")

        if not self.anomalies:
            logger.info("No cost anomalies detected for any service today.")
        else:
            logger.info(f"Detected {len(self.anomalies)} anomalies today.")

    def get_anomalies(self) -> List[Dict[str, Any]]:
        """
        Returns the list of detected anomalies.
        """
        return self.anomalies

    def run_detection(self) -> None:
        """
        Executes the full anomaly detection workflow.
        """
        logger.info("Starting cloud cost anomaly detection process.")
        try:
            self._fetch_and_store_historical_data()
            if self.historical_data:
                self._check_for_anomalies()
            else:
                logger.warning("No historical data available to run anomaly detection. Exiting.")
        except Exception as e:
            logger.error(f"An unexpected error occurred during anomaly detection: {e}", exc_info=True)
            raise
        logger.info("Cloud cost anomaly detection process completed.")

# --- Alerting Manager ---
class AlertManager:
    """
    Manages sending notifications for detected anomalies, primarily via email.
    """
    def __init__(self, config: ConfigurationManager):
        self.config = config
        self.sender_email = self.config.SENDER_EMAIL
        self.sender_password = self.config.SENDER_EMAIL_PASSWORD
        self.smtp_server = self.config.SMTP_SERVER
        self.smtp_port = self.config.SMTP_PORT
        self.smtp_use_tls = self.config.SMTP_USE_TLS
        self.recipients = self.config.ALERT_RECIPIENTS

    def _format_alert_message(self, anomalies: List[Dict[str, Any]]) -> Tuple[str, str]:
        """
        Formats the subject and body of an email alert.
        """
        if not anomalies:
            return "Cloud Cost Anomaly Detector: No Anomalies Detected", "No significant cost anomalies were detected today."

        subject = f"Cloud Cost Anomaly Alert: {len(anomalies)} Spike(s) Detected!"
        
        body_parts = []
        body_parts.append(f"Hello,\n\nThe Cloud Cost Anomaly Detector has identified {len(anomalies)} potential cost spike(s) today ({datetime.date.today().isoformat()}).\n")
        body_parts.append("Please review the details below:\n")

        for i, anomaly in enumerate(anomalies):
            service = anomaly['service']
            date = anomaly['date']
            current_cost = format_cost(anomaly['current_cost'])
            average_cost = format_cost(anomaly['average_cost'])
            percentage_change = f"{anomaly['percentage_change']:.2f}%"
            threshold = f"{anomaly['threshold']:.2f}%"

            body_parts.append(f"--- Anomaly #{i+1} ---\n")
            body_parts.append(f"Service: {service}\n")
            body_parts.append(f"Date: {date}\n")
            body_parts.append(f"Today's Cost: {current_cost}\n")
            body_parts.append(f"7-Day Average Cost: {average_cost}\n")
            body_parts.append(f"Percentage Increase: {percentage_change} (Threshold: {threshold})\n")
            body_parts.append("---------------------\n")
        
        body_parts.append("\nThis is an automated alert. Please investigate these cost increases in your cloud provider's console.")
        body_parts.append(f"\nConfiguration: Provider={self.config.CLOUD_PROVIDER.upper()}, Lookback={self.config.LOOKBACK_DAYS_FOR_AVERAGE} days, Threshold={self.config.ANOMALY_THRESHOLD_PERCENT}%")
        
        return subject, "".join(body_parts)

    def send_email_alert(self, anomalies: List[Dict[str, Any]]) -> None:
        """
        Sends an email alert for detected anomalies.
        """
        if not self.recipients:
            logger.warning("No alert recipients configured. Skipping email alert.")
            return
        if not self.sender_email or not self.sender_password:
            logger.warning("Sender email or password not configured. Skipping email alert.")
            return

        subject, body = self._format_alert_message(anomalies)

        msg = MIMEMultipart()
        msg['From'] = self.sender_email
        msg['To'] = ", ".join(self.recipients)
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        try:
            logger.info(f"Attempting to send email alert to {', '.join(self.recipients)} via {self.smtp_server}:{self.smtp_port}...")
            
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                if self.smtp_use_tls:
                    server.starttls()  # Secure the connection
                    server.ehlo()
                server.login(self.sender_email, self.sender_password)
                server.sendmail(self.sender_email, self.recipients, msg.as_string())
            
            logger.info(f"Email alert successfully sent to {', '.join(self.recipients)}.")
        except smtplib.SMTPAuthenticationError:
            logger.error("SMTP authentication failed. Check sender email and password.")
        except smtplib.SMTPServerDisconnected:
            logger.error(f"SMTP server {self.smtp_server} disconnected unexpectedly.")
        except smtplib.SMTPException as e:
            logger.error(f"Failed to send email alert: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"An unexpected error occurred during email sending: {e}", exc_info=True)

# --- Main execution logic ---
def main() -> None:
    """
    Main function to parse arguments, initialize components, and run the detector.
    """
    parser = argparse.ArgumentParser(
        description="Cloud Cost Anomaly Detector: Fetches daily billing data, compares it "
                    "to a 7-day moving average, and sends alerts for significant spikes."
    )
    parser.add_argument('--provider', type=str, choices=['aws', 'azure'],
                        help="Specify the cloud provider (aws or azure). Overrides CLOUD_PROVIDER env var.",
                        default=None)
    parser.add_argument('--debug', action='store_true',
                        help="Enable debug logging for more verbose output.")
    parser.add_argument('--no-email', action='store_true',
                        help="Disable sending email alerts, only log detected anomalies.")

    args = parser.parse_args()

    if args.debug:
        setup_logging(logging.DEBUG)
        logger.debug("Debug logging enabled.")

    config_manager = ConfigurationManager()

    # Override provider if specified via command line
    if args.provider:
        config_manager._config['CLOUD_PROVIDER'] = args.provider.lower()
        logger.info(f"Cloud provider overridden by command-line argument to: {config_manager.CLOUD_PROVIDER.upper()}")
    
    # Check if CLOUD_PROVIDER is valid after potential override
    if config_manager.CLOUD_PROVIDER not in ['aws', 'azure']:
        logger.error(f"Invalid CLOUD_PROVIDER specified: {config_manager.CLOUD_PROVIDER}. Must be 'aws' or 'azure'.")
        sys.exit(1)

    logger.info(f"Initializing for cloud provider: {config_manager.CLOUD_PROVIDER.upper()}")

    billing_service: Optional[CloudBillingService] = None
    try:
        if config_manager.CLOUD_PROVIDER == 'aws':
            # Dynamically import boto3
            try:
                import boto3 # type: ignore
            except ImportError:
                logger.error("boto3 library is required for AWS. Please install it with 'pip install boto3'")
                sys.exit(1)
            billing_service = AwsBillingService(config_manager)
        elif config_manager.CLOUD_PROVIDER == 'azure':
            # Dynamically import Azure SDK components
            try:
                from azure.identity import DefaultAzureCredential, ClientSecretCredential # type: ignore
                from azure.mgmt.consumption import ConsumptionManagementClient # type: ignore
            except ImportError:
                logger.error("Azure SDK libraries (azure-identity, azure-mgmt-consumption) are required for Azure. "
                             "Please install them with 'pip install azure-identity azure-mgmt-consumption'")
                sys.exit(1)
            billing_service = AzureBillingService(config_manager)
        
        if not billing_service:
            logger.error("Failed to initialize billing service due to unsupported provider or configuration issues.")
            sys.exit(1)

        detector = CostAnomalyDetector(config_manager, billing_service)
        detector.run_detection()

        anomalies = detector.get_anomalies()

        if anomalies:
            logger.info(f"Summary: {len(anomalies)} anomalies detected.")
            if not args.no_email:
                alert_manager = AlertManager(config_manager)
                alert_manager.send_email_alert(anomalies)
            else:
                logger.info("Email alerts are disabled (--no-email flag set). Anomalies logged.")
        else:
            logger.info("No anomalies detected. All costs are within expected ranges.")

    except Exception as e:
        logger.critical(f"A fatal error occurred during script execution: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()