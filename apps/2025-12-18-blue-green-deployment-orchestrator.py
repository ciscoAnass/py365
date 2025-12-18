import time
import logging
import random
import sys
import os
from enum import Enum

# Custom exception for deployment errors to allow specific error handling
class DeploymentException(Exception):
    """Custom exception for Blue-Green deployment errors."""
    pass

# Enum to represent the current phase of the deployment for clear state tracking
class DeploymentPhase(Enum):
    INITIALIZING = "Initializing Deployment"
    PROVISIONING_GREEN = "Provisioning Green Environment"
    HEALTH_CHECKING_GREEN = "Health Checking Green Environment"
    SHIFTING_TRAFFIC = "Shifting Traffic to Green"
    VALIDATING_GREEN = "Validating Green Environment"
    TEARING_DOWN_BLUE = "Tearing Down Blue Environment"
    FINALIZING = "Finalizing Deployment"
    ROLLING_BACK = "Rolling Back Deployment"
    FAILED = "Deployment Failed"
    COMPLETED = "Deployment Completed Successfully"

# --- Configuration ---
# Global configuration for the blue-green deployment.
# In a real-world production system, this configuration would typically be
# loaded from external sources like a YAML/JSON file, environment variables,
# a configuration management service (e.g., AWS Parameter Store, HashiCorp Vault),
# or passed as command-line arguments. For this script, it's hardcoded for
# simplicity and completeness within a single file.
CONFIG = {
    "APP_NAME": "MyAppService",
    "BLUE_ENV_NAME": "myapp-prod-blue",
    "GREEN_ENV_NAME": "myapp-prod-green",
    "REGION": "us-east-1",  # AWS region, for simulation context
    "INSTANCE_TYPE": "t3.medium",  # Simulated instance type
    "MIN_INSTANCES": 2,
    "MAX_INSTANCES": 4,
    "HEALTH_CHECK_URL": "http://green-env-load-balancer.example.com/health",
    "HEALTH_CHECK_INTERVAL_SECONDS": 5,  # Time between health check retries
    "HEALTH_CHECK_RETRIES": 10,          # Number of health check retries
    "TRAFFIC_SHIFT_INTERVAL_SECONDS": 10,  # Time to observe after each traffic percentage increment
    "TRAFFIC_SHIFT_STEP_PERCENTAGE": 10,   # How much traffic to shift in each step (e.g., 10% per step)
    "VALIDATION_PERIOD_SECONDS": 90,       # Time to observe green env after full shift
    "TEARDOWN_WAIT_SECONDS": 60,           # Wait before tearing down blue after validation
    "LOAD_BALANCER_ARN": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/myapp-main-lb/xxxxxxxxxxxxxxx",
    "BLUE_TARGET_GROUP_ARN": "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/myapp-blue-tg/yyyyyyyyyyyyyyy",
    "GREEN_TARGET_GROUP_ARN": "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/myapp-green-tg/zzzzzzzzzzzzzzz",
    "MAIN_LISTENER_ARN": "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/myapp-main-lb/xxxxxxxxxxxxxxx/ppppppppppppppp", # Main listener for traffic rules
    "BLUE_AUTO_SCALING_GROUP_NAME": "myapp-blue-asg",
    "GREEN_AUTO_SCALING_GROUP_NAME": "myapp-green-asg",
    "DNS_RECORD_NAME": "app.example.com", # For potential DNS updates if using separate LBs or CNAME shifts
    "DNS_HOSTED_ZONE_ID": "ZXXXXXXXXXXXXX", # Hosted Zone ID for DNS updates
    "SIMULATE_FAILURE_PROBABILITY": 0.05, # Probability of a simulated health check/provisioning failure
    "LOG_LEVEL": "INFO" # Set to "DEBUG" for more verbose output
}

# --- Global State Tracking ---
# This class maintains the dynamic state of the deployment throughout its lifecycle.
# It acts as a central point of truth for the deployment process, allowing different
# functions to access and update the current status.
class DeploymentState:
    def __init__(self, config: dict):
        self.config = config
        self.current_phase = DeploymentPhase.INITIALIZING
        self.traffic_shifted_to_green_percent = 0
        self.blue_env_active = True  # True if blue is considered the primary, active environment
        self.green_env_provisioned = False
        self.green_env_healthy = False
        self.rollback_needed = False  # Flag to indicate if a rollback should be performed
        self.start_time = time.time()
        self.end_time = None
        self.error_message = None

    def update_phase(self, new_phase: DeploymentPhase):
        """Updates the current phase of the deployment and logs it."""
        self.current_phase = new_phase
        logging.info(f"--- Entering Phase: {new_phase.value} ---")

    def __str__(self) -> str:
        """Provides a human-readable summary of the current deployment state."""
        duration = f"{(self.end_time - self.start_time):.2f}s" if self.end_time else "N/A"
        return (f"\n--- Current Deployment State Summary ---\n"
                f"  Phase: {self.current_phase.value}\n"
                f"  Traffic to Green: {self.traffic_shifted_to_green_percent}%\n"
                f"  Blue Env Active: {self.blue_env_active}\n"
                f"  Green Env Provisioned: {self.green_env_provisioned}\n"
                f"  Green Env Healthy: {self.green_env_healthy}\n"
                f"  Rollback Needed: {self.rollback_needed}\n"
                f"  Deployment Duration: {duration}\n"
                f"  Last Error: {self.error_message or 'None'}\n"
                f"----------------------------------------")

# --- Logging Setup ---
def setup_logging(log_level_str: str = "INFO"):
    """
    Sets up detailed logging for the script, including console output and file logging.
    Logs are written to 'blue_green_deployment.log' in the current directory.
    """
    log_level = getattr(logging, log_level_str.upper(), logging.INFO)

    # Configure the root logger
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[
            logging.StreamHandler(sys.stdout),  # Output logs to console
            logging.FileHandler("blue_green_deployment.log", mode='w')  # Output logs to a file, overwrite on each run
        ]
    )
    # If using real cloud SDKs, you might want to suppress their verbose logging:
    # logging.getLogger("boto3").setLevel(logging.WARNING)
    # logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.info(f"Logging configured at level: {log_level_str.upper()}")
    logging.info("-" * 80)
    logging.info("Starting Blue-Green Deployment Orchestrator Script")
    logging.info("-" * 80)

# --- Simulation Helper Functions ---
# These functions simulate interactions with a cloud provider's API (e.g., AWS, Azure, GCP).
# In a real-world scenario, these would be replaced with actual SDK calls (e.g., boto3 for AWS).

def simulate_api_call(action_description: str, delay_min: int = 2, delay_max: int = 7,
                      success_rate: float = 0.95, simulated_failure_prob: float = 0.0) -> bool:
    """
    Simulates an API call to a cloud provider with random delay and a chance of failure.

    Args:
        action_description (str): A description of the action being simulated (for logging).
        delay_min (int): Minimum delay in seconds for the simulated call.
        delay_max (int): Maximum delay in seconds for the simulated call.
        success_rate (float): Base probability of the API call succeeding (0.0 to 1.0).
        simulated_failure_prob (float): Additional probability for *this specific* action to fail,
                                        overriding the general success_rate if higher.

    Returns:
        bool: True if the simulated call succeeded, False otherwise.

    Raises:
        DeploymentException: If the simulated API call fails.
    """
    # Calculate the actual failure probability for this specific call
    calculated_failure_prob = max(0.0, min(1.0, (1.0 - success_rate) + simulated_failure_prob))

    # Determine if a simulated failure should occur
    if random.random() < calculated_failure_prob:
        logging.error(f"SIMULATION FAILED: {action_description}")
        raise DeploymentException(f"Simulated API call for '{action_description}' failed.")

    delay = random.randint(delay_min, delay_max)
    logging.debug(f"Simulating API call: '{action_description}' for {delay} seconds...")
    time.sleep(delay)
    logging.debug(f"Simulation complete: '{action_description}'")
    return True

def get_current_traffic_distribution(state: DeploymentState) -> tuple[int, int]:
    """
    Simulates fetching the current traffic distribution weights from the load balancer.
    In a real scenario, this would involve querying the ALB listener rules to get
    the weighted target group settings.

    Args:
        state (DeploymentState): The current deployment state object.

    Returns:
        tuple: A tuple containing (blue_weight_percent, green_weight_percent).
    """
    logging.info("Simulating fetching current traffic distribution from load balancer...")
    # For simulation, we'll just return the state's tracked value, assuming it's accurate.
    # A real implementation would parse the LB listener rules for target group weights.
    blue_weight = 100 - state.traffic_shifted_to_green_percent
    green_weight = state.traffic_shifted_to_green_percent
    logging.info(f"Current traffic distribution reported: Blue={blue_weight}%, Green={green_weight}%")
    return blue_weight, green_weight

def update_traffic_distribution(state: DeploymentState, blue_weight: int, green_weight: int):
    """
    Simulates updating the load balancer listener rules to shift traffic.
    This modifies the weights of the blue and green target groups attached to the listener.

    Args:
        state (DeploymentState): The current deployment state object.
        blue_weight (int): Percentage of traffic to send to the blue environment (0-100).
        green_weight (int): Percentage of traffic to send to the green environment (0-100).

    Raises:
        ValueError: If traffic weights are invalid.
        DeploymentException: If the simulated update fails.
    """
    if not (0 <= blue_weight <= 100 and 0 <= green_weight <= 100 and (blue_weight + green_weight == 100)):
        raise ValueError("Traffic weights must be between 0-100 and sum to 100.")

    action_description = (f"Updating Load Balancer listener '{state.config['MAIN_LISTENER_ARN']}' "
                          f"rules to distribute traffic: Blue={blue_weight}%, Green={green_weight}%")
    simulate_api_call(
        action_description,
        delay_min=3,
        delay_max=8,
        simulated_failure_prob=state.config["SIMULATE_FAILURE_PROBABILITY"] / 2 # Less likely to fail
    )
    state.traffic_shifted_to_green_percent = green_weight
    logging.info(f"Traffic distribution successfully updated (simulated): Blue={blue_weight}%, Green={green_weight}%")

def perform_health_check(url: str, retries: int, interval: int, env_name: str, state: DeploymentState) -> bool:
    """
    Simulates performing a series of HTTP health checks against a given URL.

    Args:
        url (str): The URL endpoint to check for health.
        retries (int): Number of times to retry the health check.
        interval (int): Time in seconds to wait between retries.
        env_name (str): The name of the environment being checked (for logging).
        state (DeploymentState): The current deployment state.

    Returns:
        bool: True if the health check passes within the retries, False otherwise.
    """
    logging.info(f"Initiating health checks for {env_name} at {url} (Retries: {retries}, Interval: {interval}s)...")
    for i in range(retries):
        logging.debug(f"Attempt {i+1}/{retries} for {env_name} health check...")
        try:
            # Simulate an HTTP GET request to the health endpoint.
            # In a real scenario, this would use 'requests.get(url, timeout=...)'.
            if random.random() < state.config["SIMULATE_FAILURE_PROBABILITY"]:
                # Simulate a temporary network issue or application error
                raise DeploymentException(f"Simulated HTTP error for {env_name} health check.")

            logging.debug(f"{env_name} health check successful (simulated).")
            return True # Health check passed
        except DeploymentException as e:
            logging.warning(f"Health check for {env_name} failed: {e}. Retrying in {interval}s...")
            time.sleep(interval)
        except Exception as e:
            logging.error(f"Unexpected error during {env_name} health check attempt {i+1}: {e}")
            time.sleep(interval)

    logging.error(f"Health checks for {env_name} failed after {retries} attempts. Environment is considered unhealthy.")
    return False

def provision_instance_fleet(env_name: str, config: dict) -> bool:
    """
    Simulates provisioning the compute resources for an environment, such as
    creating EC2 instances, configuring an Auto Scaling Group (ASG), and
    attaching them to a Load Balancer Target Group.
    """
    logging.info(f"Simulating provisioning instance fleet for '{env_name}'...")
    try:
        # Step 1: Create/Update Launch Configuration/Template
        simulate_api_call(
            f"Creating/Updating Launch Configuration/Template for {env_name}",
            simulated_failure_prob=config["SIMULATE_FAILURE_PROBABILITY"]
        )
        # Step 2: Create/Update Auto Scaling Group
        simulate_api_call(
            f"Creating/Updating Auto Scaling Group '{config[f'{env_name.upper()}_AUTO_SCALING_GROUP_NAME']}' for {env_name} "
            f"with {config['MIN_INSTANCES']}-{config['MAX_INSTANCES']} instances of type {config['INSTANCE_TYPE']}",
            delay_min=10, delay_max=20, # ASG operations can take longer
            simulated_failure_prob=config["SIMULATE_FAILURE_PROBABILITY"]
        )
        # Step 3: Attach ASG to Target Group
        simulate_api_call(
            f"Attaching {env_name} ASG to Target Group '{config[f'{env_name.upper()}_TARGET_GROUP_ARN']}'",
            simulated_failure_prob=config["SIMULATE_FAILURE_PROBABILITY"]
        )
        # Step 4: Wait for instances to register and become healthy
        simulate_api_call(
            f"Waiting for {env_name} instances to report healthy in target group...",
            delay_min=15, delay_max=30, success_rate=0.99 # Instances usually come up healthy, but can take time
        )
        logging.info(f"Instance fleet for '{env_name}' provisioned successfully (simulated).")
        return True
    except DeploymentException as e:
        logging.error(f"Failed to provision instance fleet for {env_name}: {e}")
        return False

def provision_load_balancer_target_group(env_name: str, config: dict) -> bool:
    """
    Simulates creating or configuring the load balancer target group for the environment.
    Assumes the main Load Balancer already exists. This function would typically
    ensure the target group exists and is properly configured for health checks.
    """
    logging.info(f"Simulating creation/configuration of Target Group for '{env_name}'...")
    try:
        # In a typical shared ALB setup, the target groups for blue and green would
        # usually be created once and then their weights modified. We simulate its creation/readiness.
        simulate_api_call(
            f"Creating/Ensuring Target Group '{config[f'{env_name.upper()}_TARGET_GROUP_ARN']}' for {env_name} is ready",
            simulated_failure_prob=config["SIMULATE_FAILURE_PROBABILITY"] / 2
        )
        logging.info(f"Target Group for '{env_name}' configured successfully (simulated).")
        return True
    except DeploymentException as e:
        logging.error(f"Failed to configure Target Group for {env_name}: {e}")
        return False

def validate_environment_deep(env_name: str, url: str, state: DeploymentState) -> bool:
    """
    Performs more extensive application-level validation beyond a simple health check.
    This can include integration tests, synthetic transactions, checking specific
    application metrics, or even running performance tests.

    Args:
        env_name (str): The name of the environment to validate.
        url (str): Base URL for validation tests.
        state (DeploymentState): The current deployment state.

    Returns:
        bool: True if validation passes, False otherwise.
    """
    logging.info(f"Initiating deep validation for {env_name} at {url}...")
    try:
        # Simulate various application-specific tests
        simulate_api_call(f"Running integration test 'User Login Flow' on {env_name}", delay_min=5, delay_max=10, simulated_failure_prob=state.config["SIMULATE_FAILURE_PROBABILITY"] / 3)
        simulate_api_call(f"Running integration test 'Payment Processing' on {env_name}", delay_min=5, delay_max=10, simulated_failure_prob=state.config["SIMULATE_FAILURE_PROBABILITY"] / 3)
        simulate_api_call(f"Checking application logs for critical errors on {env_name}", delay_min=3, delay_max=7, simulated_failure_prob=state.config["SIMULATE_FAILURE_PROBABILITY"] / 5)
        simulate_api_call(f"Verifying key metric dashboards (e.g., latency, error rates) for {env_name}", delay_min=5, delay_max=12, simulated_failure_prob=state.config["SIMULATE_FAILURE_PROBABILITY"] / 4)
        logging.info(f"Deep validation for {env_name} completed successfully (simulated). All checks passed.")
        return True
    except DeploymentException as e:
        logging.error(f"Deep validation for {env_name} failed: {e}")
        return False

def scale_auto_scaling_group(asg_name: str, min_size: int, max_size: int, desired_capacity: int, state: DeploymentState) -> bool:
    """
    Simulates updating the min, max, and desired capacity of an Auto Scaling Group.
    This is useful for scaling down the blue environment, or scaling up/down green as needed.
    """
    logging.info(f"Simulating scaling ASG '{asg_name}' to min={min_size}, max={max_size}, desired={desired_capacity}...")
    try:
        simulate_api_call(
            f"Updating ASG '{asg_name}' capacities to min:{min_size}, max:{max_size}, desired:{desired_capacity}",
            delay_min=3, delay_max=10,
            simulated_failure_prob=state.config["SIMULATE_FAILURE_PROBABILITY"] / 5 # Scaling usually more robust
        )
        logging.info(f"ASG '{asg_name}' scaled successfully (simulated).")
        return True
    except DeploymentException as e:
        logging.error(f"Failed to scale ASG '{asg_name}': {e}")
        return False

def deprovision_environment_resources(env_name: str, config: dict) -> bool:
    """
    Simulates tearing down all resources associated with a given environment.
    This typically includes:
    1. Deleting the Auto Scaling Group (which terminates instances).
    2. Deleting the Launch Template/Configuration.
    3. Deregistering instances from the Target Group.
    4. Deleting the Target Group itself.
    """
    logging.info(f"Initiating deprovisioning of '{env_name}' environment resources...")
    try:
        # Order matters for dependencies: ASG -> Launch Template -> Target Group
        simulate_api_call(
            f"Deleting Auto Scaling Group '{config[f'{env_name.upper()}_AUTO_SCALING_GROUP_NAME']}'",
            delay_min=5, delay_max=15, # ASG deletion can take time for instances to terminate
            simulated_failure_prob=config["SIMULATE_FAILURE_PROBABILITY"]
        )
        simulate_api_call(
            f"Deleting Launch Template/Configuration for '{env_name}'",
            delay_min=3, delay_max=10,
            simulated_failure_prob=config["SIMULATE_FAILURE_PROBABILITY"]
        )
        simulate_api_call(
            f"Deregistering instances from Target Group '{config[f'{env_name.upper()}_TARGET_GROUP_ARN']}'",
            delay_min=3, delay_max=10,
            simulated_failure_prob=config["SIMULATE_FAILURE_PROBABILITY"] / 2
        )
        simulate_api_call(
            f"Deleting Target Group '{config[f'{env_name.upper()}_TARGET_GROUP_ARN']}'",
            delay_min=3, delay_max=10,
            simulated_failure_prob=config["SIMULATE_FAILURE_PROBABILITY"]
        )
        logging.info(f"All resources for '{env_name}' deprovisioned successfully (simulated).")
        return True
    except DeploymentException as e:
        logging.error(f"Failed to deprovision resources for '{env_name}': {e}. Manual intervention may be required.")
        return False

def prompt_for_confirmation(message: str, default_yes: bool = True) -> bool:
    """
    Prompts the user for confirmation for critical actions.
    Can be bypassed by setting the environment variable BLUE_GREEN_NON_INTERACTIVE to 'true'.

    Args:
        message (str): The message to display to the user.
        default_yes (bool): If True, pressing Enter defaults to 'Yes'.

    Returns:
        bool: True if the user confirms, False otherwise.
    """
    # Check for non-interactive mode environment variable
    if os.getenv("BLUE_GREEN_NON_INTERACTIVE", "false").lower() == "true":
        logging.info("Running in non-interactive mode. Auto-confirming actions to 'True'.")
        return True

    suffix = "[Y/n]" if default_yes else "[y/N]"
    while True:
        try:
            response = input(f"{message} {suffix}: ").strip().lower()
            if not response: # User just pressed Enter
                return default_yes
            if response in ["y", "yes"]:
                return True
            if response in ["n", "no"]:
                return False
        except EOFError: # Handles cases where stdin is closed (e.g., CI/CD without input)
            logging.warning("No interactive input detected (EOF). Auto-confirming based on default.")
            return default_yes
        except KeyboardInterrupt:
            logging.warning("User interrupted confirmation with Ctrl+C. Assuming 'no' to prevent unintended actions.")
            return False # Treat as a 'no' to be safe
        logging.warning("Invalid input. Please enter 'y' or 'n'.")


# --- Main Orchestration Functions ---
# These functions define the distinct phases of the blue-green deployment.

def initialize_deployment(state: DeploymentState):
    """
    Initializes the deployment process, performs necessary pre-checks, and sets the initial state.
    This phase ensures that the environment is ready for a blue-green deployment.
    """
    state.update_phase(DeploymentPhase.INITIALIZING)
    logging.info(f"Starting Blue-Green Deployment for Application: {state.config['APP_NAME']}")
    logging.info(f"Current (Blue) Environment: {state.config['BLUE_ENV_NAME']}")
    logging.info(f"New (Green) Environment: {state.config['GREEN_ENV_NAME']}")

    logging.info("Performing pre-deployment checks...")
    try:
        # Simulate checking connectivity to cloud APIs and required services
        simulate_api_call("Checking cloud provider API connectivity for deployment operations.")
        simulate_api_call("Verifying IAM permissions for deployment user/role.")

        # Simulate checking if the blue environment is stable and ready for a blue-green
        logging.info(f"Verifying health of the existing Blue environment '{state.config['BLUE_ENV_NAME']}'.")
        blue_health_ok = perform_health_check(
            "http://blue-env-load-balancer.example.com/health", # Hypothetical blue health URL
            state.config["HEALTH_CHECK_RETRIES"] // 2, # Fewer retries for existing env, should be stable
            state.config["HEALTH_CHECK_INTERVAL_SECONDS"],
            state.config["BLUE_ENV_NAME"],
            state
        )
        if not blue_health_ok:
            raise DeploymentException("Blue environment is not healthy. Aborting deployment to prevent issues.")

        logging.info("Pre-deployment checks completed successfully. Blue environment is stable.")
        state.blue_env_active = True # Confirm blue is the current active environment
        state.green_env_provisioned = False
        state.green_env_healthy = False
        state.traffic_shifted_to_green_percent = 0 # Explicitly set initial state to 0% traffic to green
    except DeploymentException as e:
        logging.critical(f"Initialization failed: {e}")
        state.error_message = str(e)
        raise # Re-raise to trigger the main orchestrator's exception handling

    logging.info(state) # Log the updated state

def provision_green_environment(state: DeploymentState):
    """
    Provisions all necessary infrastructure and application resources for the
    new 'green' environment. This includes compute, networking, and application deployment.
    """
    state.update_phase(DeploymentPhase.PROVISIONING_GREEN)
    logging.info(f"Starting provisioning of Green Environment: {state.config['GREEN_ENV_NAME']}")

    try:
        # Provision the Load Balancer Target Group for green
        if not provision_load_balancer_target_group(state.config["GREEN_ENV_NAME"], state.config):
            raise DeploymentException(f"Failed to configure Target Group for {state.config['GREEN_ENV_NAME']}.")

        # Provision the compute fleet (e.g., EC2 instances, ASG)
        if not provision_instance_fleet(state.config["GREEN_ENV_NAME"], state.config):
            raise DeploymentException(f"Failed to provision instance fleet for {state.config['GREEN_ENV_NAME']}.")

        # Simulate deploying the application code to the new green instances
        simulate_api_call(f"Deploying application code to {state.config['GREEN_ENV_NAME']}", delay_min=8, delay_max=15)
        simulate_api_call(f"Configuring environment variables and secrets for {state.config['GREEN_ENV_NAME']}")

        state.green_env_provisioned = True
        logging.info(f"Green Environment '{state.config['GREEN_ENV_NAME']}' provisioned and application deployed successfully (simulated).")
    except DeploymentException as e:
        logging.critical(f"Provisioning of Green Environment failed: {e}")
        state.error_message = str(e)
        raise

    logging.info(state)

def run_pre_shift_health_checks(state: DeploymentState):
    """
    Runs initial health checks and deep validations on the newly provisioned
    'green' environment *before* any production traffic is routed to it.
    This ensures the green environment is fully operational and stable.
    """
    state.update_phase(DeploymentPhase.HEALTH_CHECKING_GREEN)
    logging.info(f"Running comprehensive pre-shift health checks on Green Environment: {state.config['GREEN_ENV_NAME']}")

    try:
        # Perform basic HTTP health checks
        green_health_ok = perform_health_check(
            state.config["HEALTH_CHECK_URL"],
            state.config["HEALTH_CHECK_RETRIES"],
            state.config["HEALTH_CHECK_INTERVAL_SECONDS"],
            state.config["GREEN_ENV_NAME"],
            state
        )
        if not green_health_ok:
            raise DeploymentException(f"Green Environment '{state.config['GREEN_ENV_NAME']}' failed initial HTTP health checks.")

        # Perform deeper application-level validation
        if not validate_environment_deep(state.config["GREEN_ENV_NAME"], state.config["HEALTH_CHECK_URL"], state):
            raise DeploymentException(f"Green Environment '{state.config['GREEN_ENV_NAME']}' failed deep application validation tests.")

        state.green_env_healthy = True
        logging.info(f"Green Environment '{state.config['GREEN_ENV_NAME']}' passed all pre-shift health checks and deep validations. It is ready to receive traffic.")
    except DeploymentException as e:
        logging.critical(f"Pre-shift health checks for Green Environment failed: {e}")
        state.error_message = str(e)
        raise

    logging.info(state)

def shift_traffic_gradually(state: DeploymentState):
    """
    Gradually shifts production traffic from the old 'blue' environment to the
    new 'green' environment. This is done in configurable steps, with validation
    after each step to ensure stability.
    """
    state.update_phase(DeploymentPhase.SHIFTING_TRAFFIC)
    logging.info(f"Starting gradual traffic shift to Green Environment: {state.config['GREEN_ENV_NAME']}")

    try:
        current_green_weight = state.traffic_shifted_to_green_percent
        target_green_weight = 100
        step = state.config["TRAFFIC_SHIFT_STEP_PERCENTAGE"]

        # Loop until 100% of traffic is shifted to green
        while current_green_weight < target_green_weight:
            next_green_weight = min(current_green_weight + step, target_green_weight)
            next_blue_weight = 100 - next_green_weight

            logging.info(f"Attempting to shift traffic to: Blue {next_blue_weight}% / Green {next_green_weight}%")

            # Update load balancer weights
            update_traffic_distribution(state, next_blue_weight, next_green_weight)

            current_green_weight = state.traffic_shifted_to_green_percent
            logging.info(f"Traffic successfully shifted to Green {current_green_weight}%. Waiting for observation period ({state.config['TRAFFIC_SHIFT_INTERVAL_SECONDS']}s)...")
            time.sleep(state.config["TRAFFIC_SHIFT_INTERVAL_SECONDS"])

            # After each traffic shift, perform quick health checks on BOTH environments
            # to detect any immediate issues caused by the shift.
            logging.debug(f"Performing post-shift mini health check for Blue ({next_blue_weight}%) and Green ({next_green_weight}%)...")
            blue_health = perform_health_check(
                "http://blue-env-load-balancer.example.com/health", # Hypothetical blue health URL
                3, # Fewer retries for quick check
                5, # Shorter interval
                state.config["BLUE_ENV_NAME"], state
            )
            green_health = perform_health_check(
                state.config["HEALTH_CHECK_URL"],
                3, 5, state.config["GREEN_ENV_NAME"], state
            )

            if not (blue_health and green_health):
                logging.error("Health check failure detected on either Blue or Green environment after traffic shift. Initiating rollback!")
                state.rollback_needed = True
                raise DeploymentException("Health check failure detected during gradual traffic shift.")

            # Optional: Prompt for manual approval at significant traffic shift points
            if next_green_weight in [25, 50, 75] and not prompt_for_confirmation(f"Traffic is now at {next_green_weight}% to Green. Continue with further traffic shift?"):
                logging.warning("User elected to stop traffic shift. Initiating rollback!")
                state.rollback_needed = True
                raise DeploymentException("User cancelled traffic shift at validation point.")

        logging.info("Traffic successfully shifted 100% to Green Environment. Blue is now drained.")
        state.blue_env_active = False # Blue is no longer receiving any traffic
    except DeploymentException as e:
        logging.critical(f"Traffic shifting failed: {e}")
        state.error_message = str(e)
        raise

    logging.info(state)

def run_post_shift_validation(state: DeploymentState):
    """
    After 100% of traffic has been shifted to the green environment,
    this phase performs a final, extended validation and monitoring period
    to ensure the green environment is stable under full production load.
    """
    state.update_phase(DeploymentPhase.VALIDATING_GREEN)
    logging.info(f"Performing final post-shift validation on Green Environment (observing for {state.config['VALIDATION_PERIOD_SECONDS']}s)...")

    try:
        # Re-run deep validation one last time after full traffic shift
        if not validate_environment_deep(state.config["GREEN_ENV_NAME"], state.config["HEALTH_CHECK_URL"], state):
            logging.error("Green environment failed post-shift deep validation under full load. Initiating rollback!")
            state.rollback_needed = True
            raise DeploymentException(f"Green Environment '{state.config['GREEN_ENV_NAME']}' failed post-shift deep validation.")

        logging.info(f"Monitoring Green Environment for {state.config['VALIDATION_PERIOD_SECONDS']} seconds for stability...")
        start_validation = time.time()
        while (time.time() - start_validation) < state.config["VALIDATION_PERIOD_SECONDS"]:
            # Simulate continuous monitoring (e.g., checking application metrics, logs, error rates)
            # In a real scenario, this would involve integrating with monitoring systems (Prometheus, Datadog, CloudWatch)
            elapsed_time = int(time.time() - start_validation)
            remaining_time = state.config["VALIDATION_PERIOD_SECONDS"] - elapsed_time
            logging.debug(f"Monitoring Green Environment... Time elapsed: {elapsed_time}s, Remaining: {remaining_time}s")

            # Re-run a quick health check during the monitoring period
            if not perform_health_check(state.config["HEALTH_CHECK_URL"], 1, 0, state.config["GREEN_ENV_NAME"], state):
                logging.error("Green environment became unhealthy during the post-shift validation period! Initiating rollback.")
                state.rollback_needed = True
                raise DeploymentException("Green environment became unhealthy post-shift during sustained monitoring.")

            # Simulate detection of critical application errors or performance degradation
            if random.random() < state.config["SIMULATE_FAILURE_PROBABILITY"] / 10: # Lower probability for this critical check
                 logging.error("Simulated critical error rate or performance degradation detected in Green Environment during validation! Initiating rollback.")
                 state.rollback_needed = True
                 raise DeploymentException("Critical application issues detected post-shift.")

            time.sleep(state.config["HEALTH_CHECK_INTERVAL_SECONDS"]) # Check every few seconds

        logging.info(f"Post-shift validation and monitoring for Green Environment completed successfully. Green is stable under full load.")
    except DeploymentException as e:
        logging.critical(f"Post-shift validation failed: {e}")
        state.error_message = str(e)
        raise

    logging.info(state)

def tear_down_blue_environment(state: DeploymentState):
    """
    After successful deployment and validation of the green environment,
    the old 'blue' environment is decommissioned and its resources are released.
    This is a destructive step and typically requires explicit confirmation.
    """
    state.update_phase(DeploymentPhase.TEARING_DOWN_BLUE)
    logging.info(f"Waiting {state.config['TEARDOWN_WAIT_SECONDS']} seconds before tearing down Blue Environment to allow for graceful connection draining (if any lingering connections exist)...")
    time.sleep(state.config['TEARDOWN_WAIT_SECONDS'])

    # Optional: Scale down blue to 0 before actual teardown to ensure all connections are drained
    logging.info(f"Attempting to scale down Blue ASG '{state.config['BLUE_AUTO_SCALING_GROUP_NAME']}' to 0 instances for graceful draining...")
    try:
        scale_auto_scaling_group(state.config['BLUE_AUTO_SCALING_GROUP_NAME'], 0, 0, 0, state)
        logging.info(f"Blue ASG scaled down. Waiting {state.config['TEARDOWN_WAIT_SECONDS'] / 2:.0f}s for instances to terminate/drain.")
        time.sleep(state.config['TEARDOWN_WAIT_SECONDS'] / 2)
    except DeploymentException as e:
        logging.warning(f"Could not scale down blue ASG gracefully to 0: {e}. Proceeding with direct teardown.")

    # Explicit user confirmation for tearing down the old production environment
    if not prompt_for_confirmation(f"Confirm teardown of Blue Environment '{state.config['BLUE_ENV_NAME']}'?", default_yes=False):
        logging.warning("User cancelled blue environment teardown. Resources for blue environment remain active. Manual cleanup will be required.")
        raise DeploymentException("User cancelled blue environment teardown. Deployment halted mid-completion.")

    logging.info(f"Starting complete teardown of Blue Environment: {state.config['BLUE_ENV_NAME']}")
    try:
        # Ensure traffic is 0% to blue before tearing down, as a safeguard
        logging.info("Double-checking traffic distribution to ensure Blue is at 0% before deprovisioning...")
        update_traffic_distribution(state, 0, 100)

        # Deprovision all resources associated with the blue environment
        if not deprovision_environment_resources(state.config["BLUE_ENV_NAME"], state.config):
            raise DeploymentException(f"Failed to deprovision resources for {state.config['BLUE_ENV_NAME']}. Manual intervention is required to clean up blue environment.")

        logging.info(f"Blue Environment '{state.config['BLUE_ENV_NAME']}' successfully torn down.")
    except DeploymentException as e:
        logging.error(f"Failed to tear down Blue Environment: {e}. This is a critical issue post-deployment. Manual intervention is REQUIRED.")
        state.error_message = str(e)
        raise # Still raise, as this indicates a partial success state needing attention

    logging.info(state)

def rollback_deployment(state: DeploymentState):
    """
    Initiates a rollback procedure. This typically involves shifting all traffic
    back to the original 'blue' environment and then deprovisioning the
    problematic 'green' environment.
    """
    state.update_phase(DeploymentPhase.ROLLING_BACK)
    logging.warning("\n" + "="*80)
    logging.warning("!!! INITIATING ROLLBACK PROCEDURE DUE TO DEPLOYMENT FAILURE OR USER CANCELLATION !!!")
    logging.warning("="*80 + "\n")

    try:
        # Step 1: Immediately shift all traffic back to the Blue environment
        logging.info("Shifting all traffic back to Blue environment (100% Blue / 0% Green)...")
        update_traffic_distribution(state, 100, 0)
        state.traffic_shifted_to_green_percent = 0
        state.blue_env_active = True
        logging.info("Traffic successfully reverted to Blue environment. Blue is now the active production environment.")

        # Step 2: Scale down and deprovision the problematic Green environment
        logging.info(f"Starting deprovisioning of the failed Green Environment: {state.config['GREEN_ENV_NAME']}")
        # First, scale down green ASG to 0 to terminate instances
        scale_auto_scaling_group(state.config['GREEN_AUTO_SCALING_GROUP_NAME'], 0, 0, 0, state)
        logging.info("Waiting 10 seconds for green instances to terminate before full deprovisioning...")
        time.sleep(10)
        if not deprovision_environment_resources(state.config["GREEN_ENV_NAME"], state.config):
            logging.error(f"Failed to fully deprovision Green Environment during rollback. Manual cleanup will be required for {state.config['GREEN_ENV_NAME']}.")
        else:
            logging.info(f"Green Environment '{state.config['GREEN_ENV_NAME']}' successfully deprovisioned during rollback.")
        state.green_env_provisioned = False
        state.green_env_healthy = False

        logging.warning("Rollback completed. Original Blue environment is now fully active and green resources are deprovisioned (or flagged for manual cleanup).")
    except DeploymentException as e:
        logging.critical(f"Rollback itself encountered an error: {e}. Manual intervention is HIGHLY recommended to ensure system stability.")
        state.error_message = f"Rollback failed: {e}. Original deployment error: {state.error_message}"
    except Exception as e:
        logging.critical(f"An unexpected error occurred during rollback: {e}. Manual intervention is HIGHLY recommended to ensure system stability.", exc_info=True)
        state.error_message = f"Unexpected rollback error: {e}. Original deployment error: {state.error_message}"

    state.update_phase(DeploymentPhase.FAILED) # A rollback always implies the initial deployment failed
    logging.info(state)

def finalize_deployment(state: DeploymentState):
    """
    Performs final checks, logs the overall outcome of the deployment,
    and performs any post-deployment tasks such as sending notifications.
    """
    if state.current_phase != DeploymentPhase.FAILED:
        state.update_phase(DeploymentPhase.FINALIZING)
        logging.info("Finalizing deployment...")
        # Simulate post-deployment tasks:
        simulate_api_call("Sending success notification to DevOps team", delay_min=1, delay_max=3)
        simulate_api_call("Updating deployment status in CI/CD pipeline/dashboard", delay_min=1, delay_max=3)
        logging.info("Deployment completion tasks (e.g., notification, metric updates) simulated.")

        logging.info("\n" + "*"*80)
        logging.info("                   BLUE-GREEN DEPLOYMENT SUMMARY                   ")
        logging.info("*"*80)
        logging.info(f"Application: {state.config['APP_NAME']}")
        logging.info(f"New Environment: {state.config['GREEN_ENV_NAME']}")
        logging.info(f"Traffic shifted to Green: {state.traffic_shifted_to_green_percent}%")
        logging.info(f"Old Blue Environment: {state.config['BLUE_ENV_NAME']} is {'active' if state.blue_env_active else 'inactive/torn down'}")

        if state.current_phase == DeploymentPhase.TEARING_DOWN_BLUE:
            state.update_phase(DeploymentPhase.COMPLETED)
            logging.info("\nDeployment completed successfully!")
        else:
            logging.warning("\nDeployment finalized, but the blue environment was NOT fully torn down due to an issue. Manual cleanup may be required.")
            state.update_phase(DeploymentPhase.FAILED) # Consider it failed if teardown didn't complete cleanly

    state.end_time = time.time()
    logging.info(state)
    logging.info("*"*80)
    logging.info("Blue-Green Deployment Orchestrator Script Finished.")
    logging.info("*"*80)


def orchestrate_blue_green_deployment(config: dict):
    """
    The main orchestrator function that defines the complete Blue-Green deployment workflow.
    It manages the state transitions and calls the individual phase functions.
    Includes comprehensive error handling and rollback logic.
    """
    setup_logging(config.get("LOG_LEVEL", "INFO"))
    state = DeploymentState(config)

    try:
        initialize_deployment(state)
        provision_green_environment(state)
        run_pre_shift_health_checks(state)
        shift_traffic_gradually(state)
        run_post_shift_validation(state)
        tear_down_blue_environment(state)
        # If no exceptions were raised up to this point, the deployment is considered completed.
        state.current_phase = DeploymentPhase.COMPLETED
    except DeploymentException as e:
        # Catch specific deployment-related exceptions
        logging.error(f"Deployment failed at phase '{state.current_phase.value}': {e}")
        state.error_message = str(e)
        state.current_phase = DeploymentPhase.FAILED
        if state.rollback_needed:
            logging.info("Attempting to rollback due to detected issues or user cancellation.")
            rollback_deployment(state)
        else:
            logging.error("Deployment failed, but rollback was not specifically requested or applicable in this state.")
            logging.error("Manual intervention may be required to resolve the issue and/or clean up resources.")
    except KeyboardInterrupt:
        # Handle user interruption (Ctrl+C)
        logging.warning("Deployment interrupted by user (Ctrl+C). Attempting to rollback...")
        state.error_message = "Deployment interrupted by user."
        state.rollback_needed = True # Force rollback on user interrupt
        rollback_deployment(state)
    except Exception as e:
        # Catch any other unexpected critical errors
        logging.critical(f"An unexpected critical error occurred during deployment: {e}", exc_info=True)
        state.error_message = str(e)
        state.current_phase = DeploymentPhase.FAILED
        logging.error("Due to an unexpected critical error, automatic rollback cannot be guaranteed. Manual intervention is HIGHLY recommended to inspect and potentially clean up resources.")
    finally:
        # Ensure finalization tasks are always run, regardless of success or failure
        finalize_deployment(state)


# --- Entry Point ---
if __name__ == "__main__":
    # To run this script non-interactively (e.g., in CI/CD pipelines),
    # set the environment variable BLUE_GREEN_NON_INTERACTIVE to 'true':
    #
    #   BLUE_GREEN_NON_INTERACTIVE=true python blue_green_deployment_orchestrator.py
    #
    orchestrate_blue_green_deployment(CONFIG)