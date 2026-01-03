import os
import time
import json
import logging
import datetime
import enum
import sys
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Union

# This script uses the 'requests' library for making HTTP requests to the GitHub API.
# It is a common and robust library for this purpose.
# You can install it using: pip install requests
import requests

# --- Configuration Classes ---

@dataclass
class GitHubConfig:
    """
    Configuration for GitHub API access.
    """
    api_url: str = "https://api.github.com"
    token: str = field(repr=False)  # Keep token out of default __repr__
    owner: str = ""  # GitHub organization or user name
    repo: str = ""   # GitHub repository name (if managing repo-specific runners)
    runner_labels: List[str] = field(default_factory=list) # Labels to assign to new runners
    runner_group: Optional[str] = None # Runner group name (if using groups)
    scope: str = "org" # 'org' for organization runners, 'repo' for repository runners

    def __post_init__(self):
        if not self.token:
            raise ValueError("GitHub personal access token must be provided.")
        if self.scope not in ["org", "repo"]:
            raise ValueError("Scope must be 'org' or 'repo'.")
        if self.scope == "org" and not self.owner:
            raise ValueError("Owner must be specified for organization runners.")
        if self.scope == "repo" and (not self.owner or not self.repo):
            raise ValueError("Owner and Repo must be specified for repository runners.")

@dataclass
class ScalingConfig:
    """
    Configuration for the scaling logic.
    """
    min_runners: int = 0
    max_runners: int = 5
    target_queue_depth_per_runner: int = 1 # How many pending jobs an idle runner can handle
    scale_up_cooldown_seconds: int = 300  # 5 minutes
    scale_down_cooldown_seconds: int = 600 # 10 minutes
    check_interval_seconds: int = 60    # How often to check the queue and scale
    runner_startup_time_seconds: int = 120 # Estimated time for a runner to become online
    max_runner_lifetime_hours: Optional[int] = 24 # Terminate runners after N hours to refresh

    def __post_init__(self):
        if self.min_runners < 0:
            raise ValueError("min_runners cannot be negative.")
        if self.max_runners < self.min_runners:
            raise ValueError("max_runners cannot be less than min_runners.")
        if self.target_queue_depth_per_runner <= 0:
            raise ValueError("target_queue_depth_per_runner must be positive.")
        if self.scale_up_cooldown_seconds < 0 or self.scale_down_cooldown_seconds < 0:
            raise ValueError("Cooldown periods cannot be negative.")
        if self.check_interval_seconds <= 0:
            raise ValueError("Check interval must be positive.")

@dataclass
class CloudConfig:
    """
    Configuration for the cloud provider where runners are hosted.
    This example uses a simulated cloud, but in a real scenario,
    this would hold API keys, region, instance types, etc.
    """
    instance_prefix: str = "github-runner-"
    runner_template_id: str = "ubuntu-22.04-medium" # A placeholder for a VM/container image
    # Add other cloud-specific config here, e.g., instance_type, security_groups, region etc.

# --- Logging Setup ---

class LogConfig:
    """
    Manages logging configuration.
    """
    @staticmethod
    def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None):
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        logging.basicConfig(level=log_level, format=log_format, handlers=[
            logging.StreamHandler(sys.stdout)
        ])
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(logging.Formatter(log_format))
            logging.getLogger().addHandler(file_handler)

        # Set specific log levels for third-party libraries if they are too noisy
        logging.getLogger("requests").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)

# Initialize logger
LogConfig.setup_logging()
logger = logging.getLogger("RunnerManager")

# --- Enums and Utility Functions ---

class RunnerStatus(enum.Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    BUSY = "busy"
    IDLE = "idle"
    UNKNOWN = "unknown"

@dataclass
class ManagedRunner:
    """Represents a runner instance managed by this tool."""
    name: str
    instance_id: str # Unique ID from the cloud provider
    github_runner_id: Optional[int] = None # GitHub's internal ID for the runner
    status: RunnerStatus = RunnerStatus.UNKNOWN
    busy: Optional[bool] = None
    last_status_check: datetime.datetime = field(default_factory=datetime.datetime.now)
    registration_time: datetime.datetime = field(default_factory=datetime.datetime.now)
    last_scaled_up_time: Optional[datetime.datetime] = None
    labels: List[str] = field(default_factory=list)

    def is_available(self) -> bool:
        return self.status == RunnerStatus.ONLINE and not self.busy

    def is_fresh(self, max_lifetime: Optional[int]) -> bool:
        if max_lifetime is None:
            return True
        return (datetime.datetime.now() - self.registration_time).total_seconds() < max_lifetime * 3600

def parse_iso_datetime(iso_string: str) -> datetime.datetime:
    """Parses an ISO 8601 datetime string from GitHub API."""
    # GitHub API might return fractional seconds or Z for UTC
    if iso_string.endswith('Z'):
        iso_string = iso_string[:-1] + '+00:00'
    return datetime.datetime.fromisoformat(iso_string)

# --- GitHub API Client ---

class GitHubClient:
    """
    Handles all interactions with the GitHub API.
    """
    def __init__(self, config: GitHubConfig):
        self.config = config
        self.headers = {
            "Authorization": f"token {self.config.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        logger.info(f"Initialized GitHubClient for {self.config.scope} '{self.config.owner}'"
                    + (f"/'{self.config.repo}'" if self.config.scope == 'repo' else ""))

    def _make_request(self, method: str, path: str, **kwargs) -> Dict[str, Any]:
        url = f"{self.config.api_url}{path}"
        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            logger.error(f"GitHub API Error [{method} {url}]: {e.response.status_code} - {e.response.text}")
            raise
        except requests.exceptions.RequestException as e:
            logger.error(f"GitHub API Connection Error [{method} {url}]: {e}")
            raise

    def get_runner_registration_token(self) -> str:
        """
        Retrieves a registration token for a new runner.
        """
        if self.config.scope == "org":
            path = f"/orgs/{self.config.owner}/actions/runners/registration-token"
        else: # scope == "repo"
            path = f"/repos/{self.config.owner}/{self.config.repo}/actions/runners/registration-token"

        logger.debug(f"Requesting runner registration token from {path}")
        data = self._make_request("POST", path)
        return data["token"]

    def list_runners(self) -> List[Dict[str, Any]]:
        """
        Lists all self-hosted runners registered with GitHub for the configured scope.
        """
        if self.config.scope == "org":
            path = f"/orgs/{self.config.owner}/actions/runners"
        else: # scope == "repo"
            path = f"/repos/{self.config.owner}/{self.config.repo}/actions/runners"

        logger.debug(f"Listing runners from {path}")
        runners_data = []
        page = 1
        while True:
            response = self._make_request("GET", path, params={"per_page": 100, "page": page})
            runners = response.get("runners", [])
            runners_data.extend(runners)
            if len(runners) < 100:
                break
            page += 1
        return runners_data

    def get_runner(self, runner_id: int) -> Optional[Dict[str, Any]]:
        """
        Retrieves details for a specific runner by its GitHub ID.
        """
        if self.config.scope == "org":
            path = f"/orgs/{self.config.owner}/actions/runners/{runner_id}"
        else: # scope == "repo"
            path = f"/repos/{self.config.owner}/{self.config.repo}/actions/runners/{runner_id}"
        
        try:
            return self._make_request("GET", path)
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                logger.warning(f"Runner with ID {runner_id} not found on GitHub.")
                return None
            raise

    def delete_runner(self, runner_id: int) -> bool:
        """
        Deletes a runner from GitHub's registration.
        """
        if self.config.scope == "org":
            path = f"/orgs/{self.config.owner}/actions/runners/{runner_id}"
        else: # scope == "repo"
            path = f"/repos/{self.config.owner}/{self.config.repo}/actions/runners/{runner_id}"

        logger.info(f"Deleting runner with ID {runner_id} from GitHub.")
        try:
            self._make_request("DELETE", path)
            logger.info(f"Successfully deleted runner ID {runner_id} from GitHub.")
            return True
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                logger.warning(f"Attempted to delete runner ID {runner_id} but it was not found on GitHub.")
                return False
            logger.error(f"Failed to delete runner ID {runner_id} from GitHub: {e}")
            return False

    def list_pending_workflow_runs(self) -> List[Dict[str, Any]]:
        """
        Lists pending workflow runs (jobs that are waiting for a runner).
        This is a more complex query as GitHub API does not have a direct
        "list pending jobs" endpoint. We approximate this by listing all
        workflow runs and filtering for 'queued' or 'waiting' jobs.
        This approach might be limited by the API's pagination and rate limits,
        and might not capture all pending jobs if there's a huge backlog.
        A more robust solution might involve GitHub webhooks or checking
        individual workflow run details, but that's beyond this initial scope.
        """
        if self.config.scope == "org":
             # For org-level, we would ideally list all repos and then their runs.
             # This is complex and rate-limited. For simplicity, we assume the jobs
             # are for a specific repo, or we'd need a list of repos to check.
             # This example will focus on a single repo if scope is org for simplicity.
            repo_path = f"/repos/{self.config.owner}/{self.config.repo}"
        else: # scope == "repo"
            repo_path = f"/repos/{self.config.owner}/{self.config.repo}"

        path = f"{repo_path}/actions/runs"
        
        logger.debug(f"Listing workflow runs for pending jobs from {path}")
        all_runs = []
        page = 1
        # Fetching all workflow runs can be expensive and hit rate limits.
        # We limit to a few pages to get recent pending jobs.
        max_pages_to_check = 5 # Adjust based on expected queue size
        while page <= max_pages_to_check:
            try:
                # Fetching only 'created' or 'queued' status is not directly supported by API.
                # We fetch all and filter. State 'queued' or 'waiting' are usually for jobs.
                # Workflow 'status' can be 'queued', 'in_progress', 'completed'.
                # Jobs within a run can have 'queued', 'in_progress', 'completed', 'waiting'.
                # We'll fetch workflow runs that are 'queued' or 'in_progress' and assume
                # jobs within them might be pending.
                response = self._make_request("GET", path, params={"per_page": 100, "page": page, "status": "queued"})
                runs_page = response.get("workflow_runs", [])
                
                # Also check 'in_progress' runs for jobs that might be waiting
                response_in_progress = self._make_request("GET", path, params={"per_page": 100, "page": page, "status": "in_progress"})
                runs_in_progress_page = response_in_progress.get("workflow_runs", [])

                current_page_runs = runs_page + runs_in_progress_page
                
                if not current_page_runs:
                    break
                all_runs.extend(current_page_runs)
                if len(runs_page) < 100 and len(runs_in_progress_page) < 100:
                    break
                page += 1
            except Exception as e:
                logger.warning(f"Could not retrieve workflow runs page {page}: {e}. Stopping pagination.")
                break

        pending_jobs_count = 0
        for run in all_runs:
            # For each workflow run, we need to fetch its jobs to determine actual pending jobs.
            # This is even more API intensive. To simplify, we'll assume each 'queued' workflow
            # run means at least one job, or check the 'in_progress' runs' jobs.
            jobs_path = f"{repo_path}/actions/runs/{run['id']}/jobs"
            try:
                jobs_response = self._make_request("GET", jobs_path)
                for job in jobs_response.get("jobs", []):
                    # Job status can be 'queued', 'in_progress', 'completed', 'waiting'
                    if job["status"] in ["queued", "waiting", "pending"]:
                        # Also check if the job requires specific labels that our runners provide
                        # This check is crucial for accurate scaling.
                        runner_groups = job.get("runner_group_name", [])
                        job_labels = job.get("labels", [])
                        
                        is_target_runner_group = (
                            not self.config.runner_group
                            or self.config.runner_group in runner_groups
                        )
                        
                        # Check if all required labels for the job are provided by our runners
                        is_matching_labels = all(
                            label in self.config.runner_labels for label in job_labels
                        )

                        if is_target_runner_group and is_matching_labels:
                            pending_jobs_count += 1
                            logger.debug(f"Found pending job: {job['name']} (ID: {job['id']}) in run {run['id']}")
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 404:
                    logger.debug(f"Jobs for workflow run {run['id']} not found, possibly already completed or removed.")
                else:
                    logger.warning(f"Failed to fetch jobs for workflow run {run['id']}: {e}")
            except Exception as e:
                logger.warning(f"Error processing jobs for workflow run {run['id']}: {e}")

        logger.info(f"Detected {pending_jobs_count} pending jobs matching specified labels and group.")
        return [{'id': i} for i in range(pending_jobs_count)] # Return a dummy list of pending jobs for count

# --- Runner Instance Manager (Simulated Cloud Provider) ---

class RunnerInstanceManager:
    """
    Simulates interaction with a cloud provider to manage runner instances.
    In a real implementation, this would use AWS SDK (boto3), Azure SDK, Docker API, etc.
    """
    def __init__(self, config: CloudConfig):
        self.config = config
        self.active_instances: Dict[str, ManagedRunner] = {} # instance_id -> ManagedRunner
        self._next_instance_id = 1
        logger.info(f"Initialized RunnerInstanceManager with instance prefix '{self.config.instance_prefix}'")

    def _generate_instance_id(self) -> str:
        instance_id = f"i-{self._next_instance_id:04d}"
        self._next_instance_id += 1
        return instance_id

    def create_runner_instance(self, runner_name: str, runner_token: str, labels: List[str], runner_group: Optional[str]) -> ManagedRunner:
        """
        Simulates creating a new runner instance (VM/Container).
        In a real scenario, this would provision a resource and pass the token/labels.
        """
        instance_id = self._generate_instance_id()
        logger.info(f"Simulating creation of new runner instance '{runner_name}' (ID: {instance_id}). Template: {self.config.runner_template_id}")
        logger.debug(f"Runner '{runner_name}' will be started with token (hidden) and labels: {labels} and group: {runner_group}")
        
        # In a real scenario:
        # 1. Call cloud provider API to launch a VM/container
        # 2. Pass runner_token, labels, runner_group to the instance (e.g., via user-data script or env vars)
        # 3. Store the cloud provider's instance ID
        
        managed_runner = ManagedRunner(
            name=runner_name,
            instance_id=instance_id,
            last_scaled_up_time=datetime.datetime.now(),
            labels=labels
        )
        self.active_instances[instance_id] = managed_runner
        logger.info(f"Simulated runner instance '{runner_name}' created successfully with instance ID '{instance_id}'.")
        return managed_runner

    def terminate_runner_instance(self, instance_id: str) -> bool:
        """
        Simulates terminating a runner instance.
        """
        if instance_id not in self.active_instances:
            logger.warning(f"Attempted to terminate non-existent instance ID '{instance_id}'.")
            return False

        runner_name = self.active_instances[instance_id].name
        logger.info(f"Simulating termination of runner instance '{runner_name}' (ID: {instance_id}).")
        
        # In a real scenario:
        # 1. Call cloud provider API to terminate the VM/container
        
        del self.active_instances[instance_id]
        logger.info(f"Simulated runner instance '{runner_name}' (ID: {instance_id}) terminated successfully.")
        return True

    def list_active_runner_instances(self) -> List[ManagedRunner]:
        """
        Returns a list of all runner instances currently managed by this manager.
        In a real scenario, this might query the cloud provider for instances
        matching a specific tag or naming convention.
        """
        logger.debug(f"Listing {len(self.active_instances)} currently managed runner instances.")
        # For simulation, we just return our internal list
        return list(self.active_instances.values())

    def get_instance_status(self, instance_id: str) -> Dict[str, Any]:
        """
        Simulates getting the detailed status of a cloud instance.
        In a real system, this would query the cloud provider.
        """
        if instance_id in self.active_instances:
            # Simulate a VM being online
            return {"status": "running", "uptime_seconds": (datetime.datetime.now() - self.active_instances[instance_id].registration_time).total_seconds()}
        return {"status": "terminated"}

# --- Main Runner Manager Logic ---

class GitHubRunnerManager:
    """
    Orchestrates the scaling of GitHub self-hosted runners.
    """
    def __init__(
        self,
        github_config: GitHubConfig,
        scaling_config: ScalingConfig,
        cloud_config: CloudConfig
    ):
        self.github_client = GitHubClient(github_config)
        self.runner_instance_manager = RunnerInstanceManager(cloud_config)
        self.scaling_config = scaling_config
        self.github_config = github_config
        self.cloud_config = cloud_config

        self.last_scale_up_time: Optional[datetime.datetime] = None
        self.last_scale_down_time: Optional[datetime.datetime] = None
        
        logger.info("GitHubRunnerManager initialized.")
        self._initialize_managed_runners()

    def _initialize_managed_runners(self):
        """
        On startup, try to reconcile any existing runners managed by our naming convention
        with GitHub's registered runners.
        """
        logger.info("Initializing managed runners by reconciling with GitHub and cloud provider...")
        gh_registered_runners = {r["name"]: r for r in self.github_client.list_runners()}
        cloud_managed_instances = self.runner_instance_manager.list_active_runner_instances()

        for cloud_runner in cloud_managed_instances:
            if cloud_runner.name in gh_registered_runners:
                gh_data = gh_registered_runners[cloud_runner.name]
                cloud_runner.github_runner_id = gh_data['id']
                cloud_runner.status = RunnerStatus.ONLINE if gh_data['status'] == 'online' else RunnerStatus.OFFLINE
                cloud_runner.busy = gh_data['busy']
                cloud_runner.registration_time = parse_iso_datetime(gh_data['created_at'])
                logger.info(f"Reconciled existing runner '{cloud_runner.name}' (Instance ID: {cloud_runner.instance_id}) "
                            f"with GitHub ID {cloud_runner.github_runner_id}. Status: {cloud_runner.status.value}, Busy: {cloud_runner.busy}")
            else:
                logger.warning(f"Cloud instance '{cloud_runner.name}' (ID: {cloud_runner.instance_id}) exists "
                               f"but is not registered with GitHub. It might be a zombie or still starting up.")
                # We'll let the reconciliation logic handle potential cleanup if it never registers

    def _get_current_runner_state(self) -> Dict[str, ManagedRunner]:
        """
        Gathers and updates the state of all active runners from both the
        cloud provider (simulated) and GitHub.
        Returns a dictionary of runner_name -> ManagedRunner.
        """
        logger.debug("Collecting current runner state from GitHub and cloud provider.")
        github_runners_data = self.github_client.list_runners()
        cloud_instances = self.runner_instance_manager.list_active_runner_instances()

        # Map by instance ID for easier lookup in reconciliation
        cloud_instances_map = {inst.instance_id: inst for inst in cloud_instances}
        
        # Populate current state with GitHub data
        current_managed_runners: Dict[str, ManagedRunner] = {}
        for gh_runner in github_runners_data:
            runner_name = gh_runner["name"]
            
            # Filter for runners managed by this system (based on naming prefix)
            if not runner_name.startswith(self.cloud_config.instance_prefix):
                logger.debug(f"Skipping GitHub runner '{runner_name}' as it does not match our instance prefix.")
                continue

            # Check if this GitHub runner corresponds to an instance we are tracking
            found_cloud_instance: Optional[ManagedRunner] = None
            for instance_id, managed_runner in cloud_instances_map.items():
                if managed_runner.name == runner_name:
                    found_cloud_instance = managed_runner
                    break

            if found_cloud_instance:
                # Update the ManagedRunner object with GitHub data
                found_cloud_instance.github_runner_id = gh_runner["id"]
                found_cloud_instance.status = RunnerStatus.ONLINE if gh_runner["status"] == "online" else RunnerStatus.OFFLINE
                found_cloud_instance.busy = gh_runner["busy"]
                found_cloud_instance.last_status_check = datetime.datetime.now()
                # If registration_time wasn't set from init, set it now
                if found_cloud_instance.registration_time.year < 2000: # Heuristic for default datetime
                     found_cloud_instance.registration_time = parse_iso_datetime(gh_runner['created_at'])
                found_cloud_instance.labels = gh_runner.get('labels', []) # Update labels if they change
                current_managed_runners[runner_name] = found_cloud_instance
                del cloud_instances_map[found_cloud_instance.instance_id] # Mark as processed
            else:
                # GitHub runner exists, but no corresponding cloud instance we track. This is a zombie.
                logger.warning(f"GitHub runner '{runner_name}' (ID: {gh_runner['id']}) exists but no "
                               f"corresponding cloud instance is managed by this tool. Marking for potential cleanup.")
                # Create a temporary ManagedRunner to track this zombie
                current_managed_runners[runner_name] = ManagedRunner(
                    name=runner_name,
                    instance_id="unknown_cloud_id", # Placeholder
                    github_runner_id=gh_runner["id"],
                    status=RunnerStatus.OFFLINE, # Assume offline if no backing instance
                    busy=False,
                    registration_time=parse_iso_datetime(gh_runner['created_at']),
                    labels=gh_runner.get('labels', [])
                )

        # Any remaining items in cloud_instances_map are instances we manage but are not registered on GitHub
        for instance_id, cloud_runner in cloud_instances_map.items():
            # If the instance just started, it might not be registered yet. Give it some time.
            if (datetime.datetime.now() - cloud_runner.last_scaled_up_time).total_seconds() < self.scaling_config.runner_startup_time_seconds:
                logger.info(f"Cloud instance '{cloud_runner.name}' (ID: {cloud_runner.instance_id}) is "
                            f"running but not yet registered with GitHub. Still within startup grace period.")
                current_managed_runners[cloud_runner.name] = cloud_runner
            else:
                logger.warning(f"Cloud instance '{cloud_runner.name}' (ID: {cloud_runner.instance_id}) is "
                               f"active but has not registered with GitHub after startup time. Marking for cleanup.")
                # This runner should be terminated and its registration token is likely invalid.
                # It will be caught by _reconcile_runners() later.
                current_managed_runners[cloud_runner.name] = cloud_runner # Add it so reconciliation can find it

        return current_managed_runners

    def _determine_scaling_action(self, current_runners: Dict[str, ManagedRunner], pending_jobs_count: int) -> int:
        """
        Decides whether to scale up, scale down, or do nothing.
        Returns the number of runners to add (positive) or remove (negative).
        """
        num_current_runners = len(current_runners)
        num_online_runners = sum(1 for r in current_runners.values() if r.status == RunnerStatus.ONLINE)
        num_idle_runners = sum(1 for r in current_runners.values() if r.is_available())
        
        logger.info(f"Current state: {num_current_runners} total runners managed, {num_online_runners} online, "
                    f"{num_idle_runners} idle. {pending_jobs_count} pending jobs.")

        # Check for scale-up conditions
        required_runners = (pending_jobs_count + self.scaling_config.target_queue_depth_per_runner - 1) // self.scaling_config.target_queue_depth_per_runner
        required_runners = max(required_runners, self.scaling_config.min_runners)

        runners_to_add = required_runners - num_online_runners

        if runners_to_add > 0:
            if num_current_runners >= self.scaling_config.max_runners:
                logger.warning(f"Cannot scale up: Already at max_runners ({self.scaling_config.max_runners}).")
                return 0

            # Apply scale-up cooldown
            if self.last_scale_up_time and \
               (datetime.datetime.now() - self.last_scale_up_time).total_seconds() < self.scaling_config.scale_up_cooldown_seconds:
                logger.info(f"Scale-up cooldown active. Last scale-up was "
                            f"{(datetime.datetime.now() - self.last_scale_up_time).total_seconds():.0f} seconds ago. Waiting.")
                return 0

            # Don't add more than remaining capacity to max_runners
            runners_to_add = min(runners_to_add, self.scaling_config.max_runners - num_current_runners)
            logger.info(f"Scaling UP: Need {runners_to_add} more runners. {pending_jobs_count} pending jobs, {num_online_runners} online runners.")
            return runners_to_add

        # Check for scale-down conditions
        # Only consider scaling down if there are idle runners and we are above min_runners
        if num_idle_runners > 0 and num_current_runners > self.scaling_config.min_runners:
            # Apply scale-down cooldown
            if self.last_scale_down_time and \
               (datetime.datetime.now() - self.last_scale_down_time).total_seconds() < self.scaling_config.scale_down_cooldown_seconds:
                logger.info(f"Scale-down cooldown active. Last scale-down was "
                            f"{(datetime.datetime.now() - self.last_scale_down_time).total_seconds():.0f} seconds ago. Waiting.")
                return 0
            
            # Determine how many idle runners we can safely remove
            # Target is `required_runners` (based on pending jobs), but don't go below min_runners
            num_runners_to_maintain = max(required_runners, self.scaling_config.min_runners)
            runners_to_remove = num_current_runners - num_runners_to_maintain

            if runners_to_remove > 0:
                # Prioritize removing stale or oldest idle runners
                idle_runners_available_for_termination = [
                    r for r in current_runners.values()
                    if r.is_available() and r.is_fresh(self.scaling_config.max_runner_lifetime_hours)
                ]
                stale_runners_for_termination = [
                    r for r in current_runners.values()
                    if r.status == RunnerStatus.ONLINE and not r.is_fresh(self.scaling_config.max_runner_lifetime_hours)
                ]

                # Max lifetime termination takes precedence
                if len(stale_runners_for_termination) > 0:
                    logger.info(f"Scaling DOWN (max lifetime): {len(stale_runners_for_termination)} runners exceeded max lifetime.")
                    return -len(stale_runners_for_termination)

                # Otherwise, terminate based on idle capacity
                # Don't try to remove more than we actually have idle
                runners_to_remove = min(runners_to_remove, num_idle_runners)
                logger.info(f"Scaling DOWN: Can remove up to {runners_to_remove} idle runners to meet target capacity.")
                return -runners_to_remove

        logger.info("No scaling action required at this time.")
        return 0

    def _execute_scaling_action(self, action_count: int, current_runners: Dict[str, ManagedRunner]):
        """
        Executes the scaling action (creating or terminating runners).
        """
        if action_count > 0:
            logger.info(f"Executing scale-up: creating {action_count} new runners.")
            for i in range(action_count):
                runner_token = self.github_client.get_runner_registration_token()
                runner_name = f"{self.cloud_config.instance_prefix}{int(time.time() * 1000)}{i}" # Unique name
                try:
                    self.runner_instance_manager.create_runner_instance(
                        runner_name,
                        runner_token,
                        self.github_config.runner_labels,
                        self.github_config.runner_group
                    )
                    self.last_scale_up_time = datetime.datetime.now()
                except Exception as e:
                    logger.error(f"Failed to create runner instance '{runner_name}': {e}")
            logger.info(f"Finished attempting to create {action_count} runners.")

        elif action_count < 0:
            num_to_remove = abs(action_count)
            logger.info(f"Executing scale-down: terminating {num_to_remove} runners.")

            # Prioritize runners that have exceeded their max lifetime or are oldest idle
            runners_for_termination = []

            # First, add stale runners (exceeded max lifetime)
            stale_runners = sorted([
                r for r in current_runners.values()
                if r.status == RunnerStatus.ONLINE and not r.is_fresh(self.scaling_config.max_runner_lifetime_hours)
            ], key=lambda x: x.registration_time) # Oldest first
            runners_for_termination.extend(stale_runners)

            # Then, add oldest idle runners if more are needed
            idle_runners = sorted([
                r for r in current_runners.values()
                if r.is_available() and r.is_fresh(self.scaling_config.max_runner_lifetime_hours)
            ], key=lambda x: x.last_status_check) # Longest idle first
            
            for runner in idle_runners:
                if len(runners_for_termination) < num_to_remove:
                    runners_for_termination.append(runner)
                else:
                    break
            
            for runner_to_terminate in runners_for_termination[:num_to_remove]:
                try:
                    # Attempt to remove from GitHub first
                    if runner_to_terminate.github_runner_id:
                        self.github_client.delete_runner(runner_to_terminate.github_runner_id)
                    else:
                        logger.warning(f"Runner '{runner_to_terminate.name}' (Instance ID: {runner_to_terminate.instance_id}) "
                                       f"has no GitHub ID. Skipping GitHub deletion.")
                    
                    # Then terminate the cloud instance
                    self.runner_instance_manager.terminate_runner_instance(runner_to_terminate.instance_id)
                    self.last_scale_down_time = datetime.datetime.now()
                except Exception as e:
                    logger.error(f"Failed to terminate runner '{runner_to_terminate.name}' (ID: {runner_to_terminate.instance_id}): {e}")
            logger.info(f"Finished attempting to terminate {num_to_remove} runners.")

    def _reconcile_runners(self, current_managed_runners: Dict[str, ManagedRunner]):
        """
        Performs cleanup and reconciliation:
        1. Identifies "zombie" GitHub runners (registered on GitHub but backing instance is gone).
        2. Identifies "phantom" cloud instances (running but failed to register with GitHub after grace period).
        """
        logger.info("Starting runner reconciliation process...")
        
        # Get actual instances from the manager
        actual_cloud_instances_map = {r.instance_id: r for r in self.runner_instance_manager.list_active_runner_instances()}

        for runner_name, managed_runner in list(current_managed_runners.items()): # Iterate over a copy
            is_cloud_instance_active = managed_runner.instance_id in actual_cloud_instances_map
            
            # Case 1: GitHub runner exists, but its cloud instance is gone or unknown. (ZOMBIE)
            if managed_runner.github_runner_id and not is_cloud_instance_active:
                logger.warning(f"Detected ZOMBIE GitHub runner: '{runner_name}' (GitHub ID: {managed_runner.github_runner_id}). "
                               f"Its backing cloud instance (ID: {managed_runner.instance_id}) is not active.")
                try:
                    self.github_client.delete_runner(managed_runner.github_runner_id)
                    logger.info(f"Successfully deleted ZOMBIE runner '{runner_name}' from GitHub.")
                except Exception as e:
                    logger.error(f"Failed to delete ZOMBIE runner '{runner_name}' from GitHub: {e}")
                # Remove from current_managed_runners if it was a zombie
                if runner_name in current_managed_runners:
                    del current_managed_runners[runner_name]
                continue

            # Case 2: Cloud instance is active, but runner failed to register with GitHub within startup time. (PHANTOM)
            if is_cloud_instance_active and not managed_runner.github_runner_id:
                # Check if it's past the startup grace period
                if (datetime.datetime.now() - managed_runner.last_scaled_up_time).total_seconds() > self.scaling_config.runner_startup_time_seconds:
                    logger.warning(f"Detected PHANTOM cloud instance: '{runner_name}' (Instance ID: {managed_runner.instance_id}). "
                                   f"It is active but never registered with GitHub after startup grace period.")
                    try:
                        self.runner_instance_manager.terminate_runner_instance(managed_runner.instance_id)
                        logger.info(f"Successfully terminated PHANTOM instance '{runner_name}'.")
                    except Exception as e:
                        logger.error(f"Failed to terminate PHANTOM instance '{runner_name}': {e}")
                    # Remove from current_managed_runners as it's being terminated
                    if runner_name in current_managed_runners:
                        del current_managed_runners[runner_name]
                    continue
                else:
                    logger.debug(f"Instance '{runner_name}' still in startup grace period, waiting for registration.")
            
            # Case 3: Runners that have gone offline for too long or are stuck
            if managed_runner.github_runner_id and managed_runner.status == RunnerStatus.OFFLINE:
                # You might want to define a threshold for 'offline duration' before terminating
                offline_duration = (datetime.datetime.now() - managed_runner.last_status_check).total_seconds()
                offline_threshold = self.scaling_config.check_interval_seconds * 3 # e.g., 3 check intervals
                if offline_duration > offline_threshold:
                    logger.warning(f"Runner '{runner_name}' (ID: {managed_runner.github_runner_id}) has been OFFLINE "
                                   f"for {offline_duration:.0f} seconds. Considering for termination.")
                    # Only terminate if we manage the underlying instance
                    if is_cloud_instance_active:
                        try:
                            self.github_client.delete_runner(managed_runner.github_runner_id)
                            self.runner_instance_manager.terminate_runner_instance(managed_runner.instance_id)
                            logger.info(f"Terminated offline runner '{runner_name}' from GitHub and cloud provider.")
                            if runner_name in current_managed_runners:
                                del current_managed_runners[runner_name]
                        except Exception as e:
                            logger.error(f"Failed to terminate long-offline runner '{runner_name}': {e}")

        logger.info("Runner reconciliation completed.")


    def run_once(self):
        """
        Executes a single cycle of the runner management logic.
        """
        logger.info("-" * 50)
        logger.info(f"Starting runner management cycle at {datetime.datetime.now()}")
        try:
            current_runners = self._get_current_runner_state()
            self._reconcile_runners(current_runners) # Perform cleanup before scaling decisions

            # Re-fetch current_runners after reconciliation, as some might have been removed
            current_runners = self._get_current_runner_state()
            
            pending_jobs = self.github_client.list_pending_workflow_runs()
            pending_jobs_count = len(pending_jobs)

            scaling_action = self._determine_scaling_action(current_runners, pending_jobs_count)
            self._execute_scaling_action(scaling_action, current_runners)

        except Exception as e:
            logger.critical(f"An unhandled error occurred during the management cycle: {e}", exc_info=True)
        finally:
            logger.info(f"Runner management cycle finished.")
            logger.info("-" * 50)

    def run_forever(self):
        """
        Continuously runs the runner management logic at a defined interval.
        """
        logger.info("Starting GitHub Actions Runner Manager in continuous mode...")
        while True:
            self.run_once()
            logger.info(f"Sleeping for {self.scaling_config.check_interval_seconds} seconds...")
            time.sleep(self.scaling_config.check_interval_seconds)

# --- Main Execution Block ---

def load_config_from_env() -> tuple[GitHubConfig, ScalingConfig, CloudConfig]:
    """
    Loads configuration from environment variables.
    """
    logger.info("Loading configuration from environment variables.")

    github_token = os.getenv("GITHUB_TOKEN")
    if not github_token:
        logger.error("GITHUB_TOKEN environment variable is not set. Exiting.")
        sys.exit(1)

    github_owner = os.getenv("GITHUB_OWNER", "")
    github_repo = os.getenv("GITHUB_REPO", "")
    github_scope = os.getenv("GITHUB_SCOPE", "org").lower()
    github_runner_labels_str = os.getenv("GITHUB_RUNNER_LABELS", "self-hosted,linux,x64")
    github_runner_labels = [label.strip() for label in github_runner_labels_str.split(',') if label.strip()]
    github_runner_group = os.getenv("GITHUB_RUNNER_GROUP")

    if github_scope == "org" and not github_owner:
        logger.error("For organization scope, GITHUB_OWNER must be set. Exiting.")
        sys.exit(1)
    if github_scope == "repo" and (not github_owner or not github_repo):
        logger.error("For repository scope, both GITHUB_OWNER and GITHUB_REPO must be set. Exiting.")
        sys.exit(1)

    gh_config = GitHubConfig(
        token=github_token,
        owner=github_owner,
        repo=github_repo,
        scope=github_scope,
        runner_labels=github_runner_labels,
        runner_group=github_runner_group
    )

    scaling_config = ScalingConfig(
        min_runners=int(os.getenv("SCALING_MIN_RUNNERS", "0")),
        max_runners=int(os.getenv("SCALING_MAX_RUNNERS", "5")),
        target_queue_depth_per_runner=int(os.getenv("SCALING_TARGET_QUEUE_DEPTH_PER_RUNNER", "1")),
        scale_up_cooldown_seconds=int(os.getenv("SCALING_SCALE_UP_COOLDOWN_SECONDS", "300")),
        scale_down_cooldown_seconds=int(os.getenv("SCALING_SCALE_DOWN_COOLDOWN_SECONDS", "600")),
        check_interval_seconds=int(os.getenv("SCALING_CHECK_INTERVAL_SECONDS", "60")),
        runner_startup_time_seconds=int(os.getenv("SCALING_RUNNER_STARTUP_TIME_SECONDS", "120")),
        max_runner_lifetime_hours=int(os.getenv("SCALING_MAX_RUNNER_LIFETIME_HOURS", "24"))
    )

    cloud_config = CloudConfig(
        instance_prefix=os.getenv("CLOUD_INSTANCE_PREFIX", "github-runner-"),
        runner_template_id=os.getenv("CLOUD_RUNNER_TEMPLATE_ID", "ubuntu-22.04-medium")
    )

    log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    log_file = os.getenv("LOG_FILE")
    LogConfig.setup_logging(log_level, log_file)

    logger.info("Configuration loaded successfully.")
    logger.debug(f"GitHub Config: {gh_config}")
    logger.debug(f"Scaling Config: {scaling_config}")
    logger.debug(f"Cloud Config: {cloud_config}")

    return gh_config, scaling_config, cloud_config

if __name__ == "__main__":
    # Example environment variables to set:
    # export GITHUB_TOKEN="ghp_YOUR_PERSONAL_ACCESS_TOKEN"
    # export GITHUB_OWNER="your-org-or-username"
    # export GITHUB_REPO="your-repo-name" # Only if GITHUB_SCOPE is 'repo'
    # export GITHUB_SCOPE="org" # or 'repo'
    # export GITHUB_RUNNER_LABELS="my-custom-label,gpu,high-mem"
    # export GITHUB_RUNNER_GROUP="my-runner-group"
    # export SCALING_MIN_RUNNERS="1"
    # export SCALING_MAX_RUNNERS="10"
    # export SCALING_TARGET_QUEUE_DEPTH_PER_RUNNER="2"
    # export SCALING_CHECK_INTERVAL_SECONDS="30"
    # export LOG_LEVEL="DEBUG" # or INFO, WARNING, ERROR, CRITICAL
    # export LOG_FILE="/var/log/github-runner-manager.log"

    try:
        github_cfg, scaling_cfg, cloud_cfg = load_config_from_env()
        manager = GitHubRunnerManager(github_cfg, scaling_cfg, cloud_cfg)
        manager.run_forever()
    except Exception as main_exception:
        logger.critical(f"GitHub Actions Runner Manager failed to start or encountered a critical error: {main_exception}", exc_info=True)
        sys.exit(1)