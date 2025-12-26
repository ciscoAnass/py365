import os
import hmac
import hashlib
import json
import logging
import sys
import threading
import time
from datetime import datetime, timezone

# --- Third-party libraries (REQUIRED) ---
# Flask: Web framework to receive GitHub webhook events.
#   Installation: pip install Flask
# PyGithub: Python library for the GitHub API.
#   Installation: pip install PyGithub
#
# Ensure these libraries are installed in your environment before running the bot.

from flask import Flask, request, abort
from github import Github, PullRequest, Repository, Branch, PullRequestReview
from github.GithubException import UnknownObjectException, GithubException

# --- Global Configuration and Setup ---

# Initialize Flask application
app = Flask(__name__)

# Configure logging for detailed operational insights.
# This setup directs logs to standard output, which is useful for containerized
# environments or monitoring systems. It includes timestamps, log levels,
# thread names (important for background processing), and the message itself.
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(threadName)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# --- Environment Variables Configuration ---
# These crucial variables must be set in the execution environment of the bot.
# They control authentication, security, and the bot's merging policy.

# GITHUB_TOKEN: A Personal Access Token (PAT) or a GitHub App token.
# Required scopes/permissions:
# - `repo` scope for PAT (or `contents:write`, `pull_requests:write` for fine-grained PATs)
# - For GitHub Apps, permissions for:
#   - `Contents`: Read & write
#   - `Pull requests`: Read & write
#   - `Checks`: Read-only (to check status)
#   - `Repository metadata`: Read-only
# Example: export GITHUB_TOKEN="ghp_YOUR_TOKEN_HERE"
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
if not GITHUB_TOKEN:
    logger.critical("Environment variable GITHUB_TOKEN not set. This token is required for GitHub API access. Exiting.")
    sys.exit(1)

# WEBHOOK_SECRET: The secret token configured in your GitHub webhook settings.
# This is vital for verifying the authenticity of incoming webhook payloads,
# preventing unauthorized requests.
# Example: export WEBHOOK_SECRET="YOUR_WEBHOOK_SECRET_STRING"
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET")
if not WEBHOOK_SECRET:
    logger.critical("Environment variable WEBHOOK_SECRET not set. This secret is required for webhook signature verification. Exiting.")
    sys.exit(1)

# REQUIRED_APPROVERS: The minimum number of 'APPROVED' reviews a Pull Request must have
# before the bot considers it eligible for automatic merging.
# Example: export REQUIRED_APPROVERS="2"
try:
    REQUIRED_APPROVERS = int(os.environ.get("REQUIRED_APPROVERS", "2"))
    if REQUIRED_APPROVERS < 0:
        raise ValueError("REQUIRED_APPROVERS must be a non-negative integer.")
except ValueError as e:
    logger.critical(f"Invalid value for REQUIRED_APPROVERS: {e}. Please provide a valid integer. Exiting.")
    sys.exit(1)

# MERGE_METHOD: Specifies how the Pull Request should be merged.
# Valid options are 'merge', 'squash', or 'rebase'.
# - 'merge': Creates a merge commit.
# - 'squash': Squashes all PR commits into a single commit and fast-forwards.
# - 'rebase': Rebases the PR commits onto the base branch and fast-forwards.
# Example: export MERGE_METHOD="squash"
MERGE_METHOD = os.environ.get("MERGE_METHOD", "merge").lower()
if MERGE_METHOD not in ["merge", "squash", "rebase"]:
    logger.warning(
        f"Invalid MERGE_METHOD '{MERGE_METHOD}' provided. "
        "Valid options are 'merge', 'squash', 'rebase'. "
        "Defaulting to 'merge'."
    )
    MERGE_METHOD = "merge"

# Initialize GitHub API client using the provided token.
# This client object facilitates all interactions with the GitHub REST API.
github_client = Github(GITHUB_TOKEN)
logger.info("GitHub API client initialized successfully.")
logger.info(f"Bot configured: {REQUIRED_APPROVERS} approval(s) needed, merge method set to '{MERGE_METHOD}'.")

# --- Helper Functions for Webhook Security and GitHub API Interaction ---

def _verify_webhook_signature(payload_body: bytes, secret_token: str, signature_header: str) -> bool:
    """
    Verifies the authenticity of incoming GitHub webhook payloads.
    GitHub signs each payload with a secret token, allowing the receiver to confirm
    that the request originated from GitHub and has not been altered in transit.

    Args:
        payload_body: The raw HTTP request body (bytes) of the webhook.
        secret_token: The secret string configured for the GitHub webhook.
        signature_header: The value of the 'X-Hub-Signature-256' HTTP header.

    Returns:
        True if the signature is valid, False otherwise.
    """
    if not signature_header:
        logger.warning("Webhook signature header (X-Hub-Signature-256) is missing. Request might be unauthorized.")
        return False

    try:
        # The signature header format is 'sha256=<hex_digest>'.
        # We split it to get the algorithm name and the signature value.
        sha_name, signature = signature_header.split('=')
        if sha_name != 'sha256':
            logger.warning(f"Unsupported signature hash algorithm: '{sha_name}'. Expected 'sha256'.")
            return False

        # Calculate the HMAC digest of the payload body using the secret token.
        # Both the secret and the payload body must be encoded as bytes.
        mac = hmac.new(secret_token.encode('utf-8'), msg=payload_body, digestmod=hashlib.sha256)
        
        # Compare the calculated digest with the provided signature.
        # hmac.compare_digest is used for a constant-time comparison to mitigate timing attacks.
        if not hmac.compare_digest(f'sha256={mac.hexdigest()}', signature):
            logger.error("Webhook signature verification failed: Calculated signature does not match header signature.")
            return False
    except (ValueError, AttributeError, TypeError) as e:
        logger.error(f"Error encountered during webhook signature verification: {e}")
        return False
    
    logger.debug("Webhook signature verified successfully.")
    return True

def _get_repository(repo_full_name: str) -> Repository:
    """
    Retrieves a GitHub repository object by its full name (e.g., 'owner/repo').

    Args:
        repo_full_name: The full name of the repository.

    Returns:
        A PyGithub Repository object.

    Raises:
        UnknownObjectException: If the repository does not exist or the bot lacks access.
        GithubException: For other GitHub API related errors.
    """
    try:
        repo = github_client.get_repo(repo_full_name)
        logger.debug(f"Successfully retrieved repository object for '{repo_full_name}'.")
        return repo
    except UnknownObjectException:
        logger.error(f"Repository '{repo_full_name}' not found or the bot does not have access permissions.")
        raise
    except GithubException as e:
        logger.error(f"GitHub API error while fetching repository '{repo_full_name}': {e}")
        raise

def _get_pull_request_object(repo: Repository, pr_number: int) -> PullRequest:
    """
    Retrieves a GitHub PullRequest object from a given repository by its number.

    Args:
        repo: The PyGithub Repository object.
        pr_number: The numerical identifier of the pull request.

    Returns:
        A PyGithub PullRequest object.

    Raises:
        UnknownObjectException: If the pull request does not exist within the repository.
        GithubException: For other GitHub API related errors.
    """
    try:
        pr = repo.get_pull(pr_number)
        logger.debug(f"Successfully retrieved Pull Request #{pr_number} from '{repo.full_name}'.")
        return pr
    except UnknownObjectException:
        logger.error(f"Pull Request #{pr_number} not found in repository '{repo.full_name}'. It might have been closed or deleted.")
        raise
    except GithubException as e:
        logger.error(f"GitHub API error while fetching Pull Request #{pr_number} from '{repo.full_name}': {e}")
        raise

def _check_pr_approvals(pr: PullRequest, required_approvers: int) -> bool:
    """
    Evaluates if a pull request has garnered the specified minimum number of 'APPROVED' reviews.
    It considers only the latest review state from each unique reviewer.

    Args:
        pr: The PyGithub PullRequest object.
        required_approvers: The minimum count of unique approvers required.

    Returns:
        True if the PR has met or exceeded the approval count, False otherwise.
    """
    logger.info(f"Checking approvals for PR #{pr.number} (title: '{pr.title}'). Required: {required_approvers} approver(s).")

    # A set is used to store unique reviewer logins who have approved the PR.
    # This prevents double-counting if a reviewer submits multiple approval reviews.
    approved_reviewers = set()
    
    try:
        # Fetch all reviews for the pull request. PyGithub generally returns them in chronological order.
        reviews = pr.get_reviews()
    except GithubException as e:
        logger.error(f"Failed to fetch reviews for PR #{pr.number}: {e}")
        return False

    # Iterate through reviews, prioritizing the latest state from each reviewer.
    # If a reviewer approves and then requests changes, the changes requested state should override.
    # Iterating in reverse is more robust for 'latest state' logic.
    reviews_by_user = {}
    for review in reviews:
        reviews_by_user[review.user.login] = review # Store the latest review for each user

    for login, review in reviews_by_user.items():
        if review.state == 'APPROVED':
            approved_reviewers.add(login)
            logger.debug(f"Review from '{login}' is 'APPROVED'.")
        elif review.state == 'CHANGES_REQUESTED':
            # If a reviewer requested changes, they are no longer considered an approver.
            if login in approved_reviewers:
                approved_reviewers.discard(login)
                logger.debug(f"Review from '{login}' is 'CHANGES_REQUESTED'. Removing from approved reviewers.")
        else:
            logger.debug(f"Review from '{login}' has state '{review.state}', ignoring for approval count.")

    current_approvals = len(approved_reviewers)
    logger.info(f"PR #{pr.number} currently has {current_approvals} unique approver(s).")

    if current_approvals >= required_approvers:
        logger.info(f"PR #{pr.number} meets the approval requirements ({current_approvals} >= {required_approvers}).")
        return True
    else:
        logger.info(f"PR #{pr.number} DOES NOT meet the approval requirements ({current_approvals} < {required_approvers}).")
        return False

def _check_pr_status_checks(pr: PullRequest) -> bool:
    """
    Verifies that all required status checks and GitHub Actions (check runs)
    associated with the head commit of the pull request have passed.

    Args:
        pr: The PyGithub PullRequest object.

    Returns:
        True if all checks are successful (or not applicable), False otherwise.
    """
    logger.info(f"Initiating status check evaluation for PR #{pr.number} (Head SHA: {pr.head.sha}).")
    commit = pr.head.ref.commit
    
    # 1. Evaluate legacy Commit Statuses
    # These are often used by older CI systems or custom integrations.
    # The API returns them in reverse chronological order, so the first for each context is the latest.
    statuses = commit.get_statuses()
    
    # We need to find the *latest* status for each *unique context*.
    # Using a dictionary to store the latest status for each context.
    latest_statuses = {}
    for status in statuses:
        if status.context not in latest_statuses:
            latest_statuses[status.context] = status
            
    if latest_statuses:
        logger.debug(f"Found {len(latest_statuses)} unique legacy status checks for commit {commit.sha}.")
        for context, status in latest_statuses.items():
            if status.state == 'error' or status.state == 'failure':
                logger.warning(
                    f"PR #{pr.number}: Legacy status check '{context}' is in state '{status.state}'. "
                    "Blocking merge due to failed status."
                )
                return False
            elif status.state == 'pending':
                logger.info(
                    f"PR #{pr.number}: Legacy status check '{context}' is in state 'pending'. "
                    "Waiting for completion before merge."
                )
                return False
            else: # status.state == 'success'
                logger.debug(f"PR #{pr.number}: Legacy status check '{context}' is in state '{status.state}'.")
        logger.info(f"All {len(latest_statuses)} legacy status checks for PR #{pr.number} are successful or non-blocking.")
    else:
        logger.info(f"No legacy status checks reported for PR #{pr.number}.")

    # 2. Evaluate GitHub Checks API runs (GitHub Actions, etc.)
    # This is the modern and preferred way for CI/CD results.
    try:
        check_runs = commit.get_check_runs()
    except GithubException as e:
        logger.error(f"Failed to fetch check runs for PR #{pr.number} (SHA: {commit.sha}): {e}")
        # An API error retrieving check runs means we cannot confirm their status, so we block.
        return False
        
    if check_runs.totalCount > 0:
        logger.debug(f"Found {check_runs.totalCount} GitHub check runs for commit {commit.sha}.")
        for check_run in check_runs:
            logger.debug(f"Check run '{check_run.name}' (ID: {check_run.id}) Status: '{check_run.status}', Conclusion: '{check_run.conclusion}'")
            
            # A check run must be 'completed' to be considered finished.
            if check_run.status != 'completed':
                logger.info(
                    f"PR #{pr.number}: Check run '{check_run.name}' is '{check_run.status}'. "
                    "Waiting for completion before merge."
                )
                return False
            
            # Once completed, its conclusion must be 'success' or a non-blocking state like 'neutral', 'skipped', 'stale'.
            # Any other conclusion (e.g., 'failure', 'timed_out', 'cancelled') blocks the merge.
            if check_run.conclusion not in ['success', 'neutral', 'skipped', 'stale']:
                logger.warning(
                    f"PR #{pr.number}: Check run '{check_run.name}' has conclusion '{check_run.conclusion}'. "
                    "Blocking merge due to failed check run."
                )
                return False
        logger.info(f"All {check_runs.totalCount} GitHub check runs for PR #{pr.number} are successful.")
    else:
        logger.info(f"No GitHub check runs found for PR #{pr.number}.")

    # 3. Final check on PR mergeability status as reported by GitHub.
    # The `mergeable` attribute indicates whether the PR can be merged without conflicts
    # and if it adheres to branch protection rules. It can be `None` if GitHub is still calculating.
    if pr.mergeable is None:
        logger.info(f"PR #{pr.number} mergeable status is 'None' (GitHub still calculating). Cannot proceed with merge yet.")
        return False # Cannot determine mergeability, so not ready.
    elif not pr.mergeable:
        logger.warning(f"PR #{pr.number} is marked as NOT mergeable by GitHub. Reason: '{pr.mergeable_state}'. Blocking merge.")
        # Common `mergeable_state` values: 'dirty' (conflicts), 'blocked' (branch protection), 'unknown', 'draft'.
        if pr.mergeable_state == 'draft':
            logger.info(f"PR #{pr.number} is a draft Pull Request. Skipping automated merge.")
            return False
        if pr.mergeable_state == 'blocked':
            logger.warning(f"PR #{pr.number} is blocked, potentially due to unsatisfied branch protection rules despite checks passing.")
            return False
        return False # Not mergeable for any reason (conflicts, protection rules, etc.)
    else: # pr.mergeable is True
        logger.info(f"PR #{pr.number} is marked as 'mergeable' by GitHub. Mergeable state: '{pr.mergeable_state}'.")

    logger.info(f"All status checks, check runs, and GitHub's mergeability criteria for PR #{pr.number} have passed successfully.")
    return True

def _perform_merge(pr: PullRequest, merge_method: str = "merge") -> bool:
    """
    Executes the merge operation for a given pull request using the specified method.

    Args:
        pr: The PyGithub PullRequest object to merge.
        merge_method: The desired merge strategy ('merge', 'squash', 'rebase').

    Returns:
        True if the merge operation was successful, False otherwise.
    """
    logger.info(f"Attempting to merge PR #{pr.number} (title: '{pr.title}') into '{pr.base.ref}' using '{merge_method}' method.")
    try:
        # Construct a comprehensive commit title and message for the merge commit.
        # This provides good traceability for automated merges.
        commit_title = f"{pr.title} (#{pr.number})"
        commit_message = f"Automated merge of Pull Request #{pr.number} by automated-pull-request-merger bot.\n\n" \
                         f"Original PR body:\n{pr.body if pr.body else 'No PR body provided.'}"

        merge_result = pr.merge(
            commit_title=commit_title,
            commit_message=commit_message,
            merge_method=merge_method
        )

        if merge_result.merged:
            logger.info(f"Successfully merged PR #{pr.number} into '{pr.base.ref}'. Merge SHA: {merge_result.sha}.")
            return True
        else:
            logger.error(f"Failed to merge PR #{pr.number}. GitHub API reported: '{merge_result.message}'. Merge status: {merge_result.merged}.")
            return False
    except GithubException as e:
        logger.error(f"GitHub API error during merge operation for PR #{pr.number}: {e}")
        return False
    except Exception as e:
        logger.critical(f"An unexpected error occurred during merge operation for PR #{pr.number}: {e}", exc_info=True)
        return False

def _delete_source_branch(repo: Repository, branch_name: str) -> bool:
    """
    Deletes the source branch of a Pull Request after a successful merge.
    This is a common cleanup practice.

    Args:
        repo: The PyGithub Repository object where the branch resides.
        branch_name: The name of the branch to be deleted.

    Returns:
        True if the branch was successfully deleted or was already non-existent, False otherwise.
    """
    logger.info(f"Attempting to delete source branch '{branch_name}' in repository '{repo.full_name}'.")
    try:
        # GitHub's API requires the full ref path, e.g., 'heads/branch-name'.
        git_ref = repo.get_git_ref(f"heads/{branch_name}")
        git_ref.delete()
        logger.info(f"Successfully deleted source branch '{branch_name}'.")
        return True
    except UnknownObjectException:
        logger.warning(f"Branch '{branch_name}' not found in repository '{repo.full_name}'. It may have been deleted manually or previously.")
        return True # If it's already gone, consider the objective met.
    except GithubException as e:
        logger.error(f"GitHub API error while deleting branch '{branch_name}': {e}")
        return False
    except Exception as e:
        logger.critical(f"An unexpected error occurred during branch deletion of '{branch_name}': {e}", exc_info=True)
        return False

def _process_pull_request_event(payload: dict):
    """
    Core logic for processing a GitHub 'pull_request' webhook event.
    This function is designed to run asynchronously in a separate thread
    to prevent blocking the main Flask server.

    It retrieves PR details, checks approvals and status, then triggers merge and branch deletion.

    Args:
        payload: The parsed JSON payload from the GitHub webhook.
    """
    action = payload.get("action")
    pr_data = payload.get("pull_request")
    repository_data = payload.get("repository")

    # Basic validation of the incoming payload structure.
    if not pr_data or not repository_data:
        logger.error("Missing 'pull_request' or 'repository' data in payload. Cannot process event.")
        return

    repo_full_name = repository_data.get("full_name")
    pr_number = pr_data.get("number")
    pr_head_branch = pr_data.get("head", {}).get("ref")
    pr_base_branch = pr_data.get("base", {}).get("ref")
    pr_title = pr_data.get("title")
    pr_state = pr_data.get("state")
    pr_is_draft = pr_data.get("draft", False)

    # Establish a consistent log prefix for easy tracing of a specific PR's processing.
    log_prefix = f"[Repo: {repo_full_name}, PR #{pr_number}]"

    logger.info(f"{log_prefix} Received 'pull_request' event with action: '{action}'. "
                f"PR Title: '{pr_title}', State: '{pr_state}', Draft: {pr_is_draft}, "
                f"Head: '{pr_head_branch}', Base: '{pr_base_branch}'.")

    # Filter for relevant actions that might trigger a merge evaluation.
    # These actions typically indicate changes to the PR's state, reviews, or code.
    if action not in ["opened", "reopened", "synchronize", "ready_for_review"]:
        logger.info(f"{log_prefix} Action '{action}' is not configured to trigger automated merging. Skipping processing.")
        return
    
    # Do not merge draft pull requests. They are still under development.
    if pr_is_draft:
        logger.info(f"{log_prefix} PR is currently a 'draft'. Automated merge is skipped for draft PRs.")
        return

    # Do not process PRs that are already closed or merged.
    if pr_state == "closed":
        logger.info(f"{log_prefix} PR is already closed. No automated merge action will be performed.")
        return
    
    # Retrieve PyGithub objects for the repository and pull request.
    # These objects are essential for detailed API interactions.
    try:
        repository = _get_repository(repo_full_name)
        pull_request = _get_pull_request_object(repository, pr_number)
    except (UnknownObjectException, GithubException) as e:
        logger.error(f"{log_prefix} Failed to retrieve GitHub repository or pull request objects: {e}. Aborting PR processing.")
        return
    except Exception as e:
        logger.critical(f"{log_prefix} Unexpected error during GitHub object retrieval: {e}", exc_info=True)
        return

    # GitHub's `mergeable` status can be `None` if it's still calculating after an event.
    # If it's `None`, we should defer to a later event or re-queue if this were a more advanced system.
    # For this synchronous bot, `None` means "not ready yet".
    if pull_request.mergeable is None:
        logger.info(f"{log_prefix} PR mergeable status is 'None' (GitHub is still calculating). "
                    "This often happens immediately after new commits. Will wait for a subsequent event.")
        return

    # --- Step 1: Check for required approvals ---
    has_enough_approvals = _check_pr_approvals(pull_request, REQUIRED_APPROVERS)
    if not has_enough_approvals:
        logger.info(f"{log_prefix} PR does not have the required number of approvals ({REQUIRED_APPROVERS}). Waiting for more reviews.")
        return

    # --- Step 2: Check for all passing status checks and check runs ---
    all_status_checks_passed = _check_pr_status_checks(pull_request)
    if not all_status_checks_passed:
        logger.info(f"{log_prefix} Not all status checks or check runs have passed or completed successfully. Waiting for checks.")
        return

    # --- Step 3: All conditions met, proceed with merging ---
    logger.info(f"{log_prefix} All automated merge conditions are met: {REQUIRED_APPROVERS}+ approvals and all status checks passed.")
    merge_successful = _perform_merge(pull_request, MERGE_METHOD)

    if merge_successful:
        logger.info(f"{log_prefix} Pull Request successfully merged. Proceeding to delete the source branch.")
        # --- Step 4: Delete source branch after successful merge ---
        # The `head` branch of the PR is the source branch that should be deleted.
        delete_successful = _delete_source_branch(repository, pr_head_branch)
        if delete_successful:
            logger.info(f"{log_prefix} Source branch '{pr_head_branch}' deleted successfully.")
        else:
            logger.warning(f"{log_prefix} Failed to delete source branch '{pr_head_branch}'. Manual cleanup may be required.")
    else:
        logger.error(f"{log_prefix} Automated merge failed. Source branch deletion skipped.")

# --- Flask Webhook Handler Entry Point ---

@app.route("/webhook", methods=["POST"])
def github_webhook_handler():
    """
    The main webhook endpoint that GitHub sends events to.
    It performs signature verification and then dispatches the actual event processing
    to a separate thread to ensure a prompt HTTP response to GitHub.
    """
    logger.info("Received a new webhook request from GitHub.")

    # Retrieve headers essential for security and event identification.
    signature = request.headers.get("X-Hub-Signature-256")
    event_type = request.headers.get("X-GitHub-Event")

    # Security check: Verify the webhook signature. This is critical to ensure
    # that the request is legitimate and has not been tampered with.
    if not _verify_webhook_signature(request.data, WEBHOOK_SECRET, signature):
        logger.error("Unauthorized request: Webhook signature verification failed. Aborting request.")
        abort(401, "Invalid signature") # HTTP 401 Unauthorized

    # Check for the presence of the event type header.
    if not event_type:
        logger.error("Missing 'X-GitHub-Event' header in webhook request. Cannot determine event type.")
        abort(400, "Missing X-GitHub-Event header") # HTTP 400 Bad Request

    # Attempt to parse the JSON payload from the request body.
    try:
        payload = request.get_json()
    except Exception as e:
        logger.error(f"Failed to parse JSON payload from webhook request: {e}")
        abort(400, "Invalid JSON payload") # HTTP 400 Bad Request

    logger.info(f"Successfully received and validated webhook event of type: '{event_type}'.")

    # Handle 'ping' events specifically. GitHub sends these to test webhook configurations.
    if event_type == "ping":
        logger.info("Received 'ping' event. Webhook is successfully configured and active.")
        return "Pong!", 200 # HTTP 200 OK
    
    # Process 'pull_request' events asynchronously.
    # By using a separate thread, the Flask server can immediately return a 202 Accepted response,
    # preventing GitHub from timing out the webhook while potentially long-running API calls are made.
    if event_type == "pull_request":
        pr_number = payload.get("pull_request", {}).get("number", "N/A")
        repo_name = payload.get("repository", {}).get("name", "N/A")
        thread_name = f"PR_Processor_Repo_{repo_name}_PR_{pr_number}"
        
        # Create and start a new thread to process the event.
        thread = threading.Thread(
            target=_process_pull_request_event, 
            args=(payload,),
            name=thread_name
        )
        thread.start()
        logger.info(f"Dispatched 'pull_request' event for processing in background thread: {thread_name}.")
        return "Pull request event received and queued for processing.", 202 # HTTP 202 Accepted
    
    # For any other event types not explicitly handled, acknowledge receipt but take no action.
    logger.info(f"Webhook event type '{event_type}' is not handled by this bot. Acknowledged and skipped processing.")
    return f"Event type '{event_type}' received. Not processed by this bot.", 200 # HTTP 200 OK

# --- Main Application Entry Point ---

if __name__ == "__main__":
    # This block ensures the Flask application runs when the script is executed directly.
    # In a production environment, it is highly recommended to use a robust WSGI server
    # like Gunicorn or uWSGI to serve the Flask application.
    #
    # `host="0.0.0.0"` makes the server accessible from any network interface, useful
    # when deploying in containers or when using tools like ngrok for local testing.
    # `port=5000` is the default Flask port.
    # `debug=False` is crucial for production environments; debug mode should never be enabled in production.
    logger.info("Starting automated-pull-request-merger bot via Flask's development server...")
    logger.warning("NOTE: Running with `app.run()` is suitable for development/testing only. "
                   "For production, please use a WSGI server (e.g., Gunicorn, uWSGI).")
    app.run(host="0.0.0.0", port=5000, debug=False)
    logger.info("automated-pull-request-merger bot gracefully stopped.")