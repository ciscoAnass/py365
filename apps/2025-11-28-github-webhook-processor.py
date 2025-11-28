import os
import json
import hmac
import hashlib
from flask import Flask, request, abort
from datetime import datetime
from typing import Tuple, Dict, Any

app = Flask(__name__)

# Configuration
GITHUB_WEBHOOK_SECRET = os.environ.get("GITHUB_WEBHOOK_SECRET")
JIRA_API_TOKEN = os.environ.get("JIRA_API_TOKEN")
JIRA_USERNAME = os.environ.get("JIRA_USERNAME")
JIRA_PROJECT_KEY = os.environ.get("JIRA_PROJECT_KEY")

# Downstream actions
def run_test_script(repo_name: str, branch: str) -> bool:
    """
    Runs a test script for the given repository and branch.
    Returns True if the test script passes, False otherwise.
    """
    # Implement the logic to run the test script
    # This could involve cloning the repository, checking out the branch,
    # and running a test suite or script
    print(f"Running test script for {repo_name} on branch {branch}")
    return True

def deploy_to_staging(repo_name: str, branch: str) -> bool:
    """
    Deploys the code for the given repository and branch to the staging environment.
    Returns True if the deployment is successful, False otherwise.
    """
    # Implement the logic to deploy the code to the staging environment
    # This could involve building and pushing a Docker image, or running
    # a deployment script on a staging server
    print(f"Deploying {repo_name} on branch {branch} to staging")
    return True

def update_jira_ticket(repo_name: str, branch: str, commit_hash: str) -> bool:
    """
    Updates a Jira ticket with information about the pushed commit.
    Returns True if the Jira ticket is updated successfully, False otherwise.
    """
    # Implement the logic to update the Jira ticket
    # This could involve making an API call to Jira to create a new issue
    # or add a comment to an existing issue
    print(f"Updating Jira ticket for {repo_name} on branch {branch}, commit {commit_hash}")
    return True

def verify_webhook_signature(request_body: bytes, signature: str) -> bool:
    """
    Verifies the signature of the incoming GitHub webhook request.
    Returns True if the signature is valid, False otherwise.
    """
    if not GITHUB_WEBHOOK_SECRET:
        return True  # Signature verification disabled

    expected_signature = f"sha256={hmac.new(GITHUB_WEBHOOK_SECRET.encode(), request_body, hashlib.sha256).hexdigest()}"
    return hmac.compare_digest(signature, expected_signature)

def process_push_event(data: Dict[str, Any]) -> None:
    """
    Processes a 'push' event from the GitHub webhook.
    Runs the test script, deploys to staging, and updates the Jira ticket.
    """
    repo_name = data["repository"]["name"]
    branch = data["ref"].split("/")[-1]
    commit_hash = data["head_commit"]["id"]

    if run_test_script(repo_name, branch):
        if deploy_to_staging(repo_name, branch):
            update_jira_ticket(repo_name, branch, commit_hash)

def process_pull_request_event(data: Dict[str, Any]) -> None:
    """
    Processes a 'pull_request' event from the GitHub webhook.
    Runs the test script for the pull request branch.
    """
    repo_name = data["repository"]["name"]
    branch = data["pull_request"]["head"]["ref"]

    run_test_script(repo_name, branch)

@app.route("/webhook", methods=["POST"])
def handle_webhook():
    """
    Handles incoming GitHub webhook requests.
    Verifies the webhook signature and processes the event accordingly.
    """
    signature = request.headers.get("X-Hub-Signature-256")
    if not verify_webhook_signature(request.data, signature):
        abort(403)

    event_type = request.headers.get("X-GitHub-Event")
    data = json.loads(request.data)

    if event_type == "push":
        process_push_event(data)
    elif event_type == "pull_request":
        process_pull_request_event(data)
    else:
        print(f"Unsupported event type: {event_type}")

    return "OK"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)