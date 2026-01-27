import os
import sys
import json
import hmac
import hashlib
import subprocess
import shutil
import tempfile
import logging
from datetime import datetime

# --- Third-party library imports (specify via comments) ---
# Flask: Web framework for handling HTTP requests.
# Installation: pip install Flask
from flask import Flask, request, jsonify, abort

# PyGithub: Python library to access the GitHub API v3.
# Installation: pip install PyGithub
from github import Github, GithubException

# You'll also need to ensure the linters themselves are installed in the environment
# where this script runs. Example:
# pip install flake8 black pylint


# --- Configuration Management Class ---
class Config:
    """
    Centralized configuration management for the automated code linter server.
    All settings are loaded from environment variables to promote secure
    and flexible deployment in various environments (e.g., Docker, Kubernetes).
    """
    # Required: GitHub Personal Access Token with 'repo' scope.
    # This token is used to interact with the GitHub API (e.g., cloning private repos, posting comments).
    GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")

    # Required: Secret token configured in the GitHub webhook settings.
    # Used to validate the authenticity of incoming webhook requests.
    WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET")

    # Optional: Port on which the Flask server will listen. Defaults to 5000.
    SERVER_PORT = int(os.environ.get("SERVER_PORT", 5000))

    # Optional: Directory to temporarily clone repositories for linting.
    # Ensure this directory has appropriate write permissions.
    TEMP_CLONE_DIR = os.environ.get("TEMP_CLONE_DIR", "/tmp/lint_repos")

    # Optional: Comma-separated list of linters to run by default if no
    # repository-specific configuration is provided.
    # Supported values: 'flake8', 'black', 'pylint'.
    DEFAULT_LINTERS_STR = os.environ.get("DEFAULT_LINTERS", "flake8,black")
    DEFAULT_LINTERS = [linter.strip().lower() for linter in DEFAULT_LINTERS_STR.split(',') if linter.strip()]

    # Optional: Advanced configuration for specific repositories.
    # Format: "owner/repo1:linter1,linter2;owner/repo2:linterX"
    # This allows tailoring linters for different projects.
    REPO_LINTER_CONFIGS_ENV = os.environ.get("REPO_LINTER_CONFIGS", "")
    REPO_LINTER_CONFIGS = {}
    if REPO_LINTER_CONFIGS_ENV:
        try:
            for repo_config_pair in REPO_LINTER_CONFIGS_ENV.split(';'):
                if ':' in repo_config_pair:
                    repo_name, linters_str = repo_config_pair.split(':', 1)
                    REPO_LINTER_CONFIGS[repo_name.strip()] = [
                        l.strip().lower() for l in linters_str.split(',') if l.strip()
                    ]
        except Exception as e:
            print(f"Error parsing REPO_LINTER_CONFIGS environment variable: {e}", file=sys.stderr)
            print("Please ensure format is 'owner/repo1:linter1,linter2;owner/repo2:linterX'", file=sys.stderr)
            sys.exit(1)

    # Dictionary defining the command and default arguments for each supported linter.
    # The script will append the file path to these commands.
    LINTER_COMMANDS = {
        "flake8": ["flake8"],
        "black": ["black", "--check", "--diff"],  # '--check' ensures it reports formatting issues without fixing.
                                                  # '--diff' shows what changes Black would make.
        "pylint": ["pylint", "--output-format=json"] # Pylint's JSON output is easier to parse.
    }

    # GitHub API base URL. Standard for public GitHub.
    GITHUB_API_BASE_URL = "https://api.github.com"

    @classmethod
    def validate(cls):
        """
        Validates that all necessary configuration parameters are set.
        Raises a ValueError if any critical configuration is missing.
        """
        if not cls.GITHUB_TOKEN:
            raise ValueError("GITHUB_TOKEN environment variable is not set. This is required for GitHub API access.")
        if not cls.WEBHOOK_SECRET:
            raise ValueError("WEBHOOK_SECRET environment variable is not set. This is required for webhook security.")
        
        # Ensure the temporary directory exists
        os.makedirs(cls.TEMP_CLONE_DIR, exist_ok=True)

        # Log loaded configuration for debugging and verification
        print("\n--- Automated Code Linter Server Configuration ---")
        print(f"  Server Port: {cls.SERVER_PORT}")
        print(f"  Temporary Clone Directory: {cls.TEMP_CLONE_DIR}")
        print(f"  Default Linters: {', '.join(cls.DEFAULT_LINTERS) if cls.DEFAULT_LINTERS else 'None'}")
        print(f"  Repository-Specific Linter Configs: {cls.REPO_LINTER_CONFIGS if cls.REPO_LINTER_CONFIGS else 'None'}")
        print("--- Configuration Loaded Successfully ---\n")


# --- Logging Setup ---
# Configure a robust logging system to capture events, warnings, and errors.
# Logs are written to a file and to standard output (console).
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("automated-code-linter-server.log", encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


# --- Initialize Flask Application ---
app = Flask(__name__)

# --- Initialize GitHub API Client ---
# The GitHub client is initialized globally after configuration validation.
github_client = None
try:
    Config.validate()  # First, validate environment variables
    github_client = Github(Config.GITHUB_TOKEN)
    logger.info("GitHub API client initialized successfully.")
    # Attempt a simple API call to verify token validity early
    user = github_client.get_user()
    logger.info(f"Connected to GitHub as user: {user.login}")
except ValueError as e:
    logger.critical(f"Configuration error at startup: {e}. Please set required environment variables. Exiting.")
    sys.exit(1)
except GithubException as e:
    logger.critical(f"Failed to connect to GitHub API or token is invalid: {e}. Please check GITHUB_TOKEN scope/validity. Exiting.")
    sys.exit(1)
except Exception as e:
    logger.critical(f"An unexpected error occurred during GitHub client initialization: {e}. Exiting.", exc_info=True)
    sys.exit(1)


# --- Data Structure for Linter Violations ---
class LinterViolation:
    """
    Represents a single linting violation detected by any linter.
    Encapsulates details like linter name, file path, line/column numbers,
    message, and severity.
    """
    def __init__(self, linter_name, file_path, line_number, column_number, message, severity="error"):
        self.linter_name = linter_name
        self.file_path = file_path # Relative path to the repo root
        self.line_number = int(line_number) if line_number is not None else None
        self.column_number = int(column_number) if column_number is not None else None
        self.message = message
        # Severity can be 'error', 'warning', 'info', 'convention', 'refactor'
        self.severity = severity.lower() 

    def __str__(self):
        """Provides a human-readable string representation of the violation."""
        location_info = ""
        if self.line_number is not None:
            location_info += f"L{self.line_number}"
            if self.column_number is not None:
                location_info += f":C{self.column_number}"
        
        if location_info:
            return f"[{self.severity.upper()}] {self.linter_name} in {self.file_path} {location_info}: {self.message}"
        else:
            return f"[{self.severity.upper()}] {self.linter_name} in {self.file_path}: {self.message}"

    def to_github_comment_format(self):
        """
        Formats the violation into a Markdown string suitable for GitHub comments.
        """
        location_md = ""
        if self.line_number is not None:
            location_md += f" line `{self.line_number}`"
            if self.column_number is not None:
                location_md += f", column `{self.column_number}`"
        
        return (
            f"**[{self.linter_name.upper()}]** "
            f"`{self.file_path}`"
            f"{location_md}: "
            f"**{self.severity.upper()}**: {self.message}"
        )


# --- Helper Functions for GitHub Webhook Security ---
def validate_github_signature(payload_body, signature_header, secret):
    """
    Validates the 'X-Hub-Signature-256' header from GitHub webhooks.
    This ensures that the webhook request truly originated from GitHub
    and has not been tampered with.
    
    Args:
        payload_body (bytes): The raw body of the POST request.
        signature_header (str): The value of the 'X-Hub-Signature-256' header.
                                 Expected format: "sha256=<hex_digest>"
        secret (str): The webhook secret configured on GitHub and in the server's environment.
    
    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    if not signature_header or not secret:
        logger.warning("Missing 'X-Hub-Signature-256' header or WEBHOOK_SECRET. Webhook validation cannot proceed.")
        return False

    try:
        sha_name, signature = signature_header.split('=', 1)
    except ValueError:
        logger.error(f"Invalid signature header format: {signature_header}. Expected 'sha256=<hex_digest>'.")
        return False

    if sha_name != 'sha256':
        logger.error(f"Unsupported signature algorithm: {sha_name}. Only 'sha256' is supported.")
        return False

    # Compute hash using HMAC with SHA256
    mac = hmac.new(secret.encode('utf-8'), msg=payload_body, digestmod=hashlib.sha256)
    expected_signature = mac.hexdigest()

    # Use hmac.compare_digest for constant-time comparison to prevent timing attacks.
    if not hmac.compare_digest(expected_signature, signature):
        logger.error(f"Webhook signature mismatch. Expected: {expected_signature}, Received: {signature}")
        return False
    
    logger.info("Webhook signature validated successfully.")
    return True


# --- Helper Functions for Git Operations ---
def clone_repository(repo_url, commit_sha, temp_dir):
    """
    Clones a specific commit of a GitHub repository into a temporary directory.
    This ensures that linters run against the exact code state of the push event.
    
    Args:
        repo_url (str): The HTTPS URL of the repository (e.g., https://github.com/owner/repo.git).
                        This URL should ideally embed the GITHUB_TOKEN for private repositories.
        commit_sha (str): The SHA of the commit to checkout.
        temp_dir (str): The base directory where the repository should be cloned.
    
    Returns:
        str: The absolute path to the cloned repository, or None on failure.
    """
    repo_name = repo_url.split('/')[-1].replace('.git', '')
    # Create a unique path for each commit to avoid conflicts and ensure isolation.
    clone_path = os.path.join(temp_dir, f"{repo_name}_{commit_sha}_{datetime.now().strftime('%Y%m%d%H%M%S%f')}")

    if os.path.exists(clone_path):
        logger.info(f"Repository already exists at {clone_path}. Skipping clone operation. (This should be rare due to unique paths)")
        return clone_path

    logger.info(f"Attempting to clone repository {repo_url} (commit: {commit_sha}) to {clone_path}...")
    try:
        # Use '--depth 1' to fetch only the specified commit, which is faster and saves space.
        # This requires `git clone` to be robust enough. If `git checkout` after `clone --depth 1` fails,
        # a full clone might be needed, but `--depth 1` then `checkout <sha>` usually works for the initial commit.
        # For an arbitrary commit in history, you might need `git fetch origin <sha>` then `git checkout <sha>`.
        # However, for a 'push' event, the `after` SHA is the latest, so `depth 1` then `checkout` should work.
        subprocess.run(["git", "clone", "--depth", "1", repo_url, clone_path], check=True, capture_output=True, text=True, timeout=300)
        
        # Ensure the correct commit is checked out.
        subprocess.run(["git", "-C", clone_path, "checkout", commit_sha], check=True, capture_output=True, text=True, timeout=60)
        
        logger.info(f"Repository cloned and checked out {commit_sha} successfully at {clone_path}.")
        return clone_path
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to clone or checkout repository: {e.cmd}", exc_info=True)
        logger.error(f"STDOUT: {e.stdout}")
        logger.error(f"STDERR: {e.stderr}")
        shutil.rmtree(clone_path, ignore_errors=True) # Clean up partial clone
        return None
    except subprocess.TimeoutExpired:
        logger.error(f"Git clone or checkout timed out for {repo_url}@{commit_sha}.")
        shutil.rmtree(clone_path, ignore_errors=True)
        return None
    except Exception as e:
        logger.error(f"An unexpected error occurred during repository cloning for {repo_url}: {e}", exc_info=True)
        shutil.rmtree(clone_path, ignore_errors=True)
        return None

def cleanup_repository(repo_path):
    """
    Removes a cloned repository directory to free up disk space and maintain isolation.
    
    Args:
        repo_path (str): The absolute path to the cloned repository.
    """
    if repo_path and os.path.exists(repo_path):
        logger.info(f"Initiating cleanup for temporary repository directory: {repo_path}")
        try:
            shutil.rmtree(repo_path)
            logger.info(f"Repository directory {repo_path} removed successfully.")
        except Exception as e:
            logger.error(f"Error cleaning up repository directory {repo_path}: {e}", exc_info=True)


# --- Helper Functions for GitHub API Interaction ---
def get_github_repository(repo_full_name):
    """
    Retrieves a GitHub repository object using the PyGithub client.
    
    Args:
        repo_full_name (str): Full name of the repository (e.g., 'owner/repo').
    
    Returns:
        github.Repository.Repository: The GitHub repository object, or None on failure.
    """
    try:
        # For organization-owned repositories, use github_client.get_organization(org_name).get_repo(repo_name)
        # For user-owned repositories, github_client.get_user().get_repo(repo_name) or github_client.get_repo(repo_full_name)
        # get_repo(repo_full_name) is more general.
        repo = github_client.get_repo(repo_full_name)
        return repo
    except GithubException as e:
        if e.status == 404:
            logger.error(f"GitHub repository {repo_full_name} not found. Check repository name and token permissions.")
        else:
            logger.error(f"Failed to get GitHub repository {repo_full_name}: {e}. Status: {e.status}, Data: {e.data}", exc_info=True)
        return None

def post_commit_comment(repo_full_name, commit_sha, comment_body):
    """
    Posts a general comment to a specific commit on GitHub.
    This is suitable for push events where a general summary of linting
    results is desired on the commit itself.
    
    Args:
        repo_full_name (str): Full name of the repository.
        commit_sha (str): The SHA of the commit to which the comment will be added.
        comment_body (str): The content of the comment in Markdown format.
    
    Returns:
        bool: True if comment was posted successfully, False otherwise.
    """
    repo = get_github_repository(repo_full_name)
    if not repo:
        logger.warning(f"Cannot post commit comment: Repository {repo_full_name} not found or inaccessible.")
        return False

    try:
        commit = repo.get_commit(sha=commit_sha)
        commit.create_comment(comment_body)
        logger.info(f"Successfully posted commit comment to {repo_full_name}@{commit_sha}")
        return True
    except GithubException as e:
        logger.error(f"Failed to post commit comment to {repo_full_name}@{commit_sha}: {e}. Status: {e.status}, Data: {e.data}", exc_info=True)
        return False
    except Exception as e:
        logger.error(f"An unexpected error occurred while posting commit comment: {e}", exc_info=True)
        return False

def post_line_comment_on_pr(repo_full_name, pull_request_number, commit_sha, file_path, line_number, comment_body):
    """
    Posts a comment on a specific line of code within a Pull Request.
    This functionality is typically used for more granular feedback during PR review.
    While the primary request is for commit comments on push, this is included
    for a more comprehensive solution, demonstrating how to target specific lines.
    
    Args:
        repo_full_name (str): Full name of the repository.
        pull_request_number (int): The number of the Pull Request.
        commit_sha (str): The SHA of the commit the comment refers to.
        file_path (str): The path to the file relative to the repository root.
        line_number (int): The line number in the *latest* version of the file in the PR.
                           Note: GitHub's PR line comments typically require a 'position'
                           which is an index into the diff hunks, not just a line number.
                           For simplicity, this example uses 'line_number' assuming
                           PyGithub handles the diff complexities for basic line references.
        comment_body (str): The content of the comment.
    
    Returns:
        bool: True if comment was posted successfully, False otherwise.
    """
    repo = get_github_repository(repo_full_name)
    if not repo:
        logger.warning(f"Cannot post line comment: Repository {repo_full_name} not found or inaccessible.")
        return False

    try:
        pr = repo.get_pull(pull_request_number)
        # 'position' refers to the line index in the diff hunk, not the absolute file line number.
        # This makes it complex to use directly with a simple line_number.
        # For this function, we'll try to use `line` which refers to the absolute line number in the latest diff.
        # This behavior can be tricky and may require more advanced diff parsing in a real-world scenario.
        # For now, `path` and `line` are common parameters for review comments.
        pr.create_review_comment(body=comment_body, commit_id=commit_sha, path=file_path, line=line_number)
        logger.info(f"Successfully posted line comment on PR #{pull_request_number} for {file_path} line {line_number}.")
        return True
    except GithubException as e:
        logger.error(f"Failed to post line comment on PR #{pull_request_number} for {file_path} line {line_number}: {e}", exc_info=True)
        logger.error(f"Possible reason: 'line' parameter might need to correspond to a line in the diff, or 'position' might be required.")
        return False
    except Exception as e:
        logger.error(f"An unexpected error occurred while posting line comment on PR: {e}", exc_info=True)
        return False


# --- Linter Execution and Output Parsing Functions ---
def execute_linter_command(linter_name, command_args, file_abs_path, base_repo_dir):
    """
    Executes a specific linter command on a given file and captures its output.
    Dispatches to appropriate parsing functions based on the linter name.
    
    Args:
        linter_name (str): The name of the linter (e.g., 'flake8', 'black', 'pylint').
        command_args (list): The base command and arguments for the linter.
        file_abs_path (str): The absolute path to the file to be linted.
        base_repo_dir (str): The absolute root directory of the cloned repository.
                             Used to convert absolute paths in linter output to relative paths.
    
    Returns:
        tuple: A tuple containing:
               - list of LinterViolation objects
               - raw stdout from the linter
               - raw stderr from the linter
    """
    violations = []
    stdout = ""
    stderr = ""
    
    try:
        full_command = list(command_args) # Create a mutable copy of the command list
        cwd_for_linter = base_repo_dir # Default CWD for linters that need project context

        # Adjust command and CWD based on linter specifics
        if linter_name == "pylint":
            # Pylint works best when run from the repository root, with module paths relative to it.
            # This allows it to resolve imports and configuration correctly.
            relative_file_path = os.path.relpath(file_abs_path, base_repo_dir)
            full_command.append(relative_file_path)
        elif linter_name == "black":
            # Black can typically take an absolute file path without needing specific CWD.
            full_command.append(file_abs_path)
            cwd_for_linter = None # Black usually doesn't need repo root CWD for single file
        else: # flake8 and others
            full_command.append(file_abs_path)
            cwd_for_linter = None # Flake8 can also run on absolute file paths

        logger.info(f"Running {linter_name} on {file_abs_path} with command: {' '.join(full_command)}")
        
        # Execute the linter command. `check=False` allows us to capture output
        # even if the linter exits with a non-zero code (which often indicates violations).
        process = subprocess.run(
            full_command,
            cwd=cwd_for_linter,
            capture_output=True,
            text=True,
            check=False,
            timeout=180 # Set a generous timeout (3 minutes) to prevent hung processes
        )
        stdout = process.stdout
        stderr = process.stderr
        
        # Log any non-zero exit codes (except for black, where 1 means reformat needed)
        if process.returncode != 0:
            if linter_name == "black" and process.returncode == 1:
                logger.info(f"Black for {file_abs_path} exited with code 1, indicating reformatting is needed (normal for --check).")
            else:
                logger.warning(f"Linter '{linter_name}' for {file_abs_path} exited with non-zero code {process.returncode}.")
        if stderr:
            logger.warning(f"Stderr from {linter_name} for {file_abs_path}:\n{stderr}")

        # Parse output based on the linter
        if linter_name == "flake8":
            violations.extend(parse_flake8_output(stdout, base_repo_dir))
        elif linter_name == "black":
            violations.extend(parse_black_output(stdout, base_repo_dir, file_abs_path, process.returncode))
        elif linter_name == "pylint":
            violations.extend(parse_pylint_json_output(stdout, base_repo_dir))
        else:
            logger.warning(f"No specific parser implemented for linter: {linter_name}. Raw stdout:\n{stdout}")
            if stdout.strip():
                 # For unsupported linters, just report the raw output as an info message
                 violations.append(LinterViolation(linter_name, os.path.relpath(file_abs_path, base_repo_dir), 
                                                   None, None, f"Raw output: {stdout.strip()}", "info"))

    except FileNotFoundError:
        logger.error(f"Linter executable '{linter_name}' not found. Please ensure it is installed and in the system PATH.", exc_info=True)
        violations.append(LinterViolation(linter_name, os.path.relpath(file_abs_path, base_repo_dir),
                                           None, None, f"Linter executable '{linter_name}' not found. Is it installed?", "error"))
    except subprocess.TimeoutExpired:
        logger.error(f"Linter '{linter_name}' timed out after 180 seconds for {file_abs_path}.")
        violations.append(LinterViolation(linter_name, os.path.relpath(file_abs_path, base_repo_dir),
                                           None, None, f"Linter timed out after 180 seconds.", "error"))
    except Exception as e:
        logger.error(f"An unexpected error occurred while running {linter_name} on {file_abs_path}: {e}", exc_info=True)
        violations.append(LinterViolation(linter_name, os.path.relpath(file_abs_path, base_repo_dir),
                                           None, None, f"Internal error during linting: {e}", "error"))
    
    return violations, stdout, stderr

def parse_flake8_output(output, base_repo_dir):
    """
    Parses the standard output format of flake8.
    Expected format: 'filepath:lineno:colno: error_code message'
    
    Args:
        output (str): The raw stdout from flake8.
        base_repo_dir (str): The root directory of the cloned repository.
    
    Returns:
        list: A list of LinterViolation objects.
    """
    violations = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            # Split by the first 3 colons to isolate file, line, col, and then the rest as message
            parts = line.split(':', 3) 
            if len(parts) >= 4:
                file_path = os.path.relpath(parts[0].strip(), base_repo_dir) # Make path relative
                line_number = parts[1].strip()
                column_number = parts[2].strip()
                message_with_code = parts[3].strip()
                
                # Flake8 errors are usually warnings by default, unless configured otherwise.
                # Common codes like E/W are warnings, F/C are style/complexity, D for docstrings etc.
                # We'll default to 'warning' for simplicity, or 'error' for specific codes if needed.
                violations.append(LinterViolation("flake8", file_path, line_number, column_number, message_with_code, "warning"))
            else:
                logger.warning(f"Could not parse flake8 output line (unexpected format): {line}")
        except Exception as e:
            logger.error(f"Error parsing flake8 line '{line}': {e}", exc_info=True)
    return violations

def parse_black_output(output, base_repo_dir, original_file_abs_path, return_code):
    """
    Parses the output of `black --check --diff`.
    Black returns 0 if no changes, 1 if changes are needed, and >1 for errors.
    
    Args:
        output (str): The raw stdout from black.
        base_repo_dir (str): The root directory of the cloned repository.
        original_file_abs_path (str): The absolute path of the file that black was run against.
        return_code (int): The exit code of the black process.
    
    Returns:
        list: A list of LinterViolation objects.
    """
    violations = []
    relative_file_path = os.path.relpath(original_file_abs_path, base_repo_dir)

    if return_code == 1: # Black found files that would be reformatted
        # Black --diff output is a standard diff format. Parsing it to find specific
        # line numbers for comments can be complex. For simplicity, we report a general
        # violation for the file.
        violations.append(LinterViolation(
            "black", relative_file_path, None, None,
            "File requires reformatting by Black. Please run `black` on this file.", "warning"
        ))
        logger.info(f"Black detected reformatting needed for {relative_file_path}.")
        if output.strip():
            logger.debug(f"Black --diff output for {relative_file_path}:\n{output}")
    elif return_code > 1: # Black encountered an internal error
        violations.append(LinterViolation(
            "black", relative_file_path, None, None,
            f"Black encountered an internal error (exit code {return_code}). Output: {output}", "error"
        ))
        logger.error(f"Black encountered an error for {relative_file_path}. Output: {output}")
    else: # return_code == 0, no issues
        logger.info(f"Black found no formatting issues for {relative_file_path}.")
    return violations

def parse_pylint_json_output(output, base_repo_dir):
    """
    Parses the JSON output of pylint (--output-format=json).
    This format is much easier to parse programmatically than plain text.
    
    Args:
        output (str): The raw stdout from pylint in JSON format.
        base_repo_dir (str): The root directory of the cloned repository.
    
    Returns:
        list: A list of LinterViolation objects.
    """
    violations = []
    if not output.strip():
        return violations

    try:
        pylint_data = json.loads(output)
        if not isinstance(pylint_data, list):
            logger.error(f"Pylint JSON output is not a list. Raw output: {output}")
            return violations

        for item in pylint_data:
            file_path = os.path.relpath(item.get('path', 'unknown_file'), base_repo_dir)
            line = item.get('line')
            column = item.get('column')
            
            # Pylint messages include a symbol (e.g., C0103) and a descriptive message.
            message = f"({item.get('symbol', 'N/A')}) {item.get('message', 'No message provided')}"
            
            # Pylint has several types: 'error', 'warning', 'refactor', 'convention'.
            # Map them to our severity convention.
            pylint_type = item.get('type', 'convention').lower()
            severity_map = {
                'error': 'error',
                'warning': 'warning',
                'fatal': 'error', # Fatal errors are also errors
                'refactor': 'info', # Refactoring suggestions can be info
                'convention': 'info' # Convention messages are often informational
            }
            severity = severity_map.get(pylint_type, 'info') # Default to info for unknown types
            
            violations.append(LinterViolation("pylint", file_path, line, column, message, severity))
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse pylint JSON output (invalid JSON): {e}. Raw output: {output}", exc_info=True)
        violations.append(LinterViolation("pylint", "unknown_file", None, None, f"Failed to parse pylint JSON output: {e}", "error"))
    except Exception as e:
        logger.error(f"Error processing pylint JSON output structure: {e}. Raw output: {output}", exc_info=True)
        violations.append(LinterViolation("pylint", "unknown_file", None, None, f"Error processing pylint output: {e}", "error"))
    return violations


# --- Main Webhook Handler Endpoint ---
@app.route('/webhook', methods=['POST'])
def github_webhook():
    """
    Primary endpoint for receiving GitHub webhook events.
    It validates the request, dispatches to specific handlers based on event type,
    and returns an appropriate HTTP response.
    """
    logger.info("Received a new webhook request.")

    # 1. Validate webhook signature for security
    payload_body = request.get_data()
    signature = request.headers.get('X-Hub-Signature-256')
    if not validate_github_signature(payload_body, signature, Config.WEBHOOK_SECRET):
        abort(401, "Invalid webhook signature. Request denied.") # Respond with HTTP 401 Unauthorized

    try:
        payload = request.get_json()
    except Exception as e:
        logger.error(f"Failed to parse JSON payload from webhook: {e}", exc_info=True)
        abort(400, "Invalid JSON payload. Request denied.") # Respond with HTTP 400 Bad Request

    github_event = request.headers.get('X-GitHub-Event')
    logger.info(f"Detected GitHub Event Type: '{github_event}'")

    # Dispatch to specific event handlers
    if github_event == 'ping':
        logger.info("Received 'ping' event. Webhook is successfully configured.")
        return jsonify({"msg": "Pong! Webhook successfully configured."}), 200
    elif github_event == 'push':
        # Process push events for commit-based linting
        return handle_push_event(payload)
    elif github_event == 'pull_request':
        # While the request description focuses on 'pre-commit webhook' which maps well to 'push',
        # a comprehensive linter service would also handle 'pull_request' events for integrated CI/CD.
        # This placeholder indicates where such logic would be added.
        logger.info("Received 'pull_request' event. This service currently focuses on 'push' events. Skipping detailed processing.")
        return jsonify({"msg": "Pull request events are currently not processed for linting by this service."}), 200
    else:
        logger.info(f"Unhandled GitHub event type: '{github_event}'. No specific processing logic implemented. Skipping.")
        return jsonify({"msg": f"Event type '{github_event}' not explicitly processed."}), 200


def handle_push_event(payload):
    """
    Dedicated handler for GitHub 'push' events.
    This function orchestrates the cloning, linting, and commenting process.
    
    Args:
        payload (dict): The parsed JSON payload from the GitHub 'push' webhook.
    
    Returns:
        tuple: A Flask response tuple (JSON response, HTTP status code).
    """
    repo_full_name = payload['repository']['full_name']
    commit_sha = payload['after']  # 'after' is the SHA of the head commit of the push
    compare_url = payload['compare']  # URL to GitHub's compare view for this push
    pusher_name = payload['pusher']['name']
    
    logger.info(f"--- Starting linting process for push event ---")
    logger.info(f"Repository: {repo_full_name}, Commit: {commit_sha}, Pusher: {pusher_name}")

    # GitHub sends a special '0000...' SHA for branch deletions.
    if commit_sha == '0000000000000000000000000000000000000000':
        logger.info("Commit SHA is all zeros, indicating a branch deletion. No linting required.")
        return jsonify({"msg": "Branch deleted, no linting performed."}), 200

    # Determine which linters to execute for this repository.
    # Prioritize repository-specific configuration, then fall back to global defaults.
    linters_to_run = Config.REPO_LINTER_CONFIGS.get(repo_full_name, Config.DEFAULT_LINTERS)
    if not linters_to_run:
        logger.info(f"No linters configured for repository '{repo_full_name}' or globally. Linting skipped.")
        post_commit_comment(repo_full_name, commit_sha,
                            f"Automated Linter: No linters are configured for this repository. Linting skipped for commit `{commit_sha}`.")
        return jsonify({"msg": "No linters configured for this repository."}), 200

    logger.info(f"Selected linters for '{repo_full_name}': {', '.join(linters_to_run)}")

    # Construct the repository clone URL. For private repositories, embedding the token
    # directly into the URL (HTTPS format) is a common way for `git clone` to authenticate.
    repo_clone_url = payload['repository']['clone_url']
    if 'github.com' in repo_clone_url and Config.GITHUB_TOKEN:
        # Example: https://github.com/owner/repo.git -> https://x-access-token:<TOKEN>@github.com/owner/repo.git
        repo_clone_url = repo_clone_url.replace("https://", f"https://x-access-token:{Config.GITHUB_TOKEN}@")

    temp_repo_path = None # Will store the path to the cloned repository
    try:
        # 2. Clone the repository to a temporary location
        temp_repo_path = clone_repository(repo_clone_url, commit_sha, Config.TEMP_CLONE_DIR)
        if not temp_repo_path:
            logger.error(f"Failed to clone repository '{repo_full_name}' for commit '{commit_sha}'. Linting aborted.")
            post_commit_comment(repo_full_name, commit_sha,
                                f"Automated Linter: Failed to clone repository for commit `{commit_sha}`. Linting aborted due to repository access issues.")
            return jsonify({"status": "error", "message": "Failed to clone repository"}), 500

        # 3. Identify files that were added or modified in this push.
        # We focus only on Python files.
        changed_python_files = set()
        head_commit_data = payload.get('head_commit', {})
        for file_list_key in ['added', 'modified']:
            for file_path in head_commit_data.get(file_list_key, []):
                if file_path.endswith('.py'):
                    changed_python_files.add(file_path)
        
        if not changed_python_files:
            logger.info(f"No Python files were added or modified in commit {commit_sha}. Skipping linting.")
            post_commit_comment(repo_full_name, commit_sha,
                                f"Automated Linter: No Python files modified or added in commit `{commit_sha}`. Skipping linting.")
            return jsonify({"msg": "No relevant Python files to lint in this commit."}), 200

        logger.info(f"Identified {len(changed_python_files)} Python files to lint for commit {commit_sha}.")
        
        all_violations = []
        detailed_comments = []

        # 4. Iterate through changed Python files and run selected linters
        for file_rel_path in sorted(list(changed_python_files)):
            full_file_abs_path = os.path.join(temp_repo_path, file_rel_path)
            
            if not os.path.exists(full_file_abs_path):
                logger.warning(f"File '{full_file_abs_path}' specified in webhook payload not found in cloned repo. Skipping.")
                continue

            for linter_name in linters_to_run:
                if linter_name not in Config.LINTER_COMMANDS:
                    logger.warning(f"Linter '{linter_name}' is configured but not supported by this server. Skipping for '{file_rel_path}'.")
                    detailed_comments.append(f"⚠️ **Warning**: Linter '{linter_name}' is configured but not supported by the server.")
                    continue
                
                command_args = Config.LINTER_COMMANDS[linter_name]
                
                # Execute the linter and collect any found violations
                violations_for_file, stdout, stderr = execute_linter_command(linter_name, command_args, full_file_abs_path, temp_repo_path)
                all_violations.extend(violations_for_file)
                
                if violations_for_file:
                    detailed_comments.append(f"\n--- **Linting results for `{file_rel_path}` (by {linter_name})** ---")
                    for violation in violations_for_file:
                        detailed_comments.append(f"- {violation.to_github_comment_format()}")
                else:
                    logger.info(f"No {linter_name} violations found in '{file_rel_path}'.")

        # 5. Post aggregated comments back to GitHub
        if all_violations:
            logger.info(f"Total {len(all_violations)} linting violations found across {len(changed_python_files)} files.")
            
            # Construct a summary comment for the commit
            summary_message = (
                f"### Automated Code Linter Report for commit `{commit_sha[:7]}` by @{pusher_name}\n\n"
                f"Automated Linter detected **{len(all_violations)} potential issues** "
                f"across {len(changed_python_files)} modified Python files using {', '.join(linters_to_run)}.\n\n"
                f"--- Detailed Findings ---\n"
            )
            
            # Aggregate detailed comments. GitHub comments have length limits.
            max_comment_length = 65000  # GitHub's max comment length is around 65536 characters
            current_comment_body = summary_message
            for detail_line in detailed_comments:
                if len(current_comment_body) + len(detail_line) + 2 > max_comment_length: # +2 for newline
                    current_comment_body += "\n\n... (Further details truncated due to GitHub comment length limits) ...\n"
                    break # Stop adding details if limit is approached
                current_comment_body += detail_line + "\n"
            
            current_comment_body += (
                f"\n---\n"
                f"For full context, please review the changes here: {compare_url}\n"
                f"Server logs might contain additional information."
            )

            post_commit_comment(repo_full_name, commit_sha, current_comment_body)
            logger.info("Linting process finished with violations.")
            return jsonify({"status": "success", "message": f"Linting completed. {len(all_violations)} violations found."}), 200
        else:
            logger.info(f"No linting violations found for commit {commit_sha}. All files passed.")
            post_commit_comment(repo_full_name, commit_sha,
                                f"### Automated Code Linter Report for commit `{commit_sha[:7]}` by @{pusher_name}\n\n"
                                f"All {len(changed_python_files)} modified Python files in commit `{commit_sha[:7]}` "
                                f"passed linting successfully with {', '.join(linters_to_run)}! 🎉\n\n"
                                f"Well done! No issues detected by the automated linter. Keep up the great work!\n"
                                f"--- \n"
                                f"Review changes: {compare_url}")
            logger.info("Linting process finished with no violations.")
            return jsonify({"status": "success", "message": "No linting violations found."}), 200

    except GithubException as e:
        logger.error(f"GitHub API error during push event processing for {repo_full_name}@{commit_sha}: {e}", exc_info=True)
        post_commit_comment(repo_full_name, commit_sha,
                            f"Automated Linter: An error occurred communicating with GitHub API during processing of commit `{commit_sha}`. Linting status unknown.")
        return jsonify({"status": "error", "message": "GitHub API error during linting process"}), 500
    except Exception as e:
        logger.critical(f"A critical unexpected error occurred during push event processing for {repo_full_name}@{commit_sha}: {e}", exc_info=True)
        post_commit_comment(repo_full_name, commit_sha,
                            f"Automated Linter: A critical internal error occurred while processing commit `{commit_sha}`. "
                            f"Please check the server logs for details. Error: `{e}`")
        return jsonify({"status": "error", "message": "Internal server error during linting process"}), 500
    finally:
        # Ensure temporary repository directory is always cleaned up, regardless of success or failure.
        cleanup_repository(temp_repo_path)
        logger.info(f"--- Finished linting process for push event on {repo_full_name}@{commit_sha} ---")


# --- Health Check Endpoint ---
@app.route('/health', methods=['GET'])
def health_check():
    """
    Provides a simple health check endpoint for monitoring the service.
    It reports the server's status and attempts a basic GitHub API call
    to verify connectivity and token validity.
    """
    status_report = {"status": "ok", "timestamp": datetime.now().isoformat()}
    try:
        # Attempt a lightweight GitHub API call (e.g., getting current user's login)
        # to ensure the GITHUB_TOKEN is still valid and API is reachable.
        user_login = github_client.get_user().login
        status_report["github_api_status"] = f"ok (Connected as '{user_login}')"
    except GithubException as e:
        status_report["github_api_status"] = f"error: {e.status} - {e.data.get('message', 'Unknown GitHub API error')}"
        status_report["status"] = "degraded"
        logger.error(f"Health check: GitHub API connectivity degraded: {e}")
    except Exception as e:
        status_report["github_api_status"] = f"error: {str(e)}"
        status_report["status"] = "degraded"
        logger.error(f"Health check: Unexpected error checking GitHub API: {e}", exc_info=True)
    
    # Return 200 for 'ok', 503 for 'degraded' (Service Unavailable)
    http_status_code = 200 if status_report["status"] == "ok" else 503
    return jsonify(status_report), http_status_code


# --- Main Application Entry Point ---
if __name__ == '__main__':
    logger.info("Starting Automated Code Linter Server application...")
    # This `Config.validate()` call at startup (outside the Flask route)
    # ensures that critical environment variables are checked immediately
    # when the script starts, failing fast if they are missing.
    try:
        Config.validate()
    except ValueError as e:
        logger.critical(f"FATAL: Configuration error at application startup: {e}. Exiting server.")
        sys.exit(1)

    # In a production deployment, it is highly recommended to use a production-ready
    # WSGI server (e.g., Gunicorn, uWSGI) to host the Flask application for robustness,
    # performance, and security.
    # For local development and testing, Flask's built-in development server is sufficient.
    # `debug=True` should NEVER be used in production as it can expose sensitive information.
    logger.info(f"Flask app starting on http://0.0.0.0:{Config.SERVER_PORT}")
    app.run(host='0.0.0.0', port=Config.SERVER_PORT, debug=False)
    logger.info("Automated Code Linter Server application stopped.")