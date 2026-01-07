import os
import re
import argparse
import sys
import yaml # Must specify: pip install PyYAML
import collections
import logging
from datetime import datetime

# --- Configuration Constants and Global Setup ---

# Set up basic logging for the script's execution.
# This helps in debugging and understanding the script's flow.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Third-party library requirement ---
# This script specifically requires the PyYAML library for parsing .yml and .yaml files.
# If you don't have it installed, you can install it using pip:
#   pip install PyYAML
# For Graphviz output, the 'dot' command-line tool (part of Graphviz) must be installed
# on your system to convert the generated .dot file into image formats like PNG or SVG.
# (e.g., on Ubuntu: sudo apt-get install graphviz; on macOS: brew install graphviz)

class Config:
    """
    Centralized configuration class for the microservice dependency mapper.
    This class holds all configurable patterns, file types, default settings,
    and Graphviz styling options. This makes the script easily adaptable
    to different environments and parsing requirements.
    """
    # File extensions that the scanner will look for to identify configuration files.
    # Add or remove extensions as per your application's setup.
    CONFIG_FILE_EXTENSIONS = ['.yml', '.yaml', '.properties', '.conf', '.json'] # Added .json for completeness
    
    # File extensions for service discovery or general application log files.
    LOG_FILE_EXTENSIONS = ['.log', '.txt']
    
    # Regex patterns used to identify the name of the current service within its own
    # configuration file. These are common patterns found in Spring Boot, generic apps, etc.
    SERVICE_NAME_PATTERNS = [
        re.compile(r'spring\.application\.name\s*:\s*([a-zA-Z0-9_-]+)'), # Spring Boot YAML
        re.compile(r'application\.name\s*=\s*([a-zA-Z0-9_-]+)'),       # Spring Boot Properties
        re.compile(r'"name"\s*:\s*"([a-zA-Z0-9_-]+)"'),                 # Generic JSON/YAML name
        re.compile(r'service\.id\s*=\s*([a-zA-Z0-9_-]+)'),               # Custom service ID
        re.compile(r'APP_NAME\s*=\s*([a-zA-Z0-9_-]+)')                   # Environment variable style config
    ]

    # Regex patterns for extracting dependencies from configuration files.
    # These are designed to capture URLs, service IDs, and environment variable references
    # that point to other services, databases, message queues, or external APIs.
    DEPENDENCY_PATTERNS_CONFIG = [
        # HTTP/HTTPS URLs: captures full URLs, common for REST API calls.
        re.compile(r'(https?://[a-zA-Z0-9\.-]+(?:[:][0-9]+)?(?:/[a-zA-Z0-9\./\?%&_=,;-]*)?)'),
        # JDBC connection strings: identifies database dependencies.
        re.compile(r'(jdbc:[a-zA-Z0-9]+://[a-zA-Z0-9\.-]+(?:[:][0-9]+)?(?:/[a-zA-Z0-9\._-]+(?:[?][a-zA-Z0-9&=]+)?)?)'),
        # Message queue/cache connection strings (AMQP, Kafka, Redis).
        re.compile(r'(amqp://[a-zA-Z0-9\.-]+(?:[:][0-9]+)?(?:/[a-zA-Z0-9\./]*)?)'),
        re.compile(r'(kafka://[a-zA-Z0-9\.-]+(?:[:][0-9]+)?(?:,[a-zA-Z0-9\.-]+(?:[:][0-9]+)?)?)'), # Kafka can have multiple brokers
        re.compile(r'(redis://[a-zA-Z0-9\.-]+(?:[:][0-9]+)?)'),
        # Environment variable references: common in cloud-native applications.
        # Captures patterns like ${SERVICE_A_HOST}, ${DB_URL}, ${KAFKA_BROKERS}.
        re.compile(r'\$\{([A-Z_]+(?:_HOST|_URL|_BROKERS|_ADDRESS))\b\}'),
        # Direct service name references often used in service discovery clients (e.g., Eureka).
        re.compile(r'serviceId\s*:\s*([a-zA-Z0-9_-]+)'),
        re.compile(r'host\s*:\s*([a-zA-Z0-9_-]+(?:[.][a-zA-Z0-9_-]+)*)'), # Generic host entries
        re.compile(r'target-url\s*:\s*([a-zA-Z0-9\.-]+(?:[:][0-9]+)?)') # Custom target URLs
    ]

    # Regex patterns for extracting dependencies from log files.
    # These patterns look for common phrases indicating outbound communication.
    DEPENDENCY_PATTERNS_LOG = [
        # General calls/requests to a named service or URL.
        re.compile(r'(?:calling|connecting to|sending request to|invoking service)\s+([a-zA-Z0-9_-]+(?:[.][a-zA-Z0-9_-]+)*)'),
        re.compile(r'(?:calling|connecting to|sending request to|invoking service)\s+(?:at|on|via)\s+(https?://[a-zA-Z0-9\.-]+(?:[:][0-9]+)?(?:/[a-zA-Z0-9\./\?%&_=,;-]*)?)'),
        # Message queue operations.
        re.compile(r'(?:sending message to|publishing to queue|consuming from topic)\s+([a-zA-Z0-9_-]+)'),
        # Database connections.
        re.compile(r'(?:database connection to|jdbc url detected:)\s+([a-zA-Z0-9\.-]+(?:[:][0-9]+)?(?:/[a-zA-Z0-9\._-]+)?)'),
        # Cloud service interactions (e.g., AWS S3, SQS).
        re.compile(r'(?:uploading to|downloading from)\s+(s3:\/\/[a-zA-Z0-9\.-]+)'),
        re.compile(r'(?:sending to SQS queue|receiving from SQS queue)\s+([a-zA-Z0-9_-]+)'),
    ]

    # Patterns for identifying known external APIs, cloud services, or infrastructure components.
    # These nodes will receive special styling in the Graphviz diagram.
    EXTERNAL_API_PATTERNS = [
        re.compile(r'api\.stripe\.com'),           # Stripe Payment Gateway
        re.compile(r'api\.sendgrid\.com'),          # SendGrid Email Service
        re.compile(r's3\.amazonaws\.com'),          # AWS S3 Storage
        re.compile(r'sqs\.[a-z0-9\-]+\.amazonaws\.com'), # AWS SQS Queues
        re.compile(r'rds\.[a-z0-9\-]+\.amazonaws\.com'), # AWS RDS Databases
        re.compile(r'sns\.[a-z0-9\-]+\.amazonaws\.com'), # AWS SNS
        re.compile(r'lambda\.[a-z0-9\-]+\.amazonaws\.com'), # AWS Lambda
        re.compile(r'cloudfront\.net'),             # CDN like CloudFront
        re.compile(r'google\.com/api'),             # Generic Google APIs
        re.compile(r'mockbin\.org'),                # Example external API
        # Internal infrastructure components that are not services but dependencies
        re.compile(r'kafka-cluster\.internal'),
        re.compile(r'message-broker\.internal'),
        re.compile(r'redis-cache\.internal'),
        re.compile(r'db-host\.internal'),
        re.compile(r'mysql-db\.internal'),
        re.compile(r'postgresql-db\.internal'),
        re.compile(r'mongo-db\.internal'),
    ]

    # Graphviz DOT language styling settings.
    # These control how nodes and edges are rendered in the generated diagram.
    DOT_GRAPH_NAME = "MicroserviceDependencies"
    DOT_NODE_SHAPE_SERVICE = "box"       # Shape for microservices
    DOT_NODE_SHAPE_DB = "cylinder"       # Shape for databases
    DOT_NODE_SHAPE_QUEUE = "oval"        # Shape for message queues/brokers/caches
    DOT_NODE_SHAPE_EXTERNAL = "Mdiamond" # Shape for external APIs/cloud services
    DOT_NODE_STYLE = "filled"            # Nodes will be filled with color
    DOT_NODE_FONTCOLOR = "#333333"       # Dark grey font for better readability

    # Specific fill colors for different types of nodes.
    DOT_NODE_FILLCOLOR_SERVICE = "#ADD8E6"  # LightBlue
    DOT_NODE_FILLCOLOR_DB = "#90EE90"       # LightGreen
    DOT_NODE_FILLCOLOR_QUEUE = "#FFD700"    # Gold
    DOT_NODE_FILLCOLOR_EXTERNAL = "#FF6347" # Tomato (a vibrant red-orange)

    DOT_EDGE_COLOR = "#333333"               # Dark grey for edges
    DOT_EDGE_STYLE = "solid"                # Solid lines for edges
    DOT_RANKDIR = "LR"                      # Graph layout direction: Left to Right
    DOT_GRAPH_BGCOLOR = "#F5F5F5"           # Light grey background for the entire graph

# --- Utility Functions ---

def _read_file_content(filepath: str) -> str:
    """
    Safely reads the entire content of a specified file.
    Handles potential file not found or decoding errors gracefully.

    Args:
        filepath (str): The absolute or relative path to the file.

    Returns:
        str: The complete content of the file as a string.
             Returns an empty string if the file cannot be read.
    """
    try:
        # Attempt to read with UTF-8, which is common.
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()
    except UnicodeDecodeError:
        # If UTF-8 fails, try a more lenient encoding like latin-1 (ISO-8859-1).
        logger.warning(f"Failed to decode file {filepath} with utf-8, trying latin-1.")
        try:
            with open(filepath, 'r', encoding='latin-1') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Could not read file {filepath} with latin-1: {e}")
            return ""
    except FileNotFoundError:
        logger.error(f"File not found: {filepath}")
        return ""
    except IOError as e:
        logger.error(f"IOError while reading {filepath}: {e}")
        return ""
    except Exception as e:
        logger.error(f"An unexpected error occurred while reading {filepath}: {e}")
        return ""

def _load_yaml_content(filepath: str) -> dict:
    """
    Loads and parses YAML content from a specified file.
    This function relies on the `PyYAML` library.

    Args:
        filepath (str): The path to the YAML file.

    Returns:
        dict: The parsed YAML content as a dictionary.
              Returns an empty dictionary if parsing fails or file is empty.
    """
    content = _read_file_content(filepath)
    if not content:
        logger.debug(f"No content to load for YAML file: {filepath}")
        return {}
    try:
        # Use safe_load to prevent arbitrary code execution from untrusted YAML sources.
        return yaml.safe_load(content)
    except yaml.YAMLError as e:
        logger.error(f"Error parsing YAML file {filepath}: {e}")
        return {}
    except Exception as e:
        logger.error(f"An unexpected error occurred while loading YAML from {filepath}: {e}")
        return {}

def _load_json_content(filepath: str) -> dict:
    """
    Loads and parses JSON content from a specified file.

    Args:
        filepath (str): The path to the JSON file.

    Returns:
        dict: The parsed JSON content as a dictionary.
              Returns an empty dictionary if parsing fails or file is empty.
    """
    import json # Import json dynamically as it might not always be needed.
    content = _read_file_content(filepath)
    if not content:
        logger.debug(f"No content to load for JSON file: {filepath}")
        return {}
    try:
        return json.loads(content)
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing JSON file {filepath}: {e}")
        return {}
    except Exception as e:
        logger.error(f"An unexpected error occurred while loading JSON from {filepath}: {e}")
        return {}

def _extract_service_name_from_path(filepath: str) -> str:
    """
    Attempts to infer the service name based on the file's directory structure.
    A common convention is that the service's root directory is named after the service.
    E.g., for `/path/to/my-service/src/main/resources/application.yml`, it extracts 'my-service'.

    Args:
        filepath (str): The full path to the configuration or log file.

    Returns:
        str: The extracted service name, normalized to lowercase and hyphenated.
             Defaults to "unknown_service" if a name cannot be reliably extracted.
    """
    try:
        # Get the directory containing the file.
        # Then get the name of that directory. This often corresponds to the service name.
        # Example: /path/to/my-service/application.yml -> my-service
        parent_dir = os.path.basename(os.path.dirname(filepath))
        if parent_dir and parent_dir != os.sep:
            # Normalize the name: lowercase, replace dots/spaces with hyphens.
            return parent_dir.replace('.', '-').replace(' ', '-').lower()
    except Exception as e:
        logger.debug(f"Could not extract service name from path {filepath}: {e}")
    return "unknown_service"

def _normalize_endpoint(endpoint: str) -> str:
    """
    Normalizes a raw extracted endpoint string (e.g., URL, environment variable, service ID)
    into a consistent, simplified identifier suitable for graphing.
    This function handles various cases like removing ports, paths, protocols, and converting
    known infrastructure components or external APIs into canonical names.

    Args:
        endpoint (str): The raw string representing a dependency (e.g., "http://api.example.com:8080/path?q=1").

    Returns:
        str: A simplified and normalized identifier (e.g., "example_api", "database", "kafka_cluster").
    """
    original_endpoint = endpoint
    endpoint = endpoint.strip().lower() # Standardize by stripping whitespace and lowercasing

    # Handle environment variable references (e.g., ${SERVICE_B_HOST})
    if endpoint.startswith('${') and endpoint.endswith('}'):
        env_var_name = endpoint[2:-1]
        if '_HOST' in env_var_name or '_URL' in env_var_name or '_BROKERS' in env_var_name:
            # Common patterns for service host/URL env vars
            if env_var_name.startswith('SERVICE_') and env_var_name.endswith(('_HOST', '_URL')):
                return env_var_name.replace('SERVICE_', '').replace('_HOST', '').replace('_URL', '').lower()
            elif env_var_name == 'DB_URL' or env_var_name == 'DATABASE_URL':
                return 'database'
            elif 'KAFKA' in env_var_name and 'BROKERS' in env_var_name:
                return 'kafka_cluster'
            elif 'REDIS' in env_var_name:
                return 'redis_cache'
            else:
                return env_var_name.lower() # Fallback for other relevant env vars
        else:
            return env_var_name.lower() # For other env vars, just use the name

    # Remove protocol prefixes (http://, https://, jdbc:, amqp://, etc.)
    endpoint = re.sub(r'^(https?|jdbc:[a-zA-Z0-9]+|amqp|kafka|redis|s3):\/\/', '', endpoint)

    # Remove credentials if present (e.g., user:pass@)
    endpoint = re.sub(r'[^@]+@', '', endpoint)

    # Remove specific paths, query parameters, and fragments, keeping only the base host.
    # e.g., example.com:8080/api/v1/users?id=123 -> example.com:8080
    endpoint = re.split(r'[/\?#]', endpoint)[0]

    # Remove port numbers (e.g., example.com:8080 -> example.com)
    endpoint = re.sub(r':\d+', '', endpoint)

    # Check against known external API patterns (using original endpoint for better matches)
    for pattern in Config.EXTERNAL_API_PATTERNS:
        if pattern.search(original_endpoint):
            # Map specific recognized patterns to standardized names
            if 's3.amazonaws.com' in original_endpoint: return 'aws_s3'
            if 'sqs.' in original_endpoint and 'amazonaws.com' in original_endpoint: return 'aws_sqs'
            if 'rds.' in original_endpoint and 'amazonaws.com' in original_endpoint: return 'aws_rds'
            if 'sns.' in original_endpoint and 'amazonaws.com' in original_endpoint: return 'aws_sns'
            if 'cloudfront.net' in original_endpoint: return 'cdn_service'
            if 'api.stripe.com' in original_endpoint: return 'stripe_payment_gateway'
            if 'api.sendgrid.com' in original_endpoint: return 'sendgrid_email_api'
            # Generic external identifier if a pattern matches but no specific mapping
            return f"external_{pattern.pattern.replace('.', '_').replace('\\.', '_').lower().strip('-').replace('(', '').replace(')', '')}"

    # Convert common database names/patterns to a generic 'database' node
    if any(db_keyword in endpoint for db_keyword in ['postgres', 'mysql', 'sqlserver', 'oracle', 'mongodb', 'db-host', 'database', 'rds']):
        return 'database'
    
    # Convert common message queue/broker/cache names to generic nodes
    if any(mq_keyword in endpoint for mq_keyword in ['kafka', 'broker', 'amqp', 'rabbitmq', 'pulsar']):
        return 'kafka_cluster' if 'kafka' in endpoint else 'message_broker'
    if any(cache_keyword in endpoint for cache_keyword in ['redis', 'cache', 'memcached']):
        return 'redis_cache'

    # General cleanup for service names and hostnames
    endpoint = endpoint.replace('-', '_').replace('.', '_')
    if endpoint.endswith('_host'):
        endpoint = endpoint[:-5]
    if endpoint.endswith('_url'):
        endpoint = endpoint[:-4]
    
    # If it still looks like a domain name, take the first part
    if '.' in endpoint:
        endpoint = endpoint.split('.')[0]
    
    # Remove leading/trailing underscores and ensure it's not empty
    endpoint = endpoint.strip('_')
    if not endpoint:
        logger.debug(f"Normalization resulted in empty string for '{original_endpoint}', using 'unidentified_dependency'.")
        return "unidentified_dependency"
        
    return endpoint

# --- Parsing Functions ---

def _find_dependencies_in_text(content: str, patterns: list[re.Pattern], current_service: str = "unknown_service") -> list[str]:
    """
    Scans a block of text content for known dependency patterns using a list of regexes.
    Each matched dependency is then normalized.

    Args:
        content (str): The text content (e.g., config file content, log file lines) to scan.
        patterns (list[re.Pattern]): A list of compiled regular expression patterns to apply.
        current_service (str): The name of the service being analyzed; used to prevent
                               self-dependencies and for logging context.

    Returns:
        list[str]: A list of unique, normalized dependency names found in the content.
    """
    found_dependencies = set()
    for pattern in patterns:
        for match in pattern.finditer(content):
            raw_dependency = match.group(1) # Most patterns are designed to capture the target in group 1
            if raw_dependency:
                normalized_dep = _normalize_endpoint(raw_dependency)
                # Only add if it's a valid, non-self, non-unknown dependency
                if normalized_dep and normalized_dep != current_service and \
                   normalized_dep != "unknown_service" and normalized_dep != "unidentified_dependency":
                    found_dependencies.add(normalized_dep)
                    logger.debug(f"Service '{current_service}' found raw dependency '{raw_dependency}' -> normalized to '{normalized_dep}'.")
    return list(found_dependencies)

def parse_config_file(filepath: str) -> tuple[str, list[str]]:
    """
    Parses a single configuration file (YAML, JSON, Properties) to identify
    the service it belongs to and its outgoing dependencies.

    Args:
        filepath (str): The full path to the configuration file.

    Returns:
        tuple[str, list[str]]: A tuple where the first element is the determined
                               service name, and the second is a list of its
                               normalized dependencies.
    """
    logger.info(f"Parsing configuration file: {filepath}")
    
    # Start with a service name inferred from the file path as a fallback.
    service_name = _extract_service_name_from_path(filepath)
    content = _read_file_content(filepath)

    if not content:
        logger.warning(f"No content found or readable for {filepath}. Skipping parsing for dependencies.")
        return service_name, []

    # Attempt to determine service name from content first, which is more reliable.
    for pattern in Config.SERVICE_NAME_PATTERNS:
        match = pattern.search(content)
        if match:
            extracted_name = match.group(1)
            if extracted_name:
                service_name = extracted_name.lower().replace('.', '-').replace(' ', '-')
                logger.info(f"Identified service name '{service_name}' from content of {filepath}.")
                break
    else:
        logger.info(f"Could not find explicit service name in content for {filepath}, using '{service_name}' inferred from path.")

    dependencies = set() # Use a set to collect unique dependencies

    # Handle YAML files specifically, leveraging PyYAML for structured parsing.
    if filepath.endswith(('.yml', '.yaml')):
        yaml_data = _load_yaml_content(filepath)
        if yaml_data:
            # Convert YAML data to a string for general regex matching.
            # This is effective for simpler key-value dependencies.
            dependencies.update(_find_dependencies_in_text(str(yaml_data), Config.DEPENDENCY_PATTERNS_CONFIG, service_name))
            
            # More targeted parsing for common YAML structures (e.g., Spring Boot datasource, clients).
            # This can catch dependencies that might be missed by generic regex on a stringified dict.
            if isinstance(yaml_data, dict):
                # Example: spring.datasource.url
                if 'spring' in yaml_data and isinstance(yaml_data['spring'], dict) and \
                   'datasource' in yaml_data['spring'] and isinstance(yaml_data['spring']['datasource'], dict) and \
                   'url' in yaml_data['spring']['datasource']:
                    db_url = yaml_data['spring']['datasource']['url']
                    normalized_db = _normalize_endpoint(db_url)
                    if normalized_db != service_name and normalized_db != "unknown_service" and normalized_db != "unidentified_dependency":
                        dependencies.add(normalized_db)
                        logger.debug(f"YAML direct lookup: Found datasource dependency '{db_url}' -> '{normalized_db}' for service '{service_name}'.")

                # Example: clients: { service-a: { url: ... }, service-b: { url: ... } }
                if 'clients' in yaml_data and isinstance(yaml_data['clients'], dict):
                    for client_name, client_config in yaml_data['clients'].items():
                        if isinstance(client_config, dict) and 'url' in client_config:
                            client_url = client_config['url']
                            normalized_client = _normalize_endpoint(client_url)
                            if normalized_client != service_name and normalized_client != "unknown_service" and normalized_client != "unidentified_dependency":
                                dependencies.add(normalized_client)
                                logger.debug(f"YAML direct lookup: Found client dependency '{client_url}' -> '{normalized_client}' for service '{service_name}'.")

                # Recursively search for URLs/hosts in the entire YAML structure
                # This could be a very detailed function if we want to traverse every possible nested key.
                # For brevity and performance, current approach focuses on common patterns and full-text regex.
        else:
            logger.warning(f"YAML content for {filepath} was empty or could not be loaded as dictionary.")

    # Handle JSON files similarly.
    elif filepath.endswith('.json'):
        json_data = _load_json_content(filepath)
        if json_data:
            dependencies.update(_find_dependencies_in_text(str(json_data), Config.DEPENDENCY_PATTERNS_CONFIG, service_name))
            # Similar targeted parsing for JSON structures can be added here if needed.
        else:
            logger.warning(f"JSON content for {filepath} was empty or could not be loaded as dictionary.")

    # For other config types (e.g., .properties, .conf) or as a fallback.
    # We rely solely on regex matching against the raw file content.
    dependencies.update(_find_dependencies_in_text(content, Config.DEPENDENCY_PATTERNS_CONFIG, service_name))
    
    return service_name, list(dependencies)

def parse_log_file(filepath: str, inferred_service_name: str) -> tuple[str, list[str]]:
    """
    Parses a log file to extract dependencies by looking for patterns that indicate
    outbound calls or connections made by the service that generated the log.

    Args:
        filepath (str): The full path to the log file.
        inferred_service_name (str): The name of the service, typically inferred from
                                     the log file's directory, as log files usually
                                     don't contain the service name explicitly for parsing.

    Returns:
        tuple[str, list[str]]: A tuple containing the inferred service name and a list of
                               its normalized dependencies found in the log.
    """
    logger.info(f"Parsing log file: {filepath}")
    
    content = _read_file_content(filepath)
    if not content:
        logger.warning(f"No content found or readable for {filepath}. Skipping log parsing.")
        return inferred_service_name, []

    dependencies = _find_dependencies_in_text(content, Config.DEPENDENCY_PATTERNS_LOG, inferred_service_name)
    return inferred_service_name, list(set(dependencies)) # Ensure unique dependencies

# --- Graphviz Generation Function ---

def generate_dot_graph(dependencies_map: dict[str, list[str]], output_filepath: str):
    """
    Generates a Graphviz DOT language file based on the collected service dependencies.
    This file can then be processed by the Graphviz command-line tools (e.g., `dot`)
    to render a visual diagram.

    Args:
        dependencies_map (dict[str, list[str]]): A dictionary where keys are source
                                                 service names and values are lists of
                                                 the normalized services/APIs they depend on.
        output_filepath (str): The full path where the generated `.dot` file will be saved.
    """
    logger.info(f"Generating Graphviz DOT file: {output_filepath}")

    # Start the DOT file content with graph declaration and global settings.
    dot_content_lines = [
        f'digraph "{Config.DOT_GRAPH_NAME}" {{',
        f'  rankdir="{Config.DOT_RANKDIR}";', # Layout direction (e.g., LR for Left to Right)
        f'  bgcolor="{Config.DOT_GRAPH_BGCOLOR}";', # Background color of the graph
        '  node [fontname="Helvetica", fontsize=10, fontcolor="' + Config.DOT_NODE_FONTCOLOR + '"];',
        '  edge [fontname="Helvetica", fontsize=9, color="' + Config.DOT_EDGE_COLOR + '", style="' + Config.DOT_EDGE_STYLE + '"];',
        '', # Empty line for readability
    ]

    # Collect all unique nodes (both services and their dependencies) that will appear in the graph.
    all_nodes = set(dependencies_map.keys())
    for deps_list in dependencies_map.values():
        all_nodes.update(deps_list)
    
    # Define individual nodes with appropriate shapes, colors, and labels based on their type.
    node_definitions = []
    for node in sorted(list(all_nodes)):
        node_label = node.replace('_', ' ').title() # Make node labels human-readable (e.g., "user_service" -> "User Service")

        shape = Config.DOT_NODE_SHAPE_SERVICE
        fillcolor = Config.DOT_NODE_FILLCOLOR_SERVICE

        # Apply specific styling for different types of dependencies.
        if node == 'database' or 'db' in node:
            shape = Config.DOT_NODE_SHAPE_DB
            fillcolor = Config.DOT_NODE_FILLCOLOR_DB
        elif node in ['kafka_cluster', 'message_broker', 'redis_cache'] or 'queue' in node or 'broker' in node:
            shape = Config.DOT_NODE_SHAPE_QUEUE
            fillcolor = Config.DOT_NODE_FILLCOLOR_QUEUE
        elif node.startswith('external_') or node.startswith('aws_') or \
             any(p.search(node.replace('_', '.')) for p in Config.EXTERNAL_API_PATTERNS): # Check patterns against original-like string
            shape = Config.DOT_NODE_SHAPE_EXTERNAL
            fillcolor = Config.DOT_NODE_FILLCOLOR_EXTERNAL

        node_definitions.append(
            f'  "{node}" [label="{node_label}", shape="{shape}", style="{Config.DOT_NODE_STYLE}", fillcolor="{fillcolor}"];'
        )
    
    dot_content_lines.extend(sorted(node_definitions)) # Add node definitions, sorted for consistent output.
    dot_content_lines.append('')

    # Add edges representing the dependencies between services/APIs.
    edge_definitions = []
    for service, dependencies in sorted(dependencies_map.items()):
        for dep in sorted(dependencies):
            edge_definitions.append(f'  "{service}" -> "{dep}";')
    
    dot_content_lines.extend(edge_definitions)
    dot_content_lines.append('}') # Close the digraph block.

    # Write the generated DOT content to the specified output file.
    try:
        # Ensure the output directory exists.
        output_dir = os.path.dirname(output_filepath)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            
        with open(output_filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(dot_content_lines))
        logger.info(f"Graphviz DOT file successfully saved to: {output_filepath}")
        logger.info("To render this graph to an image (e.g., PNG, SVG), you need the Graphviz command-line tool.")
        logger.info(f"Example command: dot -Tpng {output_filepath} -o {output_filepath.replace('.dot', '.png')}")
        logger.info(f"Alternatively for SVG: dot -Tsvg {output_filepath} -o {output_filepath.replace('.dot', '.svg')}")
    except IOError as e:
        logger.error(f"Failed to write DOT file to {output_filepath}: {e}")
    except Exception as e:
        logger.error(f"An unexpected error occurred during DOT file generation: {e}")

# --- Main Script Execution ---

def setup_mock_data(base_path="mock_data"):
    """
    Sets up a mock directory structure with example config and log files.
    This function makes the script immediately runnable for demonstration purposes,
    without requiring existing application data.
    """
    logger.info(f"Setting up mock data in '{base_path}' for demonstration.")

    # Define a set of mock microservices, their configurations, and log entries.
    mock_services = {
        "user-service": {
            "application.yml": """
spring:
  application:
    name: user-service
  datasource:
    url: jdbc:postgresql://db-host.internal:5432/user_db
  kafka:
    bootstrap-servers: kafka-cluster.internal:9092,kafka-cluster.internal:9093
    topic: user-events
  clients:
    order-service:
      url: http://order-service-host:8080/api/orders
    payment-gateway:
      url: https://api.payment-gateway.com/v1/payments
    notification-service:
      url: ${NOTIFICATION_SERVICE_URL} # Environment variable reference
    storage-service:
      s3-bucket-url: https://my-user-files.s3.amazonaws.com
""",
            "user-service.log": f"""
2023-10-27 10:00:01 INFO  [user-service] Starting User Service.
2023-10-27 10:00:05 INFO  [user-service] Successfully connected to database: db-host.internal
2023-10-27 10:00:10 DEBUG [user-service] Calling order-service-host:8080/api/orders/user/123 to fetch orders.
2023-10-27 10:00:15 INFO  [user-service] Publishing message to topic user-events on kafka-cluster.internal for analytics.
2023-10-27 10:00:20 INFO  [user-service] Invoking service at https://api.payment-gateway.com/v1/payments for user transaction.
2023-10-27 10:00:25 ERROR [user-service] Could not reach notification_service due to network issue.
2023-10-27 10:00:30 INFO  [user-service] Uploading user profile to s3://my-user-files-bucket.
"""
        },
        "order-service": {
            "application.yaml": """
application.name: order-service
server.port: 8080
dependencies:
  user-service-api: http://user-service-host:8081/api/users
  product-service-api: http://product-service:8080/products
  inventory-service:
    url: http://inventory-service-internal:8080/stock
  redis-cache-url: redis://redis-cache.internal:6379
  stripe-payment: https://api.stripe.com/v1/charges # Another external API example
  notification-queue:
    type: SQS
    name: order-notifications-queue # SQS Queue name
""",
            "order-service.log": f"""
2023-10-27 10:05:01 INFO  [order-service] Initializing Order Service.
2023-10-27 10:05:03 DEBUG [order-service] Fetching user data from user-service-host:8081 for order processing.
2023-10-27 10:05:08 INFO  [order-service] Sending request to product-service for product details for order 12345.
2023-10-27 10:05:12 WARNING [order-service] Failed to connect to inventory-service-internal.
2023-10-27 10:05:18 INFO  [order-service] Storing order data in redis-cache.internal.
2023-10-27 10:05:22 INFO  [order-service] Sending to SQS queue order-notifications-queue.
"""
        },
        "product-service": {
            "application.yml": """
name: product-service
db.url: jdbc:mysql://mysql-db.internal:3306/product_db
kafka.broker: ${KAFKA_BROKERS} # Another env var reference
search.service.url: http://search-service:8090/query
cdn.endpoint: https://product-images.cloudfront.net # CDN dependency
""",
            "product-service.log": f"""
2023-10-27 10:10:01 INFO  [product-service] Product Service is up.
2023-10-27 10:10:05 INFO  [product-service] Database connection to mysql-db.internal established.
2023-10-27 10:10:10 DEBUG [product-service] Querying search-service at http://search-service:8090 for product categorization.
"""
        },
        "notification-service": {
            "application.yaml": """
name: notification-service
email.service.api: https://api.sendgrid.com/v3/mail/send
sms.gateway.url: https://sms.example.com/api/send # External SMS gateway
metrics.endpoint: http://prometheus:9090 # Monitoring system
""",
        },
        "inventory-service": {
            "application.properties": """
app.name=inventory-service
db.host=inventory-db-host
db.port=5432
db.name=inventory_db
stock.service.url=http://stock-api.internal:8080
""",
        },
        "search-service": {
            "application.json": """
{
  "name": "search-service",
  "search": {
    "engine": "elasticsearch",
    "endpoint": "http://elasticsearch-cluster:9200"
  },
  "data_source": {
    "product_sync_api": "http://product-service:8080/products/sync"
  }
}
""",
        }
    }

    # Ensure the base directory for mock data exists.
    os.makedirs(base_path, exist_ok=True)

    # Create the mock service directories and their respective configuration/log files.
    for service_dir, files in mock_services.items():
        service_path = os.path.join(base_path, service_dir)
        os.makedirs(service_path, exist_ok=True)
        for filename, content in files.items():
            filepath = os.path.join(service_path, filename)
            try:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content.strip())
                logger.debug(f"Created mock file: {filepath}")
            except Exception as e:
                logger.error(f"Error creating mock file {filepath}: {e}")
    logger.info("Mock data setup complete.")


def main():
    """
    The main execution function of the microservice-dependency-mapper script.
    It handles argument parsing, directory scanning, file parsing, and graph generation.
    """
    parser = argparse.ArgumentParser(
        description="Microservice Dependency Mapper: Automatically generates a Graphviz DOT diagram "
                    "showing dependencies between microservices and APIs by parsing "
                    "configuration and log files."
    )
    # Argument for specifying the root directory to scan.
    parser.add_argument(
        '--path',
        type=str,
        default='.', # Default to current directory
        help='The root directory to scan for microservice configuration and log files. '
             'Defaults to the current directory (e.g., "./my_app_root").'
    )
    # Argument for specifying the output file path for the Graphviz DOT file.
    parser.add_argument(
        '--output',
        type=str,
        default='dependencies_graph.dot', # Default output file name
        help='The output file path for the Graphviz DOT file. '
             'Defaults to "dependencies_graph.dot" in the current directory. '
             'The script will create parent directories if they do not exist.'
    )
    # Flag to skip setting up mock data. Useful when running against real data.
    parser.add_argument(
        '--skip-mock-data',
        action='store_true',
        help='If set, the script will skip creating mock data and only process files '
             'found in the specified --path. Use this if you have your own data structure.'
    )
    # Flag to enable verbose logging for detailed debugging.
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging for detailed debugging output, showing more '
             'information about file processing and dependency extraction.'
    )

    args = parser.parse_args()

    # Adjust logging level based on --verbose flag.
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled.")

    scan_path = args.path
    if not args.skip_mock_data:
        # If mock data is not skipped, create it and set the scan path to the mock data directory.
        mock_data_path = os.path.join(os.getcwd(), "mock_data")
        setup_mock_data(mock_data_path)
        scan_path = mock_data_path # Use mock data path for scanning

    # Validate the scan path.
    if not os.path.isdir(scan_path):
        logger.error(f"Error: The specified path '{scan_path}' is not a valid directory or does not exist.")
        sys.exit(1)

    logger.info(f"Starting scan for configuration and log files in: {scan_path}")

    # Use collections.defaultdict to easily aggregate dependencies for each service.
    # Key: service_name, Value: list of dependencies.
    dependencies_map = collections.defaultdict(list)
    # Keep track of all identified services, even those without outgoing dependencies.
    all_identified_services = set()

    # Traverse the directory tree to find all relevant configuration and log files.
    found_files_count = 0
    for root, _, files in os.walk(scan_path):
        for filename in files:
            filepath = os.path.join(root, filename)
            found_files_count += 1

            # Process configuration files.
            if any(filename.endswith(ext) for ext in Config.CONFIG_FILE_EXTENSIONS):
                try:
                    service, deps = parse_config_file(filepath)
                    if service and service != "unknown_service":
                        all_identified_services.add(service)
                        if deps:
                            dependencies_map[service].extend(deps)
                            logger.debug(f"Config for '{service}' found dependencies: {deps}")
                        else:
                            logger.debug(f"Config for '{service}' found no explicit dependencies or was empty.")
                    else:
                        logger.warning(f"Could not determine a valid service name for config file: {filepath}")
                except Exception as e:
                    logger.error(f"Error processing config file {filepath}: {e}", exc_info=args.verbose)

            # Process log files.
            elif any(filename.endswith(ext) for ext in Config.LOG_FILE_EXTENSIONS):
                # For log files, the service name is often inferred from the directory structure.
                inferred_service_name = _extract_service_name_from_path(filepath)
                if inferred_service_name == "unknown_service":
                    logger.debug(f"Skipping log file {filepath} as service name could not be inferred from its path.")
                    continue
                
                try:
                    service, deps = parse_log_file(filepath, inferred_service_name)
                    if service and service != "unknown_service":
                        all_identified_services.add(service)
                        if deps:
                            dependencies_map[service].extend(deps)
                            logger.debug(f"Log for '{service}' found dependencies: {deps}")
                        else:
                            logger.debug(f"Log for '{service}' found no explicit dependencies or was empty.")
                except Exception as e:
                    logger.error(f"Error processing log file {filepath}: {e}", exc_info=args.verbose)

    if not all_identified_services:
        logger.warning(f"No services or dependencies were identified after scanning {found_files_count} files in '{scan_path}'. "
                       "The generated graph will be empty or minimal. Please check your patterns and file structure.")
        sys.exit(0) # Exit gracefully if nothing was found to graph.

    # Post-processing: Filter out self-dependencies and ensure unique dependencies per service.
    final_dependencies = {}
    for service in all_identified_services:
        # Start with dependencies found for this service.
        deps = dependencies_map.get(service, [])
        # Filter out self-loops (a service depending on itself) and keep only unique dependencies.
        unique_and_external_deps = sorted(list(set(d for d in deps if d != service)))
        
        # Add the service to final_dependencies. Even if it has no outgoing dependencies,
        # it will still appear as a node in the graph.
        final_dependencies[service] = unique_and_external_deps

    # Final check if any actual nodes are present for the graph.
    if not final_dependencies:
        logger.error("No valid services or dependencies were identified for the graph after post-processing. "
                     "This might indicate all found dependencies were self-references or invalid.")
        sys.exit(1)

    # Generate the Graphviz DOT file using the processed dependencies.
    generate_dot_graph(final_dependencies, args.output)
    logger.info("Dependency mapping process completed successfully.")

if __name__ == '__main__':
    # Entry point for the script.
    main()