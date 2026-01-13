# geocoding-api.py

# Standard library imports
import os
import sys
import json
import logging
import time
import re # For input validation/sanitization and string cleaning

# Third-party library imports
# Specify strictly necessary 3rd party libs:
# Flask: Web framework for creating the API endpoints.
# geopy: Library for geocoding services, specifically using Nominatim.
#
# To install these required libraries, use pip:
# pip install Flask geopy

from flask import Flask, request, jsonify, abort
from geopy.geocoders import Nominatim
from geopy.extra.rate_limiter import RateLimiter
from geopy.exc import (
    GeocoderServiceError,
    GeocoderTimedOut,
    GeocoderUnavailable,
    ConfigurationError,
    # GeocoderAuthenticationError could be used if a paid service requiring
    # authentication was chosen instead of Nominatim.
)

# --- Configuration Section ---
# This section defines various configuration parameters for the application.
# It prioritizes environment variables for deployment flexibility and provides
# sensible default values for local development. These configurations control
# the Flask server behavior, geocoding service interaction, and logging.

# Application Name - Used for logging and identifying the service.
# Defaults to "GeocodingAPI" if not set via environment variable.
APP_NAME = os.getenv("APP_NAME", "GeocodingAPI")

# Flask Application Settings
# FLASK_HOST: The IP address the Flask server will listen on.
#             "0.0.0.0" makes it accessible from any IP, useful in Docker/cloud.
#             Defaults to "0.0.0.0".
FLASK_HOST = os.getenv("FLASK_HOST", "0.0.0.0")
# FLASK_PORT: The port number the Flask server will listen on.
#             Defaults to 5000.
FLASK_PORT = int(os.getenv("FLASK_PORT", 5000))
# FLASK_DEBUG: Enables/disables Flask's debug mode.
#              Should be 'False' in production environments for security and performance.
#              Converts string environment variable ('true', '1', 't') to boolean.
FLASK_DEBUG = os.getenv("FLASK_DEBUG", "False").lower() in ("true", "1", "t")

# Geocoding Service Configuration (geopy with Nominatim)
# GEO_USER_AGENT: A unique user agent string is REQUIRED by Nominatim's usage policy.
#                 It helps identify your application and provides contact information
#                 in case of issues. Using a unique string avoids being blocked.
#                 Example: YourAppName/1.0 (your_email@example.com)
GEO_USER_AGENT = os.getenv("GEO_USER_AGENT", f"{APP_NAME}-Service/1.0 (contact@example.com)")

# Rate Limiting Configuration for geopy
# Nominatim has usage policies. It's crucial to respect them to avoid being blocked
# (e.g., typically max 1 request per second).
# GEO_RATE_LIMIT_DELAY: The minimum time in seconds to wait between consecutive geocoding requests.
#                       A delay of 1 second (1.0) is generally recommended for Nominatim.
GEO_RATE_LIMIT_DELAY = float(os.getenv("GEO_RATE_LIMIT_DELAY", 1.0))
# GEO_RATE_LIMIT_RETRIES: Maximum number of times to retry a geocoding request if it
#                         fails due to transient errors (e.g., network issues, rate limits).
GEO_RATE_LIMIT_RETRIES = int(os.getenv("GEO_RATE_LIMIT_RETRIES", 3))
# GEO_TIMEOUT_SECONDS: Timeout for individual geocoding requests in seconds.
#                      If the geocoding service doesn't respond within this time,
#                      a GeocoderTimedOut exception is raised.
GEO_TIMEOUT_SECONDS = int(os.getenv("GEO_TIMEOUT_SECONDS", 10))

# Logging Configuration
# LOG_LEVEL: Defines the minimum logging level. Messages below this level will be ignored.
#            Options: DEBUG, INFO, WARNING, ERROR, CRITICAL. Defaults to INFO.
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
# LOG_FILE_PATH: Optional path to a log file. If set, logs will be written to this file
#                in addition to stdout. If None, only console logging is used.
LOG_FILE_PATH = os.getenv("LOG_FILE_PATH", None) # Example: "geocoding_service.log"
# LOG_FILE_MAX_BYTES: Maximum size of a log file before it's rotated (in bytes).
#                     Defaults to 10 MB (10 * 1024 * 1024 bytes).
LOG_FILE_MAX_BYTES = int(os.getenv("LOG_FILE_MAX_BYTES", 10 * 1024 * 1024))
# LOG_FILE_BACKUP_COUNT: Number of backup log files to keep during rotation.
#                        Defaults to 5.
LOG_FILE_BACKUP_COUNT = int(os.getenv("LOG_FILE_BACKUP_COUNT", 5))

# --- Logging Setup ---
# This function configures the Python logging system to provide detailed insights
# into the application's operation, including information, warnings, and errors.
def setup_logging():
    """
    Configures the application's logging system.
    Sets up a root logger with a console handler and an optional file handler.
    Log messages include timestamp, log level, module, function name, and the message itself.

    Returns:
        logging.Logger: The configured logger instance.
    """
    # Create a logger instance for the application. Using __name__ ensures
    # a logger specific to this module.
    logger = logging.getLogger(__name__)
    # Set the logging level based on the LOG_LEVEL configuration.
    logger.setLevel(LOG_LEVEL)

    # Define a consistent formatter for log messages.
    # It includes timestamp, logger name, log level, the function that logged the message,
    # and the actual message.
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(funcName)s - %(message)s"
    )

    # Console Handler: Logs messages to standard output (stdout).
    # This is typically where logs go in containerized environments.
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(LOG_LEVEL) # Console handler respects general log level
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # Optional File Handler: Logs messages to a file.
    # Uses RotatingFileHandler to manage log file size and rotation, preventing
    # a single log file from consuming too much disk space.
    if LOG_FILE_PATH:
        try:
            from logging.handlers import RotatingFileHandler
            file_handler = RotatingFileHandler(
                LOG_FILE_PATH,
                maxBytes=LOG_FILE_MAX_BYTES,      # Max size before rotation
                backupCount=LOG_FILE_BACKUP_COUNT # Number of old log files to keep
            )
            file_handler.setLevel(LOG_LEVEL) # File handler also respects general log level
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
            logger.info(f"Logging to file: {LOG_FILE_PATH}")
        except Exception as e:
            # If file logging setup fails, log the error and proceed without it.
            logger.error(f"Failed to set up file logging: {e}")
            logger.warning("Proceeding without file logging.")
    else:
        logger.info("File logging is not enabled (LOG_FILE_PATH not set).")

    # Prevent duplicate logs from propagating to the root logger's handlers,
    # which could happen if Flask or other libraries also configure logging.
    logger.propagate = False
    return logger

# Initialize the application-wide logger immediately after setup.
logger = setup_logging()
logger.info(f"{APP_NAME} service initializing...")

# --- Geocoding Service Initialization ---
# This section sets up the geocoding client using geopy and Nominatim.
# It includes robust error handling for initialization and integrates
# a RateLimiter to adhere to Nominatim's usage policies.

try:
    # Initialize the Nominatim geocoder.
    # The 'user_agent' is a critical parameter and identifies your application
    # to the Nominatim service. It must be unique and descriptive.
    # 'timeout' sets the maximum time to wait for a response from the Nominatim server.
    geolocator = Nominatim(user_agent=GEO_USER_AGENT, timeout=GEO_TIMEOUT_SECONDS)

    # Wrap the geolocator's `geocode` method with RateLimiter.
    # This decorator ensures that there is a minimum delay between calls and
    # handles retries for transient failures, preventing overuse of the Nominatim API.
    geocoder = RateLimiter(geolocator.geocode,
                           min_delay_seconds=GEO_RATE_LIMIT_DELAY,
                           max_retries=GEO_RATE_LIMIT_RETRIES)
    
    # Wrap the geolocator's `reverse` method separately with RateLimiter.
    # This allows for consistent rate limiting across both forward and reverse geocoding operations.
    reverse_geocoder = RateLimiter(geolocator.reverse,
                                   min_delay_seconds=GEO_RATE_LIMIT_DELAY,
                                   max_retries=GEO_RATE_LIMIT_RETRIES)

    logger.info("Geocoding service (Nominatim with RateLimiter) initialized successfully.")
    logger.info(f"Rate limiting configured: min_delay={GEO_RATE_LIMIT_DELAY}s, max_retries={GEO_RATE_LIMIT_RETRIES}.")
    logger.info(f"Geocoding request timeout set to {GEO_TIMEOUT_SECONDS} seconds.")

except ConfigurationError as e:
    # Catch specific geopy configuration errors, which often point to issues
    # with the user_agent or other initial settings.
    logger.critical(f"Geocoder configuration error: {e}. Please check GEO_USER_AGENT and other geopy settings.")
    sys.exit(1) # Exit the application if the geocoder cannot be configured.
except Exception as e:
    # Catch any other unexpected errors during geocoder initialization.
    logger.critical(f"Failed to initialize geocoding service: {e}", exc_info=True)
    sys.exit(1) # Exit if the geocoding service cannot be made ready.

# --- Flask Application Setup ---
# Initialize the Flask application instance.
app = Flask(__name__)

# Set Flask's secret key for session management and security.
# In a production environment, this should be a strong, randomly generated value
# obtained from a secure source (e.g., environment variable, secrets manager)
# and NEVER hardcoded or committed to source control.
app.secret_key = os.getenv("FLASK_SECRET_KEY", "super_secret_dev_key_do_not_use_in_prod_12345")
if app.secret_key == "super_secret_dev_key_do_not_use_in_prod_12345" and not FLASK_DEBUG:
    logger.warning("Using default FLASK_SECRET_KEY. Please set a strong, unique secret key from an environment variable in production.")

# --- Helper Functions for Validation and Response Formatting ---
# These functions aid in robust input validation and consistent API response generation.

def is_valid_coordinate(coord_str, coord_type):
    """
    Validates if a string represents a valid latitude or longitude.
    Latitude must be between -90.0 and 90.0 degrees.
    Longitude must be between -180.0 and 180.0 degrees.

    Args:
        coord_str (str): The string to validate, expected to be a numeric value.
        coord_type (str): Specifies 'latitude' or 'longitude' to apply correct validation range.

    Returns:
        float or None: The validated float coordinate if valid, otherwise None.
    """
    if not isinstance(coord_str, str):
        logger.debug(f"Invalid coordinate type for {coord_type}: {type(coord_str)}. Expected string.")
        return None
    try:
        coord = float(coord_str)
        if coord_type == 'latitude':
            if -90.0 <= coord <= 90.0:
                return coord
            else:
                logger.warning(f"Invalid latitude value: {coord}. Must be between -90 and 90.")
        elif coord_type == 'longitude':
            if -180.0 <= coord <= 180.0:
                return coord
            else:
                logger.warning(f"Invalid longitude value: {coord}. Must be between -180 and 180.")
        else:
            # This case should ideally not be hit if coord_type is controlled by calling code.
            logger.error(f"Unknown coordinate type for validation: {coord_type}")
        return None # Coordinate out of range or unknown type
    except ValueError:
        # Catches errors if coord_str cannot be converted to a float.
        logger.warning(f"Invalid numeric format for {coord_type}: '{coord_str}'")
        return None

def sanitize_address_input(address):
    """
    Sanitizes the input address string to remove extraneous whitespace and limit length.
    This helps in providing cleaner input to the geocoding service and can mitigate
    some basic forms of invalid input.

    Args:
        address (str): The raw address string provided by the client.

    Returns:
        str: The sanitized address string. Returns an empty string if input is not a string
             or becomes empty after sanitization.
    """
    if not isinstance(address, str):
        logger.warning(f"Address input is not a string: {type(address)}. Returning empty string.")
        return "" # Return empty string for non-string inputs

    # Remove leading/trailing whitespace.
    sanitized = address.strip()
    # Replace multiple spaces with a single space to normalize formatting.
    sanitized = re.sub(r'\s+', ' ', sanitized)

    # Implement a length limit to prevent excessively long requests to the geocoding service.
    # While Nominatim might handle long strings, extremely long ones can indicate malicious
    # input or a client error.
    MAX_ADDRESS_LENGTH = 500
    if len(sanitized) > MAX_ADDRESS_LENGTH:
        logger.warning(f"Address string is too long (>{MAX_ADDRESS_LENGTH} chars), truncating.")
        sanitized = sanitized[:MAX_ADDRESS_LENGTH]

    return sanitized

def create_json_response(data, status_code=200, message="Success", error_code=None):
    """
    Creates a standardized JSON response dictionary for API endpoints.
    Ensures consistent structure for both success and error responses.

    Args:
        data (dict): The main data payload for a successful response. Can be None for errors.
        status_code (int): The HTTP status code to be returned with the response.
        message (str): A human-readable message about the response (e.g., "Address geocoded successfully.").
        error_code (str, optional): An application-specific error code (e.g., "BAD_REQUEST", "NO_RESULTS")
                                    if an error occurred. If present, sets status to "error".

    Returns:
        tuple: A tuple containing the Flask `jsonify` object and the HTTP status code.
    """
    response_payload = {
        "status": "success" if error_code is None else "error",
        "code": status_code,
        "message": message,
        "timestamp": int(time.time()), # Unix timestamp for when the response was generated
    }
    if error_code:
        response_payload["error_code"] = error_code
    if data:
        response_payload["data"] = data

    return jsonify(response_payload), status_code

# --- Flask Error Handlers ---
# These functions define how the API responds to common HTTP errors that might
# be raised by Flask (e.g., `abort()`) or occur internally.

@app.errorhandler(400)
def bad_request_error(error):
    """
    Handler for HTTP 400 Bad Request errors.
    This typically occurs due to invalid input from the client (e.g., missing parameters,
    malformed data).
    """
    # Log the specific description provided when `abort(400, description=...)` is called.
    logger.warning(f"Bad Request (400): {error.description} - Client IP: {request.remote_addr}")
    return create_json_response(None, 400, "Bad Request: " + error.description, "BAD_REQUEST")

@app.errorhandler(404)
def not_found_error(error):
    """
    Handler for HTTP 404 Not Found errors.
    This occurs when a client requests a URL endpoint that does not exist on the server.
    """
    logger.warning(f"Not Found (404): No handler for {request.method} {request.path} - Client IP: {request.remote_addr}")
    return create_json_response(None, 404, "Not Found: The requested URL was not found on the server.", "NOT_FOUND")

@app.errorhandler(405)
def method_not_allowed_error(error):
    """
    Handler for HTTP 405 Method Not Allowed errors.
    This occurs when a request is made to an existing endpoint with an unsupported HTTP method
    (e.g., POST to a GET-only endpoint).
    """
    logger.warning(f"Method Not Allowed (405): {request.method} on {request.path} - Client IP: {request.remote_addr}")
    return create_json_response(None, 405, "Method Not Allowed: The method is not allowed for the requested URL.", "METHOD_NOT_ALLOWED")


@app.errorhandler(500)
def internal_server_error(error):
    """
    Handler for HTTP 500 Internal Server Error.
    This is a catch-all for any unhandled exceptions in the application logic.
    It logs the full traceback to aid in debugging.
    """
    # Log the full exception traceback for debugging.
    # sys.exc_info() provides (type, value, traceback) which logger.exception uses.
    logger.exception(f"Internal Server Error (500) caught by handler: {error.description if hasattr(error, 'description') else str(error)} - Client IP: {request.remote_addr}")
    return create_json_response(None, 500, "Internal Server Error: An unexpected error occurred.", "INTERNAL_SERVER_ERROR")

# --- API Endpoints ---
# These are the core functionalities of the web service, exposing geocoding capabilities.

@app.route('/health', methods=['GET'])
def health_check():
    """
    Provides a simple health check endpoint for the service.
    This endpoint can be used by load balancers, container orchestrators,
    or monitoring systems to verify that the service is running and responsive.
    In an advanced scenario, it could also check connectivity to the external geocoding service.
    """
    logger.debug("Health check requested.")
    # For a simple health check, we verify that the geolocator object was initialized.
    # A more thorough check might involve a very light, known geocoding call,
    # but this can be costly for frequent checks due to rate limits.
    try:
        if geolocator is None:
            # If for some reason geolocator failed to initialize but the app didn't exit.
            raise RuntimeError("Geocoding service object not initialized.")

        # Optionally, attempt a very basic, non-rate-limited call if available,
        # or use a mock for rapid health checks. For Nominatim, any call counts.
        # If we wanted to test actual connectivity without hitting rate limits aggressively,
        # we might implement a separate periodic check and store its status.
        # For this example, just checking object existence is sufficient for "up" status.

        return create_json_response({"status": "healthy", "service_name": APP_NAME, "version": "1.0"}, 200, "Service is up and running.")
    except Exception as e:
        logger.error(f"Health check failed due to geocoding service initialization issue: {e}", exc_info=True)
        # Return 503 Service Unavailable if the core geocoding component is not ready.
        return create_json_response({"status": "unhealthy", "error": str(e)}, 503, "Service is degraded or unhealthy.", "SERVICE_DEGRADED")


@app.route('/geocode/address', methods=['GET'])
def geocode_address():
    """
    Endpoint for forward geocoding: converts a human-readable street address
    into its corresponding latitude and longitude coordinates.

    Query Parameters:
        address (str): The street address string to be geocoded. (Required)

    Example Request:
        GET /geocode/address?address=1600 Amphitheatre Pkwy, Mountain View, CA

    Returns:
        JSON response containing the geocoded coordinates and found address details,
        or an error message if the address cannot be geocoded or parameters are invalid.
    """
    logger.info(f"Received request for address geocoding from {request.remote_addr}.")

    # 1. Parameter Extraction and Validation
    address = request.args.get('address')
    if not address:
        logger.warning(f"Address parameter is missing in geocode/address request from {request.remote_addr}.")
        # Use Flask's abort to trigger the 400 error handler.
        abort(400, description="The 'address' query parameter is required.")

    # Sanitize the input address string to improve robustness and prevent issues.
    sanitized_address = sanitize_address_input(address)
    if not sanitized_address:
        logger.warning(f"Sanitized address is empty after processing original: '{address}' from {request.remote_addr}.")
        abort(400, description="Provided address is invalid or empty after sanitization.")

    logger.debug(f"Attempting to geocode sanitized address: '{sanitized_address}'")

    # 2. Geocoding Logic using geopy
    try:
        # Perform the geocoding request using the rate-limited geocoder.
        # The RateLimiter automatically handles delays and retries as configured.
        location = geocoder(sanitized_address)

        if location:
            # If a location is found, extract relevant details.
            response_data = {
                "input_address": address,         # The original address provided by the user.
                "found_address": location.address, # The standardized address returned by Nominatim.
                "latitude": location.latitude,
                "longitude": location.longitude,
                "details": location.raw           # Raw data from Nominatim for more extensive information.
            }
            logger.info(f"Successfully geocoded '{sanitized_address}' to ({location.latitude}, {location.longitude}).")
            return create_json_response(response_data, 200, "Address successfully geocoded.")
        else:
            # No results found for the given address.
            logger.info(f"No geocoding results found for address: '{sanitized_address}'.")
            return create_json_response(
                {"input_address": address, "message": "No results found for the given address."},
                404, "No geocoding results found.", "NO_RESULTS_FOUND"
            )

    except (GeocoderTimedOut, GeocoderUnavailable) as e:
        # Handle issues related to the geocoding service itself (e.g., service being down,
        # network partition, or request timing out before a response is received).
        logger.error(f"Geocoding service error (timeout/unavailable) for '{sanitized_address}': {e}", exc_info=True)
        return create_json_response(
            None, 503, "Geocoding service currently unavailable or timed out. Please try again later.", "GEO_SERVICE_UNAVAILABLE"
        )
    except GeocoderServiceError as e:
        # Catch more general geocoding service errors, which might include API usage limits,
        # malformed requests not caught by local validation, or other server-side issues.
        logger.error(f"General geocoding service error for '{sanitized_address}': {e}", exc_info=True)
        return create_json_response(
            None, 500, f"An error occurred with the geocoding service: {str(e)}", "GEO_SERVICE_ERROR"
        )
    except Exception as e:
        # Catch any other unexpected errors during the geocoding process.
        # This is a fallback for unanticipated issues.
        logger.exception(f"An unexpected error occurred during geocoding for '{sanitized_address}'.")
        return create_json_response(
            None, 500, f"An unexpected error occurred: {str(e)}", "UNEXPECTED_ERROR"
        )


@app.route('/geocode/reverse', methods=['GET'])
def reverse_geocode():
    """
    Endpoint for reverse geocoding: converts latitude and longitude coordinates
    into the nearest human-readable street address.

    Query Parameters:
        latitude (float): The latitude coordinate. (Required, range -90 to 90)
        longitude (float): The longitude coordinate. (Required, range -180 to 180)

    Example Request:
        GET /geocode/reverse?latitude=34.0522&longitude=-118.2437

    Returns:
        JSON response containing the reverse-geocoded address and its coordinates,
        or an error message if no address is found or parameters are invalid.
    """
    logger.info(f"Received request for reverse geocoding from {request.remote_addr}.")

    # 1. Parameter Extraction and Validation
    latitude_str = request.args.get('latitude')
    longitude_str = request.args.get('longitude')

    if not latitude_str or not longitude_str:
        logger.warning(f"Missing 'latitude' or 'longitude' parameters in reverse geocoding request from {request.remote_addr}.")
        abort(400, description="'latitude' and 'longitude' query parameters are required.")

    # Validate and convert latitude and longitude strings to floats.
    latitude = is_valid_coordinate(latitude_str, 'latitude')
    longitude = is_valid_coordinate(longitude_str, 'longitude')

    if latitude is None:
        logger.warning(f"Invalid 'latitude' value received: '{latitude_str}' from {request.remote_addr}.")
        abort(400, description=f"Invalid 'latitude' value: '{latitude_str}'. Must be a number between -90 and 90.")
    if longitude is None:
        logger.warning(f"Invalid 'longitude' value received: '{longitude_str}' from {request.remote_addr}.")
        abort(400, description=f"Invalid 'longitude' value: '{longitude_str}'. Must be a number between -180 and 180.")

    # Create a tuple (latitude, longitude) as required by geopy's reverse method.
    point = (latitude, longitude)
    logger.debug(f"Attempting to reverse geocode coordinates: {point}")

    # 2. Reverse Geocoding Logic using geopy
    try:
        # Perform the reverse geocoding request using the rate-limited reverse_geocoder.
        # `exactly_one=True` ensures that geopy tries to return a single, most relevant result.
        location = reverse_geocoder(point, exactly_one=True)

        if location:
            # If an address is found, extract relevant details.
            response_data = {
                "input_latitude": latitude,
                "input_longitude": longitude,
                "found_address": location.address,
                "latitude": location.latitude,  # Coordinates of the found address, might differ slightly from input
                "longitude": location.longitude, # due to snapping to a known geographical feature.
                "details": location.raw         # Raw data from Nominatim
            }
            logger.info(f"Successfully reverse geocoded {point} to '{location.address}'.")
            return create_json_response(response_data, 200, "Coordinates successfully reverse geocoded.")
        else:
            # No address found for the given coordinates.
            logger.info(f"No reverse geocoding results found for coordinates: {point}.")
            return create_json_response(
                {"input_latitude": latitude, "input_longitude": longitude, "message": "No results found for the given coordinates."},
                404, "No reverse geocoding results found.", "NO_RESULTS_FOUND"
            )

    except (GeocoderTimedOut, GeocoderUnavailable) as e:
        # Handle issues related to the geocoding service itself.
        logger.error(f"Reverse geocoding service error (timeout/unavailable) for {point}: {e}", exc_info=True)
        return create_json_response(
            None, 503, "Geocoding service currently unavailable or timed out. Please try again later.", "GEO_SERVICE_UNAVAILABLE"
        )
    except GeocoderServiceError as e:
        # Catch general geocoding service errors.
        logger.error(f"General reverse geocoding service error for {point}: {e}", exc_info=True)
        return create_json_response(
            None, 500, f"An error occurred with the geocoding service: {str(e)}", "GEO_SERVICE_ERROR"
        )
    except Exception as e:
        # Catch any other unexpected errors during the reverse geocoding process.
        logger.exception(f"An unexpected error occurred during reverse geocoding for {point}.")
        return create_json_response(
            None, 500, f"An unexpected error occurred: {str(e)}", "UNEXPECTED_ERROR"
        )

# --- Application Entry Point ---
# This block ensures the Flask application runs only when the script is executed directly
# (e.g., `python geocoding-api.py`), not when it's imported as a module.
if __name__ == '__main__':
    logger.info(f"Starting {APP_NAME} web service on {FLASK_HOST}:{FLASK_PORT}")
    logger.info(f"Flask debug mode is {'enabled' if FLASK_DEBUG else 'disabled'}.")

    # Log an example of how to make requests to the API for quick reference.
    logger.info("Example Forward Geocoding Request (GET):")
    logger.info(f"  curl -X GET \"http://{FLASK_HOST}:{FLASK_PORT}/geocode/address?address=1600 Amphitheatre Pkwy, Mountain View, CA\"")
    logger.info("Example Reverse Geocoding Request (GET):")
    logger.info(f"  curl -X GET \"http://{FLASK_HOST}:{FLASK_PORT}/geocode/reverse?latitude=34.0522&longitude=-118.2437\"")

    try:
        # Run the Flask application.
        # `threaded=True` enables handling multiple requests concurrently.
        # `debug=FLASK_DEBUG` enables/disables debug mode based on configuration.
        app.run(host=FLASK_HOST, port=FLASK_PORT, debug=FLASK_DEBUG, threaded=True)
    except Exception as e:
        # Catch any exceptions that prevent the Flask app from starting or cause it to crash.
        logger.critical(f"Failed to start Flask application: {e}", exc_info=True)
        sys.exit(1) # Exit with a non-zero status code to indicate failure.

```