import os
import io
import logging
from datetime import datetime

# Core Flask imports for web application development
from flask import Flask, request, send_file, abort, jsonify, make_response

# Third-party library for QR code generation
# This library is essential for creating QR codes.
# To install: pip install qrcode[pil]
# The `[pil]` extra ensures that Pillow (PIL Fork) is installed,
# which is necessary for saving QR codes as images.
import qrcode
from qrcode.constants import ERROR_CORRECT_H
from qrcode.exceptions import DataTooLongError

# --- Configuration Section ---
# This class centralizes all configurable parameters for the application.
# Using a class makes it easy to manage and access settings throughout the code,
# promoting cleaner organization and maintainability.
class AppConfig:
    """
    Centralized configuration for the QR Code Generator API.
    This class holds all constants and tunable parameters for the application,
    including Flask settings, QR code generation defaults, and logging details.
    """

    # --- Flask Application Configuration ---
    # FLASK_DEBUG_MODE: Controls Flask's debug features. Set to True for development,
    #                   False for production. Debug mode provides detailed error messages
    #                   and enables an auto-reloader.
    FLASK_DEBUG_MODE = True
    # FLASK_HOST: The interface on which the Flask application will listen.
    #             '0.0.0.0' makes the server accessible from any IP address on the network.
    #             '127.0.0.1' or 'localhost' would restrict it to the local machine.
    FLASK_HOST = '0.0.0.0'
    # FLASK_PORT: The port number the Flask application will bind to.
    #             Standard HTTP port is 80, HTTPS is 443. 5000 is a common development port.
    FLASK_PORT = 5000
    # FLASK_SECRET_KEY: A secret key is required for Flask applications, especially
    #                   when dealing with sessions, flash messages, or secure cookies.
    #                   It should be a long, random string. For production,
    #                   it should be loaded from an environment variable or a secure vault.
    #                   Here, we generate a random one for demonstration purposes.
    FLASK_SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', os.urandom(24).hex())

    # --- API Endpoint Configuration ---
    # API_QR_ENDPOINT: The URL path for the QR code generation endpoint.
    API_QR_ENDPOINT = '/qr'
    # API_QR_DATA_PARAMETER: The query parameter name used to pass data for QR code encoding.
    API_QR_DATA_PARAMETER = 'data'
    # API_MAX_DATA_LENGTH: The maximum number of characters allowed for the input data.
    #                      This helps prevent excessively large QR codes or resource exhaustion.
    API_MAX_DATA_LENGTH = 2048 # QR codes have practical limits, 2KB is a generous upper bound.

    # --- Default QR Code Generation Parameters ---
    # These parameters are used when generating the QR code. They can be fine-tuned
    # to control the appearance and robustness of the generated image.
    # DEFAULT_QR_VERSION: The size and data capacity of the QR code.
    #                     Ranges from 1 (21x21 modules) to 40 (177x177 modules).
    #                     'None' allows the `qrcode` library to automatically determine
    #                     the smallest version required for the given data.
    DEFAULT_QR_VERSION = None
    # DEFAULT_QR_ERROR_CORRECTION: The error correction level. Higher levels allow
    #                              more damage to the QR code before it becomes unreadable,
    #                              but increase the QR code's size.
    #                              - ERROR_CORRECT_L: 7% data recovery capacity
    #                              - ERROR_CORRECT_M: 15% data recovery capacity (default)
    #                              - ERROR_CORRECT_Q: 25% data recovery capacity
    #                              - ERROR_CORRECT_H: 30% data recovery capacity (chosen for robustness)
    DEFAULT_QR_ERROR_CORRECTION = ERROR_CORRECT_H
    # DEFAULT_QR_BOX_SIZE: The size of each 'box' (module) in pixels. Larger values result
    #                      in a larger overall QR code image.
    DEFAULT_QR_BOX_SIZE = 10
    # DEFAULT_QR_BORDER: The width of the quiet zone (white border) around the QR code,
    #                    in terms of number of boxes. The QR specification recommends
    #                    at least a 4-box wide border.
    DEFAULT_QR_BORDER = 4
    # DEFAULT_QR_FILL_COLOR: The color of the QR code modules (the "data" part).
    DEFAULT_QR_FILL_COLOR = "black"
    # DEFAULT_QR_BACK_COLOR: The color of the background (the "quiet zone" and empty parts).
    DEFAULT_QR_BACK_COLOR = "white"
    # DEFAULT_QR_IMAGE_FORMAT: The output image format. PNG is chosen for its lossless compression
    #                          and wide browser support.
    DEFAULT_QR_IMAGE_FORMAT = "PNG"
    # DEFAULT_QR_FILENAME: A base name for the generated QR code file if saved to disk (not applicable here,
    #                      but good for general QR generation utility).
    DEFAULT_QR_FILENAME = "qrcode_image"

    # --- Logging Configuration ---
    # LOG_LEVEL: The minimum level of messages to log.
    #            Options: DEBUG, INFO, WARNING, ERROR, CRITICAL.
    LOG_LEVEL = logging.INFO
    # LOG_FORMAT: The format string for log messages.
    #             Includes timestamp, logger name, level, and the message itself.
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    # LOG_FILE: The name of the file to which logs will be written.
    LOG_FILE = 'qr_generator_api.log'
    # LOG_MAX_BYTES: Maximum size of the log file before it's rotated. 1 MB.
    LOG_MAX_BYTES = 1024 * 1024
    # LOG_BACKUP_COUNT: Number of backup log files to keep.
    LOG_BACKUP_COUNT = 5


# --- Logging Setup ---
# This function initializes and configures the Python logging system.
# Proper logging is crucial for monitoring the application's health,
# debugging issues, and understanding its behavior in production.
def configure_logging():
    """
    Configures the application's logging system.
    Sets up a file handler for persistent logs and a console handler for immediate feedback.
    Log levels are set based on AppConfig.
    """
    # Create a logger instance for the application.
    # The name 'qr_generator_api' makes it easy to identify log messages
    # originating from this specific application.
    app_logger = logging.getLogger('qr_generator_api')
    app_logger.setLevel(AppConfig.LOG_LEVEL)

    # Prevent adding multiple handlers if function is called multiple times
    if not app_logger.handlers:
        # Create a file handler for logging messages to a file.
        # This uses RotatingFileHandler to manage log file size and rotation,
        # preventing a single log file from consuming all disk space.
        from logging.handlers import RotatingFileHandler
        file_handler = RotatingFileHandler(
            AppConfig.LOG_FILE,
            maxBytes=AppConfig.LOG_MAX_BYTES,
            backupCount=AppConfig.LOG_BACKUP_COUNT
        )
        file_handler.setLevel(AppConfig.LOG_LEVEL)

        # Create a console handler for logging messages to the standard output (terminal).
        console_handler = logging.StreamHandler()
        console_handler.setLevel(AppConfig.LOG_LEVEL)

        # Define the format for log messages.
        formatter = logging.Formatter(AppConfig.LOG_FORMAT)
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        # Add the handlers to the logger.
        app_logger.addHandler(file_handler)
        app_logger.addHandler(console_handler)

    # Return the configured logger instance.
    return app_logger

# Initialize the logger for the entire application.
# This global logger instance will be used by different parts of the application.
logger = configure_logging()
logger.info("Application logging configured successfully.")


# --- Custom QR Code Generator Class ---
# Encapsulating the QR code generation logic within a class provides better
# organization, allows for state management (though minimal here), and
# makes the code more modular and testable.
class QRCodeGenerator:
    """
    A class responsible for generating QR code images.
    It encapsulates the configuration and logic for creating QR codes
    based on various parameters.
    """

    def __init__(self,
                 version=AppConfig.DEFAULT_QR_VERSION,
                 error_correction=AppConfig.DEFAULT_QR_ERROR_CORRECTION,
                 box_size=AppConfig.DEFAULT_QR_BOX_SIZE,
                 border=AppConfig.DEFAULT_QR_BORDER,
                 fill_color=AppConfig.DEFAULT_QR_FILL_COLOR,
                 back_color=AppConfig.DEFAULT_QR_BACK_COLOR):
        """
        Initializes the QRCodeGenerator with specified or default parameters.

        Args:
            version (int, optional): QR code version (size). None for auto-detection.
                                     Defaults to AppConfig.DEFAULT_QR_VERSION.
            error_correction (int, optional): Error correction level.
                                            Defaults to AppConfig.DEFAULT_QR_ERROR_CORRECTION.
            box_size (int, optional): Size of each QR code module in pixels.
                                      Defaults to AppConfig.DEFAULT_QR_BOX_SIZE.
            border (int, optional): Width of the quiet zone border in modules.
                                    Defaults to AppConfig.DEFAULT_QR_BORDER.
            fill_color (str, optional): Color of the QR code modules (e.g., "black", "#000000").
                                        Defaults to AppConfig.DEFAULT_QR_FILL_COLOR.
            back_color (str, optional): Color of the background (e.g., "white", "#FFFFFF").
                                        Defaults to AppConfig.DEFAULT_QR_BACK_COLOR.
        """
        logger.debug(f"Initializing QRCodeGenerator with version={version}, error_correction={error_correction}, "
                     f"box_size={box_size}, border={border}, fill_color={fill_color}, back_color={back_color}")
        self._version = version
        self._error_correction = error_correction
        self._box_size = box_size
        self._border = border
        self._fill_color = fill_color
        self._back_color = back_color

    def generate_qr_code_image_bytes(self, data_to_encode: str) -> io.BytesIO:
        """
        Generates a QR code image for the given data and returns it as a BytesIO object.
        This allows the image to be handled in memory without needing to save it to disk.

        Args:
            data_to_encode (str): The string data to be encoded into the QR code.

        Returns:
            io.BytesIO: A BytesIO object containing the PNG image data of the QR code.

        Raises:
            ValueError: If the input data is invalid (e.g., empty or too long).
            DataTooLongError: If the data is too long for the specified QR code version.
            Exception: For any other unexpected errors during QR code generation.
        """
        if not data_to_encode:
            logger.error("Attempted to generate QR code with empty data.")
            raise ValueError("Data to encode cannot be empty.")
        if not isinstance(data_to_encode, str):
            logger.error(f"Invalid data type for QR code generation: {type(data_to_encode)}. Expected string.")
            raise TypeError("Data to encode must be a string.")

        logger.info(f"Generating QR code for data (first 50 chars): '{data_to_encode[:50]}'")

        try:
            # Create a QR code object with specified parameters.
            # The `qrcode.QRCode` class handles the core logic of QR code generation.
            qr = qrcode.QRCode(
                version=self._version,
                error_correction=self._error_correction,
                box_size=self._box_size,
                border=self._border,
            )

            # Add the data to the QR code.
            # This step involves encoding the string into QR code segments.
            qr.add_data(data_to_encode)
            # Make the QR code. The `fit=True` argument ensures that the QR code version
            # is automatically adjusted to the smallest possible size that can hold the data,
            # if `version` was set to `None`.
            qr.make(fit=True)

            # Create an image from the QR code data.
            # The `make_image` method from `qrcode` uses Pillow (PIL) to render the image.
            img = qr.make_image(
                fill_color=self._fill_color,
                back_color=self._back_color
            )

            # Save the image into a BytesIO object.
            # BytesIO acts like an in-memory binary file, which is perfect for
            # passing image data directly as an HTTP response.
            img_byte_arr = io.BytesIO()
            img.save(img_byte_arr, format=AppConfig.DEFAULT_QR_IMAGE_FORMAT)
            img_byte_arr.seek(0) # Rewind the buffer to the beginning.

            logger.info(f"Successfully generated QR code image for data: '{data_to_encode[:50]}'")
            return img_byte_arr

        except DataTooLongError as dtle:
            logger.error(f"DataTooLongError: The provided data is too long for the chosen QR code version or constraints. "
                         f"Data length: {len(data_to_encode)}. Error: {dtle}")
            raise DataTooLongError(f"Data is too long to encode in a QR code: {dtle}")
        except Exception as e:
            logger.critical(f"An unexpected error occurred during QR code generation for data "
                            f"'{data_to_encode[:50]}': {e}", exc_info=True)
            raise RuntimeError(f"Failed to generate QR code due to an internal error: {e}")


# --- Flask Application Initialization ---
# Create the Flask application instance.
# The `__name__` argument helps Flask determine the root path for resources.
app = Flask(__name__)

# Apply configurations from the AppConfig class to the Flask app.
# This includes debug mode, secret key, etc.
app.config['DEBUG'] = AppConfig.FLASK_DEBUG_MODE
app.config['SECRET_KEY'] = AppConfig.FLASK_SECRET_KEY

# Log the application's configuration state.
logger.info(f"Flask application initialized with DEBUG={app.config['DEBUG']} and host={AppConfig.FLASK_HOST}, port={AppConfig.FLASK_PORT}")


# --- Utility Functions for API Responses and Error Handling ---
# These functions standardize how errors are returned to the client,
# ensuring consistent API behavior.
def create_json_error_response(message: str, status_code: int) -> tuple[dict, int]:
    """
    Creates a standardized JSON error response.

    Args:
        message (str): The error message to be included in the response.
        status_code (int): The HTTP status code for the response.

    Returns:
        tuple[dict, int]: A tuple containing the JSON response body and the HTTP status code.
    """
    error_response_payload = {
        "status": "error",
        "message": message,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    logger.warning(f"Returning error {status_code}: {message}")
    # Using make_response and jsonify ensures correct content-type header for JSON.
    return make_response(jsonify(error_response_payload), status_code)


# --- Flask Error Handlers ---
# These decorators register functions to handle specific HTTP error codes
# that might occur during request processing within the Flask application.
# They provide custom, user-friendly error messages instead of generic ones.
@app.errorhandler(400)
def bad_request_error(error):
    """
    Handles HTTP 400 Bad Request errors.
    This typically occurs when the client sends an invalid request,
    e.g., missing parameters or incorrect data format.
    """
    error_message = f"Bad Request: The server cannot process the request due to malformed syntax. {str(error)}"
    logger.error(f"400 Bad Request encountered: {error_message}", exc_info=True)
    return create_json_error_response(error_message, 400)

@app.errorhandler(404)
def not_found_error(error):
    """
    Handles HTTP 404 Not Found errors.
    This occurs when the client requests a resource (URL) that does not exist.
    """
    error_message = f"Not Found: The requested URL was not found on the server. {str(error)}"
    logger.warning(f"404 Not Found encountered: {request.url}")
    return create_json_error_response(error_message, 404)

@app.errorhandler(405)
def method_not_allowed_error(error):
    """
    Handles HTTP 405 Method Not Allowed errors.
    This occurs when the client tries to use an HTTP method (e.g., POST)
    on a route that only supports other methods (e.g., GET).
    """
    error_message = f"Method Not Allowed: The method is not allowed for the requested URL. {str(error)}"
    logger.warning(f"405 Method Not Allowed encountered for {request.method} {request.path}")
    return create_json_error_response(error_message, 405)


@app.errorhandler(500)
def internal_server_error(error):
    """
    Handles HTTP 500 Internal Server Error.
    This is a generic error that indicates something went wrong on the server's side
    that wasn't caught by more specific error handlers.
    """
    error_message = f"Internal Server Error: An unexpected error occurred on the server. {str(error)}"
    logger.critical(f"500 Internal Server Error encountered: {error_message}", exc_info=True)
    return create_json_error_response(error_message, 500)

# Initialize the QR code generator instance with default parameters.
# This instance can be reused for multiple requests, avoiding redundant object creation.
qr_generator_instance = QRCodeGenerator()
logger.info("QRCodeGenerator instance created.")


# --- Main API Endpoint Definition ---
# This defines the primary route for our QR code generation service.
@app.route(AppConfig.API_QR_ENDPOINT, methods=['GET'])
def generate_qr_code_api():
    """
    Handles GET requests to the QR code generation endpoint.
    Expects a 'data' query parameter containing the string to encode.
    Returns a PNG image of the generated QR code.

    Example usage:
        GET /qr?data=Hello%20World
    """
    request_start_time = datetime.now()
    logger.info(f"Received GET request for {AppConfig.API_QR_ENDPOINT} from {request.remote_addr} "
                f"with args: {request.args}")

    # 1. Parameter Extraction: Retrieve the 'data' parameter from the URL query string.
    #    The `request.args.get()` method is safe as it returns None if the parameter is missing.
    data_to_encode = request.args.get(AppConfig.API_QR_DATA_PARAMETER)

    # 2. Input Validation: Crucial for robust API design.
    #    a. Check if the 'data' parameter is provided.
    if data_to_encode is None:
        logger.warning("QR code generation request failed: Missing 'data' parameter.")
        return create_json_error_response(
            f"Missing required query parameter: '{AppConfig.API_QR_DATA_PARAMETER}'. "
            f"Usage: {AppConfig.API_QR_ENDPOINT}?{AppConfig.API_QR_DATA_PARAMETER}=YourDataHere",
            400
        )

    #    b. Check if the 'data' parameter is empty. An empty string can generate an empty QR, but usually
    #       it indicates an oversight from the client.
    if not data_to_encode.strip(): # Check for empty or whitespace-only string
        logger.warning("QR code generation request failed: 'data' parameter is empty or whitespace-only.")
        return create_json_error_response(
            "The 'data' parameter cannot be empty or contain only whitespace. Please provide valid content.",
            400
        )

    #    c. Check if the data length exceeds the defined maximum.
    #       This prevents denial-of-service attacks or generation of excessively complex QR codes.
    if len(data_to_encode) > AppConfig.API_MAX_DATA_LENGTH:
        logger.warning(f"QR code generation request failed: Data length ({len(data_to_encode)}) exceeds "
                       f"maximum allowed ({AppConfig.API_MAX_DATA_LENGTH}).")
        return create_json_error_response(
            f"Data too long. Maximum allowed length is {AppConfig.API_MAX_DATA_LENGTH} characters. "
            f"Provided length: {len(data_to_encode)}.",
            400
        )

    # 3. QR Code Generation: Delegate to the QRCodeGenerator class.
    #    This separates the API endpoint logic from the core QR generation logic.
    try:
        qr_image_bytes = qr_generator_instance.generate_qr_code_image_bytes(data_to_encode)
    except (ValueError, TypeError) as ve:
        # Catch validation errors from the generator itself
        logger.error(f"Validation error during QR generation: {ve}")
        return create_json_error_response(f"Invalid data for QR code: {ve}", 400)
    except DataTooLongError as dtle:
        # Specifically handle cases where data is too long for the QR version
        logger.error(f"DataTooLongError caught during QR generation: {dtle}")
        return create_json_error_response(
            f"Data content is too complex or long to fit into a QR code with current settings: {dtle}",
            400
        )
    except RuntimeError as re:
        # Catch general runtime errors during QR generation
        logger.error(f"Runtime error during QR generation: {re}")
        return create_json_error_response(f"Failed to generate QR code: {re}", 500)
    except Exception as e:
        # Catch any other unexpected exceptions during the generation process
        logger.critical(f"An unhandled exception occurred during QR code generation: {e}", exc_info=True)
        return create_json_error_response(f"An unexpected internal error occurred: {e}", 500)

    # 4. Response Construction: Prepare the image for sending back to the client.
    #    `send_file` is a Flask utility function that streams a file-like object
    #    and automatically sets appropriate headers (e.g., Content-Type).
    response = send_file(
        qr_image_bytes,
        mimetype=f'image/{AppConfig.DEFAULT_QR_IMAGE_FORMAT.lower()}', # e.g., 'image/png'
        as_attachment=False, # We want to display the image, not force a download.
        download_name=f"{AppConfig.DEFAULT_QR_FILENAME}_{datetime.now().strftime('%Y%m%d%H%M%S')}.{AppConfig.DEFAULT_QR_IMAGE_FORMAT.lower()}"
    )

    # Add caching headers to the response.
    # These headers instruct browsers and proxies on how to cache the image,
    # improving performance for repeated requests of the same QR code.
    response.headers['Cache-Control'] = 'public, max-age=3600' # Cache for 1 hour
    response.headers['Expires'] = (datetime.utcnow() + datetime.timedelta(hours=1)).strftime('%a, %d %b %Y %H:%M:%S GMT')

    request_end_time = datetime.now()
    processing_time = (request_end_time - request_start_time).total_seconds() * 1000 # in milliseconds
    logger.info(f"Successfully processed QR code request for data '{data_to_encode[:50]}'. "
                f"Response sent in {processing_time:.2f} ms.")
    return response

# --- Health Check Endpoint (Optional but good practice) ---
# A simple endpoint to check if the API is running and responsive.
# Useful for load balancers, container orchestration systems, and monitoring.
@app.route('/health', methods=['GET'])
def health_check():
    """
    Provides a simple health check endpoint for the API.
    Returns a JSON response indicating the API's status.
    """
    logger.debug("Health check endpoint hit.")
    response_payload = {
        "status": "healthy",
        "service": "qr-code-generator-api",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "uptime_info": "Not implemented yet, but service is responding."
    }
    return jsonify(response_payload), 200


# --- Main Execution Block ---
# This block ensures that the Flask development server is run only when
# the script is executed directly (not when imported as a module).
if __name__ == '__main__':
    logger.info(f"Starting Flask development server on http://{AppConfig.FLASK_HOST}:{AppConfig.FLASK_PORT}")
    logger.info(f"Access QR code endpoint: http://{AppConfig.FLASK_HOST}:{AppConfig.FLASK_PORT}{AppConfig.API_QR_ENDPOINT}?{AppConfig.API_QR_DATA_PARAMETER}=YourTestString")

    try:
        # Run the Flask application.
        # `debug=True` provides interactive debugger and auto-reloader for development.
        # In a production environment, a more robust WSGI server like Gunicorn or uWSGI
        # would be used instead of Flask's built-in development server.
        app.run(host=AppConfig.FLASK_HOST, port=AppConfig.FLASK_PORT, debug=AppConfig.FLASK_DEBUG_MODE)
    except Exception as e:
        logger.critical(f"Failed to start Flask application: {e}", exc_info=True)
        # It's good practice to exit with a non-zero status code on critical failures.
        exit(1)