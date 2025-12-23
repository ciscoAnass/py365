# Required third-party libraries (install via pip):
# pip install Flask pyotp qrcode[pil]

# Standard library imports for system operations, logging, base64 encoding, and IO.
import os
import io
import json
import base64
import logging
import datetime

# Third-party library imports for cryptographic operations, TOTP generation, and QR code generation.
# 'pyotp' is essential for Time-based One-Time Password (TOTP) secret management.
# 'qrcode' is used for generating the QR code image from the TOTP URI.
# 'PIL' (Pillow) is used by 'qrcode' and for image manipulation/saving to a buffer.
import pyotp
import qrcode
from PIL import Image

# ----------------------------------------------------------------------------------------------------------------------
# Configuration Settings
# This section defines various parameters for the API, logging, and QR code generation.
# Using a class or dictionary for configuration helps centralize settings and makes them easily modifiable.
# Environment variables are used for flexible deployment, with sensible defaults provided.
# ----------------------------------------------------------------------------------------------------------------------
class AppConfig:
    """
    Configuration class for the 2FA QR Code Generator API.
    Centralizes all configurable parameters, making the application easier to manage and deploy.
    Settings are loaded from environment variables where available, falling back to defaults.
    """
    # API Server Settings
    # The host address for the Flask application. '0.0.0.0' makes it accessible externally.
    API_HOST: str = os.getenv('API_HOST', '0.0.0.0')
    # The port number on which the Flask application will listen.
    API_PORT: int = int(os.getenv('API_PORT', 5000))
    # Boolean flag to enable/disable Flask's debug mode. Should be False in production.
    DEBUG_MODE: bool = os.getenv('DEBUG_MODE', 'False').lower() in ('true', '1', 't')

    # Logging Settings
    # The minimum level of logging messages to be processed (e.g., INFO, DEBUG, WARNING, ERROR, CRITICAL).
    LOG_LEVEL: str = os.getenv('LOG_LEVEL', 'INFO').upper()
    # The file path where log messages will be written.
    LOG_FILE_PATH: str = os.getenv('LOG_FILE_PATH', 'app_2fa_qr_generator.log')
    # The format string for log messages. Includes timestamp, logger name, level, source file, line number, and message.
    LOG_FORMAT: str = (
        '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
    )
    # A unique name for the application's logger to avoid conflicts with other library loggers.
    LOGGER_NAME: str = '2fa_qr_api_logger'

    # QR Code Generation Settings
    # The size of each 'box' (pixel) in the QR code. Larger values result in a larger image.
    QR_CODE_BOX_SIZE: int = int(os.getenv('QR_CODE_BOX_SIZE', 10))
    # The thickness of the white border (quiet zone) around the QR code, in terms of 'box_size' units.
    QR_CODE_BORDER_SIZE: int = int(os.getenv('QR_CODE_BORDER_SIZE', 4))
    # The error correction level for the QR code. Higher levels increase redundancy, making the QR code
    # more resilient to damage but also larger. qrcode.constants.ERROR_CORRECT_H allows up to 30% damage.
    QR_CODE_ERROR_CORRECTION: int = int(os.getenv('QR_CODE_ERROR_CORRECTION', qrcode.constants.ERROR_CORRECT_H))

    # API Response Messages
    # Standard success message for 2FA QR code generation.
    MESSAGE_SUCCESS_GENERATE: str = "2FA QR code generated successfully."
    # Error message for invalid or missing input parameters.
    MESSAGE_ERROR_INVALID_INPUT: str = "Invalid input. 'username' and 'issuer' are required and must be non-empty strings."
    # Generic internal server error message.
    MESSAGE_ERROR_INTERNAL_SERVER: str = "An internal server error occurred during QR code generation."
    # Error message for issues with parsing the JSON request body.
    MESSAGE_ERROR_JSON_PARSE: str = "Failed to parse JSON request body."
    # Error message for requests made with unsupported HTTP methods.
    MESSAGE_ERROR_METHOD_NOT_ALLOWED: str = "Method Not Allowed. Only POST requests are supported for this endpoint."


# ----------------------------------------------------------------------------------------------------------------------
# Logging Setup
# A dedicated function to configure the application's logging system.
# This ensures that all events, errors, and debugging information are properly recorded,
# aiding in monitoring and troubleshooting the API.
# ----------------------------------------------------------------------------------------------------------------------
def setup_logging() -> logging.Logger:
    """
    Configures the application's logging system.
    Sets up a logger that outputs messages to both the console (stdout) and a file.
    The log level and message format are determined by the AppConfig settings.
    This function prevents adding duplicate handlers if called multiple times,
    ensuring a clean logging setup.

    Returns:
        logging.Logger: The configured logger instance for the application.
    """
    # Retrieve the logger instance by its name defined in AppConfig.
    # This ensures we are always working with the same logger throughout the application.
    logger = logging.getLogger(AppConfig.LOGGER_NAME)
    # Set the global logging level for this logger. Messages below this level will be ignored.
    logger.setLevel(AppConfig.LOG_LEVEL)

    # Check if the logger already has handlers to prevent duplicate output.
    # This is crucial if setup_logging might be called more than once (e.g., in testing).
    if not logger.handlers:
        # Create a formatter object to define the structure of log messages.
        formatter = logging.Formatter(AppConfig.LOG_FORMAT)

        # 1. Console Handler:
        # This handler sends log records to the console (standard output).
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        # Set the level for the console handler. For user-facing APIs, INFO level is often appropriate
        # to show essential status messages without overwhelming the console with DEBUG info.
        console_handler.setLevel(logging.INFO)
        logger.addHandler(console_handler) # Add the console handler to the logger.

        # 2. File Handler:
        # This handler sends log records to a specified file.
        file_handler = logging.FileHandler(AppConfig.LOG_FILE_PATH)
        file_handler.setFormatter(formatter)
        # Set the level for the file handler. This usually matches the logger's main level
        # to capture all relevant details in the log file.
        file_handler.setLevel(AppConfig.LOG_LEVEL)
        logger.addHandler(file_handler) # Add the file handler to the logger.

        # Prevent log messages from being propagated to the root logger.
        # If not set to False, messages might appear twice if the root logger also has handlers.
        logger.propagate = False

    return logger

# Initialize the application-wide logger immediately upon script execution.
app_logger = setup_logging()
app_logger.info("Application logging configured successfully.")
app_logger.debug(f"Current log level set to: {AppConfig.LOG_LEVEL}")
app_logger.debug(f"Log messages will be written to: {AppConfig.LOG_FILE_PATH}")


# ----------------------------------------------------------------------------------------------------------------------
# TOTP (Time-based One-Time Password) Helper Functions
# These functions encapsulate the specific logic required for generating cryptographically secure
# TOTP secrets and constructing the standardized 'otpauth' URI.
# The 'otpauth' URI is a critical component as it instructs authenticator applications
# on how to configure the 2FA entry.
# ----------------------------------------------------------------------------------------------------------------------
def generate_totp_secret(length_bytes: int = 20) -> str:
    """
    Generates a new random Base32 encoded secret for TOTP.
    Base32 encoding is preferred for TOTP secrets as it is case-insensitive
    and consists of characters that are generally safe for various systems and displays.
    A longer secret provides greater security.

    Args:
        length_bytes (int): The desired length of the secret in bytes.
                            A standard secure length is 16 bytes (128 bits) or 20 bytes (160 bits).
                            pyotp.random_base32() generates a variable length string
                            based on a default of 160 bits of entropy.

    Returns:
        str: A cryptographically secure, randomly generated Base32 encoded secret string.
             Example: "JBSWY3DPEHPK3PXP"
    """
    # pyotp.random_base32() internally generates random bytes using os.urandom
    # and then encodes them to Base32. The 'length_bytes' parameter is not
    # directly passed to pyotp, as it manages the entropy internally.
    # The default generation is sufficient for strong security.
    secret = pyotp.random_base32()
    # Log a masked version of the secret to avoid exposing sensitive information in logs.
    app_logger.debug(f"Generated TOTP secret (masked for security): {secret[:4]}...{secret[-4:]}")
    return secret

def create_totp_uri(secret: str, username: str, issuer: str) -> str:
    """
    Constructs the standard 'otpauth' URI for a TOTP secret.
    This URI is a specially formatted string that authenticator applications
    can parse to automatically set up a new 2FA account. It typically includes
    the secret, the account name (username), and the issuer name.

    The format is typically: otpauth://totp/LABEL?secret=SECRET&issuer=ISSUER_NAME&algorithm=ALGO&digits=DIGITS&period=PERIOD

    Args:
        secret (str): The Base32 encoded TOTP secret string.
        username (str): The user's account identifier (e.g., email address, login name).
                        This will form part of the label displayed in the authenticator app.
        issuer (str): The name of the service provider or organization.
                      This helps users identify the 2FA entry in their authenticator app.

    Returns:
        str: The full 'otpauth' URI string, properly formatted and URL-encoded.
             Example: "otpauth://totp/MyCompany:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=MyCompany"
    """
    # It's important to URL-encode the 'username' and 'issuer' components to handle
    # special characters correctly within the URI. pyotp's provisioning_uri method
    # handles this encoding automatically, which is a robust approach.
    app_logger.debug(f"Creating TOTP URI for username: '{username}', issuer: '{issuer}'.")

    # Use pyotp's dedicated method to generate the provisioning URI.
    # This method handles all the necessary formatting, parameter inclusion, and URL encoding.
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name=issuer
    )
    app_logger.debug(f"Successfully created TOTP URI. URI: {totp_uri}")
    return totp_uri


# ----------------------------------------------------------------------------------------------------------------------
# QR Code Generation and Image Handling Helper Functions
# These functions are responsible for taking the 'otpauth' URI and converting it into a visual
# QR code image, and then transforming that image into a web-friendly data:image/png URL.
# This entire process avoids saving any temporary files to disk, operating entirely in memory.
# ----------------------------------------------------------------------------------------------------------------------
def generate_qr_code_image(data: str) -> Image.Image:
    """
    Generates a QR code image from the given string data (which is typically an otpauth URI).
    Utilizes the 'qrcode' library, configured with parameters from AppConfig for visual
    appearance (box size, border) and error correction capabilities.

    Args:
        data (str): The string content to be encoded into the QR code. This should be the
                    complete 'otpauth' URI generated by `create_totp_uri`.

    Returns:
        PIL.Image.Image: A Pillow (PIL) Image object representing the generated QR code.
                         This image is in-memory and can be further processed or saved.
    """
    app_logger.debug(f"Initiating QR code image generation for data of length: {len(data)}.")
    app_logger.debug(f"QR Code settings: Box Size={AppConfig.QR_CODE_BOX_SIZE}, "
                     f"Border Size={AppConfig.QR_CODE_BORDER_SIZE}, "
                     f"Error Correction Level={AppConfig.QR_CODE_ERROR_CORRECTION}.")

    # Initialize the QRCode generator with specific parameters.
    # `version=None` tells the library to automatically choose the smallest QR code version
    # that can hold the data with the specified error correction level.
    qr = qrcode.QRCode(
        version=None,
        error_correction=AppConfig.QR_CODE_ERROR_CORRECTION,
        box_size=AppConfig.QR_CODE_BOX_SIZE,
        border=AppConfig.QR_CODE_BORDER_SIZE,
    )

    # Add the data string to the QR code object.
    qr.add_data(data)
    # This method computes the necessary modules and structure of the QR code.
    # `fit=True` ensures the version is automatically adjusted if the data is too large for the initial estimate.
    qr.make(fit=True)

    # Create the actual image from the QR code modules.
    # `fill_color` defines the color of the dark modules (the data-carrying squares).
    # `back_color` defines the color of the light modules (the background squares).
    img = qr.make_image(fill_color="black", back_color="white")
    app_logger.debug("QR code image successfully generated as a Pillow (PIL) Image object.")
    return img

def convert_image_to_data_url(image: Image.Image) -> str:
    """
    Converts a Pillow (PIL) Image object into a 'data:image/png' URL string.
    This format is highly useful for web applications as it allows embedding
    the image data directly into HTML, CSS, or JSON responses, eliminating
    the need for separate image files or endpoints.

    The process involves saving the image to an in-memory byte stream,
    Base64 encoding these bytes, and then prefixing the result with the
    appropriate MIME type and Base64 indicator.

    Args:
        image (PIL.Image.Image): The Pillow Image object to be converted.

    Returns:
        str: A string formatted as a 'data:image/png' URL.
             Example: "data:image/png;base64,iVBORw0K..."
    """
    app_logger.debug("Initiating conversion of Pillow Image to data:image/png URL.")

    # Create an in-memory binary stream to temporarily hold the image data.
    # This avoids writing any files to the filesystem.
    byte_arr = io.BytesIO()
    
    try:
        # Save the Pillow Image object into the BytesIO stream in PNG format.
        # PNG is chosen for its lossless compression and wide browser support,
        # which is ideal for precise graphics like QR codes.
        image.save(byte_arr, format='PNG')
        # Retrieve the complete byte sequence from the stream.
        encoded_image_bytes = byte_arr.getvalue()
        app_logger.debug(f"Image successfully saved to BytesIO buffer. Raw size: {len(encoded_image_bytes)} bytes.")

        # Base64 encode the raw image bytes.
        # Base64 is an encoding scheme that converts binary data into an ASCII string format.
        base64_encoded_data = base64.b64encode(encoded_image_bytes)
        # Decode the Base64 bytes into a UTF-8 string, which is required for the data URL format.
        base64_string = base64_encoded_data.decode('utf-8')
        app_logger.debug(f"Image data successfully Base64 encoded. Encoded length: {len(base64_string)} characters.")

        # Construct the complete data URL string.
        # The prefix "data:image/png;base64," specifies the MIME type and encoding.
        data_url_prefix = "data:image/png;base64,"
        data_url = data_url_prefix + base64_string
        app_logger.debug(f"Final data:image/png URL generated. Total length: {len(data_url)} characters.")
        return data_url
    except Exception as e:
        app_logger.error(f"Error during image to data URL conversion: {e}", exc_info=True)
        raise # Re-raise the exception after logging for proper error handling upstream.


# ----------------------------------------------------------------------------------------------------------------------
# Core Orchestration Function
# This function acts as the main business logic orchestrator, integrating all the individual
# helper functions into a coherent workflow. It manages the sequence of operations from
# secret generation to final QR code data URL creation, including error handling.
# ----------------------------------------------------------------------------------------------------------------------
def generate_2fa_qr_data_url(username: str, issuer: str) -> dict:
    """
    Orchestrates the entire process of generating a 2FA TOTP secret,
    creating its corresponding QR code, and returning it as a data:image/png URL.
    This function combines secret generation, URI construction, image creation,
    and base64 encoding.

    Args:
        username (str): The user's account identifier for which the 2FA is being set up.
        issuer (str): The name of the service or organization providing the 2FA.

    Returns:
        dict: A dictionary containing:
              - 'secret' (str): The newly generated Base32 TOTP secret.
              - 'qr_code_url' (str): The data:image/png URL of the QR code.
              If an error occurs, 'secret' and 'qr_code_url' will be None.
    """
    app_logger.info(f"Initiating full 2FA QR code generation process for user: '{username}', issuer: '{issuer}'.")
    secret = None
    qr_data_url = None

    try:
        # Step 1: Generate a new TOTP secret.
        # This secret is the foundation of the 2FA authentication, shared only between
        # the server and the user's authenticator app.
        app_logger.debug("Calling generate_totp_secret()...")
        secret = generate_totp_secret()
        if not secret:
            app_logger.error("Failed to generate a valid TOTP secret.")
            raise ValueError("TOTP secret generation failed.")
        app_logger.debug("TOTP secret generation complete.")

        # Step 2: Create the otpauth URI from the secret, username, and issuer.
        # This URI is the standard way to configure authenticator apps.
        app_logger.debug("Calling create_totp_uri()...")
        totp_uri = create_totp_uri(secret, username, issuer)
        if not totp_uri:
            app_logger.error("Failed to create TOTP URI.")
            raise ValueError("TOTP URI creation failed.")
        app_logger.debug("TOTP URI creation complete.")

        # Step 3: Generate the QR code image from the otpauth URI.
        # This converts the URI string into a scannable visual representation.
        app_logger.debug("Calling generate_qr_code_image()...")
        qr_image = generate_qr_code_image(totp_uri)
        if qr_image is None:
            app_logger.error("Failed to generate QR code image.")
            raise ValueError("QR code image generation failed.")
        app_logger.debug("QR code image generation complete.")

        # Step 4: Convert the generated QR code image into a data:image/png URL.
        # This makes the image directly embeddable in JSON responses or web pages.
        app_logger.debug("Calling convert_image_to_data_url()...")
        qr_data_url = convert_image_to_data_url(qr_image)
        if not qr_data_url:
            app_logger.error("Failed to convert QR image to data URL.")
            raise ValueError("Image to data URL conversion failed.")
        app_logger.debug("Image to data URL conversion complete.")

        app_logger.info(f"Successfully completed 2FA QR code generation for user '{username}'.")
        return {
            "secret": secret,
            "qr_code_url": qr_data_url
        }

    except Exception as e:
        # Catch any unexpected errors that occur during the entire process.
        # Log the error with full traceback for detailed debugging.
        app_logger.error(
            f"An error occurred during 2FA QR code generation for user '{username}', issuer '{issuer}': {e}",
            exc_info=True # This includes the traceback in the log.
        )
        # Return a result indicating failure, allowing the API endpoint to handle it gracefully.
        return {
            "secret": None,
            "qr_code_url": None
        }


# ----------------------------------------------------------------------------------------------------------------------
# Flask API Application Setup
# This section initializes the Flask web framework, imports necessary components, and sets up
# the core application instance. Flask is a micro-framework that provides tools for building
# web applications and APIs.
# ----------------------------------------------------------------------------------------------------------------------
try:
    # Attempt to import Flask and related modules.
    from flask import Flask, request, jsonify, make_response
    # Import specific HTTP exceptions from Werkzeug to handle common API error scenarios.
    from werkzeug.exceptions import HTTPException, BadRequest, MethodNotAllowed, InternalServerError
except ImportError:
    # If Flask is not installed, log a critical error and exit the application.
    # This prevents the script from attempting to run without its core dependency.
    app_logger.critical(
        "Flask is not installed. Please install it using 'pip install Flask'."
        " For image generation, ensure 'qrcode[pil]' is also installed."
    )
    import sys
    sys.exit(1) # Exit the script with an error code.


# Create the Flask application instance.
# '__name__' tells Flask where to find static files and templates relative to the module.
app = Flask(__name__)
# Set Flask's debug mode based on the configuration. Debug mode provides more verbose errors
# and auto-reloading, but should never be enabled in production environments.
app.debug = AppConfig.DEBUG_MODE

# Disable strict slashes for routes. This means that '/endpoint' and '/endpoint/' will
# be treated as the same route, which can improve flexibility for clients.
app.url_map.strict_slashes = False

app_logger.info("Flask application initialized.")
if app.debug:
    app_logger.warning("Flask is running in DEBUG mode. This is suitable for development ONLY. "
                       "Do NOT use in production environments due to security risks.")


# ----------------------------------------------------------------------------------------------------------------------
# Flask Error Handlers
# These functions register custom handlers for various HTTP error codes within the Flask application.
# They ensure that API errors return consistent JSON responses, improve user experience by
# providing clear messages, and log detailed information for debugging.
# ----------------------------------------------------------------------------------------------------------------------
@app.errorhandler(BadRequest)
def handle_bad_request(e: BadRequest):
    """
    Handles HTTP 400 Bad Request errors.
    This error typically signifies issues with the client's request, such as
    malformed JSON, missing required parameters, or invalid input data.
    """
    app_logger.warning(f"Bad Request (400) encountered: {e.description} for request from {request.remote_addr}.")
    response_payload = {
        "status": "error",
        "code": 400,
        "message": AppConfig.MESSAGE_ERROR_INVALID_INPUT # Use a generic message for security and consistency.
                                                        # Can use e.description for more detail in debug mode.
    }
    return make_response(jsonify(response_payload), 400)

@app.errorhandler(MethodNotAllowed)
def handle_method_not_allowed(e: MethodNotAllowed):
    """
    Handles HTTP 405 Method Not Allowed errors.
    This occurs when a client attempts to access a URL with an HTTP method
    that is not supported by the defined route (e.g., trying a GET on a POST-only endpoint).
    """
    app_logger.warning(f"Method Not Allowed (405) encountered: {e.description} for request from {request.remote_addr}.")
    response_payload = {
        "status": "error",
        "code": 405,
        "message": AppConfig.MESSAGE_ERROR_METHOD_NOT_ALLOWED
    }
    return make_response(jsonify(response_payload), 405)

@app.errorhandler(InternalServerError)
def handle_internal_server_error(e: InternalServerError):
    """
    Handles HTTP 500 Internal Server Error.
    This is a general-purpose error message indicating an unexpected condition
    on the server that prevented it from fulfilling the request. It typically
    catches unhandled exceptions within the application logic.
    """
    app_logger.error(
        f"Internal Server Error (500) encountered: {e.description} for request from {request.remote_addr}.",
        exc_info=True # Log the full traceback for debugging.
    )
    response_payload = {
        "status": "error",
        "code": 500,
        "message": AppConfig.MESSAGE_ERROR_INTERNAL_SERVER
    }
    return make_response(jsonify(response_payload), 500)

@app.errorhandler(HTTPException)
def handle_http_exception(e: HTTPException):
    """
    A general handler for all Flask-specific HTTP exceptions (e.g., 404 Not Found, 401 Unauthorized)
    that are not explicitly caught by the more specific handlers above.
    Provides a consistent JSON response structure for all HTTP errors.
    """
    app_logger.error(
        f"HTTP Exception {e.code} encountered: {e.name} - {e.description} for request from {request.remote_addr}.",
        exc_info=True # Log traceback for detailed investigation.
    )
    response_payload = {
        "status": "error",
        "code": e.code,
        "message": e.description if AppConfig.DEBUG_MODE else AppConfig.MESSAGE_ERROR_INTERNAL_SERVER
        # In debug mode, provide the specific error description; otherwise, a generic message.
    }
    return make_response(jsonify(response_payload), e.code)

@app.errorhandler(Exception)
def handle_unhandled_exception(e: Exception):
    """
    A catch-all error handler for any uncaught Python exceptions that occur
    within the Flask application's request processing.
    This is crucial for preventing raw Python stack traces from being exposed to clients
    and ensures all unexpected errors are logged.
    """
    app_logger.critical(
        f"An unhandled application exception occurred: {e} for request from {request.remote_addr}.",
        exc_info=True # Essential for logging the full error details.
    )
    response_payload = {
        "status": "error",
        "code": 500,
        "message": AppConfig.MESSAGE_ERROR_INTERNAL_SERVER
    }
    return make_response(jsonify(response_payload), 500)


# ----------------------------------------------------------------------------------------------------------------------
# API Endpoint Definition: /generate-2fa-qr
# This is the primary API endpoint for generating 2FA QR codes.
# It expects an HTTP POST request with a JSON payload containing 'username' and 'issuer'.
# All input validation, core logic execution, and response formatting happen here.
# ----------------------------------------------------------------------------------------------------------------------
@app.route('/generate-2fa-qr', methods=['POST'])
def generate_2fa_qr_code_api():
    """
    API endpoint to generate a new TOTP secret and its corresponding QR code as a data:image/png URL.
    This endpoint expects a JSON payload in the request body containing 'username' and 'issuer'.

    Request Body (JSON example):
    ```json
    {
        "username": "user@example.com",
        "issuer": "MyCompany"
    }
    ```

    Successful Response (JSON example):
    ```json
    {
        "status": "success",
        "code": 200,
        "message": "2FA QR code generated successfully.",
        "data": {
            "secret": "JBSWY3DPEHPK3PXP",
            "qr_code_url": "data:image/png;base64,iVBORw0K..."
        }
    }
    ```

    Error Response (JSON example):
    ```json
    {
        "status": "error",
        "code": 400,
        "message": "Invalid input. 'username' and 'issuer' are required and must be non-empty strings."
    }
    ```
    """
    client_ip = request.remote_addr
    app_logger.info(f"Received POST request for '/generate-2fa-qr' from {client_ip}.")

    # Step 1: Parse the request body as JSON.
    # Flask's `request.get_json()` method automatically handles content-type checking
    # and JSON deserialization. It returns None if parsing fails or if the content-type is wrong.
    try:
        request_data = request.get_json()
        if request_data is None:
            # This condition implies either missing 'Content-Type: application/json' header
            # or an empty/malformed JSON body.
            app_logger.warning(f"Request body is not valid JSON or is empty from {client_ip}. "
                               "Ensure 'Content-Type: application/json' header is set.")
            raise BadRequest(AppConfig.MESSAGE_ERROR_JSON_PARSE)
        app_logger.debug(f"Successfully parsed JSON request data: {request_data}")
    except BadRequest as e:
        # If Flask's get_json() raises a BadRequest (e.g., due to malformed JSON), re-raise it.
        app_logger.error(f"JSON parsing failed for request from {client_ip}: {e.description}")
        raise
    except Exception as e:
        # Catch any other unexpected errors during JSON parsing.
        app_logger.error(f"Unexpected error during JSON parsing for request from {client_ip}: {e}", exc_info=True)
        raise BadRequest(AppConfig.MESSAGE_ERROR_JSON_PARSE)


    # Step 2: Extract and validate 'username' and 'issuer' from the parsed request data.
    # Use .get() with a default of None to safely retrieve values without KeyError.
    username = request_data.get('username')
    issuer = request_data.get('issuer')

    # Perform comprehensive input validation.
    # Check for existence, type, and non-emptiness after stripping whitespace.
    if not username or not isinstance(username, str) or not username.strip():
        app_logger.warning(f"Validation failed for request from {client_ip}: 'username' is missing, "
                           f"not a string, or empty. Received: '{username}'")
        raise BadRequest(AppConfig.MESSAGE_ERROR_INVALID_INPUT)

    if not issuer or not isinstance(issuer, str) or not issuer.strip():
        app_logger.warning(f"Validation failed for request from {client_ip}: 'issuer' is missing, "
                           f"not a string, or empty. Received: '{issuer}'")
        raise BadRequest(AppConfig.MESSAGE_ERROR_INVALID_INPUT)

    # Sanitize inputs by stripping leading/trailing whitespace.
    # Further sanitization (e.g., regex, length limits) could be added based on requirements.
    username = username.strip()
    issuer = issuer.strip()
    app_logger.debug(f"Validated and sanitized inputs - Username: '{username}', Issuer: '{issuer}'")

    # Step 3: Call the core orchestration function to generate the 2FA QR code data.
    # This function encapsulates all the complex logic of secret generation, URI, and image.
    app_logger.debug(f"Calling generate_2fa_qr_data_url for user '{username}' and issuer '{issuer}'...")
    generation_result = generate_2fa_qr_data_url(username, issuer)
    app_logger.debug(f"Generation result received: secret={'<masked>' if generation_result['secret'] else 'None'}, "
                     f"qr_code_url={'<generated>' if generation_result['qr_code_url'] else 'None'}")


    # Step 4: Check if the generation was successful.
    # The orchestration function returns None for qr_code_url if any step failed internally.
    if generation_result["qr_code_url"] is None:
        app_logger.error(f"Failed to generate QR code URL for user '{username}' due to an internal error.")
        # If the core logic failed, raise an InternalServerError, which will be caught
        # by our Flask error handlers and return a 500 response.
        raise InternalServerError(AppConfig.MESSAGE_ERROR_INTERNAL_SERVER)

    # Step 5: Construct and return the success response.
    # Use Flask's `jsonify` to convert the Python dictionary to a JSON response
    # and set the appropriate HTTP status code (200 OK).
    response_payload = {
        "status": "success",
        "code": 200,
        "message": AppConfig.MESSAGE_SUCCESS_GENERATE,
        "data": generation_result # Contains both 'secret' and 'qr_code_url'
    }
    app_logger.info(f"Successfully responded with 2FA QR code for user '{username}'.")
    return jsonify(response_payload), 200

# ----------------------------------------------------------------------------------------------------------------------
# API Status/Health Check Endpoint
# A simple endpoint to verify that the API service is running and responsive.
# This is useful for monitoring systems and load balancers.
# ----------------------------------------------------------------------------------------------------------------------
@app.route('/health', methods=['GET'])
def health_check():
    """
    A simple health check endpoint to determine if the API service is operational.
    Responds with a JSON object indicating the service status, current UTC timestamp,
    service name, and API version. This is typically used by load balancers or
    orchestration systems (like Kubernetes) to monitor service availability.
    """
    client_ip = request.remote_addr
    app_logger.debug(f"Received health check request from {client_ip}.")
    response_payload = {
        "status": "ok",
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z", # UTC timestamp in ISO 8601 format.
        "service": "2fa-qr-code-generator-api",
        "version": "1.0.0" # Hardcoded for simplicity; could be loaded dynamically from metadata.
    }
    app_logger.debug(f"Responded to health check for {client_ip}.")
    return jsonify(response_payload), 200


# ----------------------------------------------------------------------------------------------------------------------
# Main Execution Block
# This block ensures that the Flask development server is only started when the script is
# executed directly (i.e., not when imported as a module).
# It uses the host and port defined in the AppConfig.
# ----------------------------------------------------------------------------------------------------------------------
if __name__ == '__main__':
    # Log information about the server startup parameters.
    app_logger.info(f"Attempting to start Flask API server on "
                    f"http://{AppConfig.API_HOST}:{AppConfig.API_PORT}/")
    app_logger.info(f"Flask debug mode is currently {'ENABLED' if AppConfig.DEBUG_MODE else 'DISABLED'}.")

    try:
        # Run the Flask development server.
        # `host='0.0.0.0'` makes the server publicly accessible from any IP address.
        # `port=AppConfig.API_PORT` sets the listening port.
        # `debug=AppConfig.DEBUG_MODE` enables/disables Flask's debug features.
        app.run(host=AppConfig.API_HOST, port=AppConfig.API_PORT, debug=AppConfig.DEBUG_MODE)
    except Exception as e:
        app_logger.critical(f"Failed to start Flask API server: {e}", exc_info=True)
    finally:
        app_logger.info("Flask API server has stopped or encountered a critical error during startup.")