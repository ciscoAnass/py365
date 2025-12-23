# language-translation-api.py

"""
This script implements a simple language translation API using Flask and the 'googletrans' library.
It provides a web endpoint to translate text from one language to another, automatically detecting
the source language if not specified.

The API exposes the following endpoints:
- GET /: Provides basic information about the API.
- GET /health: A simple health check endpoint to verify service operational status.
- GET /languages: Lists commonly supported language codes and their human-readable names.
- POST /translate: Accepts text and a target language, returning the translated text.

Requirements:
- Flask: A micro web framework for building the API endpoints.
- googletrans: An unofficial Google Translate API client for performing the actual translation.
  (You might need to install these: pip install Flask googletrans==4.0.0-rc1)

Note on googletrans:
The 'googletrans' library is an unofficial Google Translate API client. It's free and
doesn't require an API key, but it might be unstable for production use due to rate
limiting, CAPTCHAs, or changes in Google Translate's underlying API. For robust,
production-grade applications, it is highly recommended to consider official APIs
like Google Cloud Translation API or DeepL API, which provide service level agreements
and dedicated support. These official APIs would typically require API keys and might
incur costs. This script uses a specific version (4.0.0-rc1) which has shown more
stability recently than older versions of 'googletrans'.

This script aims to be comprehensive, including detailed logging, robust error handling,
flexible configuration options, and extensive comments to illustrate best practices for
building a Flask-based API. It separates concerns into a configuration class, a translation
service class, and Flask application routes with helper functions for consistent responses.
"""

# --- Standard Library Imports ---
import os
import json # Used for JSON manipulation, though Flask handles most of it.
import logging # For comprehensive logging of application events and errors.
import sys # For system-specific parameters and functions, like exiting the script.
from datetime import datetime # For timestamping log entries and API responses.

# --- Third-Party Library Imports (Specify if strictly necessary) ---
# It is essential to install these libraries using pip before running the script:
# pip install Flask googletrans==4.0.0-rc1

try:
    from flask import Flask, request, jsonify, abort
    from googletrans import Translator, LANGUAGES
    # googletrans.constants.DUMMY_REQUEST_ARGS can be imported for reference but isn't actively used here.
    # from googletrans.constants import DUMMY_REQUEST_ARGS
except ImportError as e:
    # This block ensures that the script provides a helpful error message and exits
    # if the required third-party libraries are not installed.
    print(f"Error importing required libraries: {e}", file=sys.stderr)
    print("Please install Flask and googletrans. For example, run:", file=sys.stderr)
    print("pip install Flask googletrans==4.0.0-rc1", file=sys.stderr)
    sys.exit(1) # Exit the application if critical dependencies are missing.

# --- Configuration Settings ---
# This class encapsulates all configurable parameters for the application.
# It allows for easy modification of settings and could be extended to load
# from environment variables, a YAML file, or a dedicated config file for
# more complex deployments.

class AppConfig:
    """
    Configuration class for the Language Translation API application.
    Encapsulates all tunable parameters for easy management and access
    throughout the application.
    """
    # --- Application General Settings ---
    APP_NAME = "LanguageTranslationAPI"
    APP_VERSION = "1.0.0"
    # Debug mode can be controlled via FLASK_DEBUG environment variable.
    # Default to True for development, set to False in production.
    DEBUG_MODE = os.environ.get("FLASK_DEBUG", "True").lower() == "true"
    # Host and Port for the Flask development server.
    # Can be overridden by FLASK_RUN_HOST and FLASK_RUN_PORT environment variables.
    HOST = os.environ.get("FLASK_RUN_HOST", "0.0.0.0") # Listens on all public IPs.
    PORT = int(os.environ.get("FLASK_RUN_PORT", 5000)) # Default port 5000.

    # --- Translation Service Specific Settings ---
    # Default target language to use if the client does not specify one.
    DEFAULT_TARGET_LANGUAGE = os.environ.get("DEFAULT_TARGET_LANG", "en")
    # Timeout in seconds for individual translation requests.
    TRANSLATION_TIMEOUT_SECONDS = int(os.environ.get("TRANSLATION_TIMEOUT", 10))
    # User agent string helps mimic a web browser and is crucial for googletrans
    # to avoid being blocked. It can be customized.
    TRANSLATOR_USER_AGENT = os.environ.get(
        "TRANSLATOR_USER_AGENT",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    )
    # Service URLs for googletrans. Sometimes, one URL might be blocked; providing
    # alternatives can increase reliability.
    TRANSLATOR_SERVICE_URLS = os.environ.get(
        "TRANSLATOR_SERVICE_URLS",
        "translate.google.com,translate.google.co.kr"
    ).split(',')

    # --- Logging Settings ---
    # Log level can be set via LOG_LEVEL environment variable (e.g., DEBUG, INFO, WARNING, ERROR, CRITICAL).
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
    # Path to the log file.
    LOG_FILE_PATH = os.environ.get("LOG_FILE_PATH", "app_translation.log")
    # Format for log messages. Includes timestamp, logger name, level, and message.
    LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    # Timestamp format within log messages.
    LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

    # --- API Response Messages (for consistency and easy modification) ---
    MSG_MISSING_TEXT = "Missing 'text' parameter in request body. Please provide the text to translate."
    MSG_MISSING_TARGET_LANG = "Missing 'target_lang' parameter in request body. Please specify the target language."
    MSG_INVALID_JSON = "Invalid JSON payload. The request body must be a valid JSON object."
    MSG_INVALID_LANGUAGE = "Unsupported or invalid target language code: '{lang_code}'. Please provide a valid ISO 639-1 code."
    MSG_TRANSLATION_FAILED = "Translation failed due to an internal error or external service issue: {error_detail}"
    MSG_INTERNAL_SERVER_ERROR = "An unexpected internal server error occurred. Our team has been notified."
    MSG_HEALTH_OK = "Language Translation Service is up and running smoothly."
    MSG_RESOURCE_NOT_FOUND = "The requested resource was not found. Please check the URL."
    MSG_METHOD_NOT_ALLOWED = "The HTTP method '{method}' is not allowed for this endpoint."

# --- Logging Setup ---
# Configure a comprehensive logging system for the application.
# Log messages will be directed to both the console (stdout) and a designated file.
logging.basicConfig(
    level=AppConfig.LOG_LEVEL, # Set the global logging level.
    format=AppConfig.LOG_FORMAT, # Define the format of log messages.
    datefmt=AppConfig.LOG_DATE_FORMAT, # Define the date/time format for log messages.
    handlers=[
        logging.StreamHandler(sys.stdout), # Stream log messages to standard output (console).
        logging.FileHandler(AppConfig.LOG_FILE_PATH, encoding='utf-8') # Write log messages to a file.
    ]
)
# Get a specific logger instance for the application, using its name for better identification.
logger = logging.getLogger(AppConfig.APP_NAME)
logger.info(f"Application logging initialized with level: {AppConfig.LOG_LEVEL}.")
logger.debug(f"Current application configuration settings: {json.dumps({k: v for k, v in AppConfig.__dict__.items() if not k.startswith('__') and not callable(v)}, indent=2)}")

# --- Global Flask Application Instance ---
# Initialize the Flask application. This instance will handle all incoming web requests.
app = Flask(__name__)
# Configure Flask's debug mode based on our AppConfig.
app.config["DEBUG"] = AppConfig.DEBUG_MODE

# --- Helper Functions for API Responses ---
# These functions standardize the structure of API responses, making them consistent.

def _create_error_response(message: str, status_code: int, error_code: str = "api_error") -> tuple:
    """
    Standardizes error responses for the API.
    All error responses will follow a consistent JSON structure.
    
    Args:
        message (str): A user-friendly, descriptive error message.
        status_code (int): The HTTP status code to return (e.g., 400, 500).
        error_code (str): An internal, programmatic error code for client-side handling.
        
    Returns:
        tuple: A tuple containing a Flask JSON response object and the HTTP status code.
    """
    error_payload = {
        "status": "error",
        "code": error_code,
        "message": message,
        "timestamp": datetime.now().isoformat() # ISO 8601 formatted timestamp.
    }
    logger.warning(f"Returning API error response: Status={status_code}, Code='{error_code}', Message='{message}'")
    return jsonify(error_payload), status_code

def _create_success_response(data: dict, status_code: int = 200) -> tuple:
    """
    Standardizes success responses for the API.
    All successful API responses will follow a consistent JSON structure.
    
    Args:
        data (dict): The primary data payload to include in the response.
        status_code (int): The HTTP status code for the response (default: 200 OK).
        
    Returns:
        tuple: A tuple containing a Flask JSON response object and the HTTP status code.
    """
    success_payload = {
        "status": "success",
        "data": data,
        "timestamp": datetime.now().isoformat() # ISO 8601 formatted timestamp.
    }
    logger.debug(f"Returning API success response: Status={status_code}, Data keys={list(data.keys())}")
    return jsonify(success_payload), status_code

def _get_request_data() -> dict:
    """
    Safely extracts and validates JSON data from the Flask request object.
    
    This function ensures that the incoming request has a valid JSON content type
    and that the JSON payload is parseable and not empty.
    
    Returns:
        dict: The parsed JSON data from the request body.
        
    Raises:
        ValueError: If the request content type is not JSON, or if the JSON
                    payload is invalid or empty.
    """
    # Check if the incoming request's Content-Type header indicates JSON.
    if not request.is_json:
        logger.debug(f"Request content-type is not JSON: {request.content_type}")
        raise ValueError(AppConfig.MSG_INVALID_JSON)
    
    try:
        # Attempt to parse the JSON body.
        data = request.get_json()
        if data is None:
            # If get_json() returns None, it means the JSON body was empty or malformed.
            logger.debug("Request JSON payload was empty or resulted in None after parsing.")
            raise ValueError(AppConfig.MSG_INVALID_JSON)
        logger.debug("Successfully parsed JSON request data.")
        return data
    except Exception as e:
        # Catch any exceptions during JSON parsing (e.g., malformed JSON syntax).
        logger.error(f"Failed to parse JSON request body: {e}", exc_info=True)
        raise ValueError(AppConfig.MSG_INVALID_JSON) from e

# --- Translation Service Class ---
# This class abstracts the details of the 'googletrans' library, providing a clean
# interface for translation operations. It also handles initialization and error
# management specific to the translation process.

class TranslatorService:
    """
    A robust wrapper class for the 'googletrans' library, providing core
    language translation capabilities. This class manages the initialization
    of the translator instance, provides a list of supported languages,
    and handles the complexities and potential errors of the translation logic.
    """
    def __init__(self):
        """
        Initializes the TranslatorService by creating an instance of googletrans.Translator.
        This includes setting up crucial parameters like service URLs, user agent, and timeout
        to enhance reliability and prevent connection issues.
        """
        logger.info("Initializing TranslatorService with googletrans...")
        try:
            # The 'googletrans' library often requires a specific user agent string
            # to mimic a standard web browser. This helps in avoiding IP blocks or
            # CAPTCHA challenges from Google's servers, which might interpret
            # automated requests as malicious.
            self.translator = Translator(
                service_urls=AppConfig.TRANSLATOR_SERVICE_URLS, # List of Google Translate server URLs.
                user_agent=AppConfig.TRANSLATOR_USER_AGENT, # Custom user agent string.
                timeout=AppConfig.TRANSLATION_TIMEOUT_SECONDS # Timeout for translation requests.
            )
            logger.info(f"TranslatorService initialized successfully. Using service URLs: {AppConfig.TRANSLATOR_SERVICE_URLS}, User Agent: '{AppConfig.TRANSLATOR_USER_AGENT}'.")
            
            # Pre-populate the list of supported languages during initialization.
            # googletrans.LANGUAGES is a dictionary mapping language codes to names (e.g., 'en': 'english').
            self._supported_languages = self._prepare_supported_languages()
            logger.info(f"Loaded {len(self._supported_languages)} commonly supported languages for reference.")

        except Exception as e:
            # If the Translator cannot be initialized, it's a critical error that prevents
            # the service from functioning. Log and re-raise.
            logger.critical(f"Failed to initialize googletrans Translator instance: {e}", exc_info=True)
            raise RuntimeError(f"Could not initialize translation service due to an internal error: {e}") from e

    def _prepare_supported_languages(self) -> list:
        """
        Prepares and formats a list of supported languages from googletrans.LANGUAGES.
        
        The native `googletrans.LANGUAGES` is a dictionary (e.g., `{'en': 'english'}`).
        This method transforms it into a more consumer-friendly list of dictionaries:
        `[{'code': 'en', 'name': 'English'}, {'code': 'fr', 'name': 'French'}, ...]`,
        sorted alphabetically by language name.
        
        Returns:
            list: A sorted list of dictionaries, each representing a supported language.
        """
        languages_list = []
        for code, name in LANGUAGES.items():
            languages_list.append({"code": code, "name": name.capitalize()}) # Capitalize for better display.
        # Sort the list of languages by their capitalized name for easy lookup and presentation.
        return sorted(languages_list, key=lambda x: x['name'])

    def is_language_supported(self, lang_code: str) -> bool:
        """
        Checks if a given language code is officially recognized and supported by
        the underlying translation service (googletrans in this case).
        
        Args:
            lang_code (str): The ISO 639-1 language code (e.g., 'en', 'fr', 'es').
            
        Returns:
            bool: True if the language code is found in the supported languages list, False otherwise.
        """
        # The LANGUAGES dictionary from googletrans provides the authoritative list.
        return lang_code.lower() in LANGUAGES

    def get_all_supported_languages(self) -> list:
        """
        Returns the pre-generated list of all supported languages with their
        respective codes and capitalized names.
        
        Returns:
            list: A list of dictionaries, each containing 'code' and 'name' for a language.
        """
        return self._supported_languages

    def translate_text(self, text: str, target_lang: str, source_lang: str = None) -> dict:
        """
        Translates the provided text into the specified target language.
        
        This method encapsulates the actual call to the `googletrans.Translator` instance,
        including language validation and comprehensive error handling.
        
        Args:
            text (str): The string content to be translated. This cannot be empty.
            target_lang (str): The ISO 639-1 code of the desired target language (e.g., 'es' for Spanish).
            source_lang (str, optional): The ISO 639-1 code of the source language.
                                         If provided, it guides the translator. If None,
                                         googletrans will attempt to auto-detect the source language.
                                         Defaults to None.
                                         
        Returns:
            dict: A dictionary containing the original text, the translated text,
                  the detected/provided source language, and the target language.
                  Example: `{'original_text': 'Hello', 'translated_text': 'Hola',
                             'source_lang': 'en', 'target_lang': 'es'}`
                            
        Raises:
            ValueError: If the `target_lang` is not a valid or supported language code.
            TranslationError: If any error occurs during the translation process (e.g.,
                              network issues, service unavailability, API rate limits).
        """
        # Input validation for text and target_lang
        if not text or not isinstance(text, str):
            logger.warning(f"Invalid text provided for translation: '{text}'. Text must be a non-empty string.")
            raise ValueError("Text to translate must be a non-empty string.")
        
        if not self.is_language_supported(target_lang):
            logger.warning(f"Attempted translation to an unsupported target language code: '{target_lang}'.")
            raise ValueError(AppConfig.MSG_INVALID_LANGUAGE.format(lang_code=target_lang))

        logger.info(f"Initiating translation for text (first 70 chars: '{text[:70]}...') "
                    f"from '{source_lang if source_lang else 'auto-detect'}' to '{target_lang}'.")

        try:
            # Perform the actual translation using the googletrans library.
            # 'src' parameter is set to 'auto' for auto-detection if source_lang is not provided.
            translation = self.translator.translate(
                text=text,
                dest=target_lang,
                src=source_lang if source_lang else 'auto'
            )
            
            # Check if the translation object or its text content is valid.
            if not translation or not translation.text:
                logger.error(f"Translation returned an empty or invalid result for text: '{text[:70]}...'. "
                             f"Source: {source_lang}, Target: {target_lang}.")
                raise RuntimeError("Translation service returned an empty result for the given text.")

            result = {
                "original_text": text,
                "translated_text": translation.text,
                "source_lang": translation.src, # The detected or specified source language.
                "target_lang": translation.dest # The target language.
            }
            logger.info(f"Translation successful: from '{translation.src}' to '{translation.dest}'. "
                        f"Translated text (first 70 chars): '{translation.text[:70]}...'.")
            logger.debug(f"Full translation result: {json.dumps(result, indent=2)}")
            return result

        except Exception as e:
            # Catch-all for any exceptions that might occur during the translation call.
            # This could be network errors, rate limiting, or issues within googletrans itself.
            logger.error(f"Translation failed for text (first 70 chars: '{text[:70]}...') "
                         f"to '{target_lang}' (source: {source_lang}): {e}", exc_info=True)
            # Re-raise with a more specific custom exception for API handling.
            raise TranslationError(
                AppConfig.MSG_TRANSLATION_FAILED.format(error_detail=str(e))
            ) from e

# --- Custom Exception Classes ---
# Define custom exceptions to provide more granular error handling within the API.

class TranslationError(Exception):
    """
    Custom exception specifically for errors encountered during the language
    translation process, typically originating from the `TranslatorService`.
    This allows for distinct error handling in API routes.
    """
    pass

# --- Initialize Translation Service ---
# Create a single instance of the TranslationService at application startup.
# This ensures that the translator is ready before any requests are handled.
# If initialization fails, the application should not start.
try:
    translation_service = TranslatorService()
    logger.info("TranslationService successfully instantiated.")
except RuntimeError as e:
    logger.critical(f"Application cannot start because the TranslationService failed to initialize: {e}. Exiting.")
    sys.exit(1) # Terminate the application if the core service is unavailable.

# --- Flask API Endpoints ---
# Define the various routes (endpoints) that the API will expose.

@app.route("/", methods=["GET"])
def root_info() -> tuple:
    """
    Root endpoint for the API. Provides basic information about the service,
    its version, and a brief overview of available endpoints.
    
    Returns:
        tuple: A Flask JSON response with API information and HTTP status 200 (OK).
    """
    logger.debug("Received request on root endpoint '/'.")
    info_payload = {
        "api_name": AppConfig.APP_NAME,
        "version": AppConfig.APP_VERSION,
        "description": "A simple language translation API built with Flask and the 'googletrans' library.",
        "usage_notes": "For production use, consider official APIs like Google Cloud Translation or DeepL for better reliability and support.",
        "available_endpoints": {
            "/health": "GET - Check the operational status of the service.",
            "/languages": "GET - Retrieve a list of all supported language codes and their names.",
            "/translate": "POST - Translate text from a source language to a target language. Requires JSON payload with 'text' and 'target_lang'."
        },
        "current_server_time": datetime.now().isoformat()
    }
    return _create_success_response(info_payload)

@app.route("/health", methods=["GET"])
def health_check() -> tuple:
    """
    Health check endpoint. This simple endpoint verifies that the Flask application
    is running and responsive. It does not explicitly check the external translation
    service, but its success implies the application itself is active.
    
    Returns:
        tuple: A Flask JSON response indicating service status and HTTP status 200 (OK).
    """
    logger.debug("Received request on health check endpoint '/health'.")
    health_payload = {
        "status": "healthy",
        "message": AppConfig.MSG_HEALTH_OK,
        "app_name": AppConfig.APP_NAME,
        "app_version": AppConfig.APP_VERSION,
        "current_server_time": datetime.now().isoformat()
    }
    return _create_success_response(health_payload)

@app.route("/languages", methods=["GET"])
def get_supported_languages() -> tuple:
    """
    Endpoint to retrieve a list of all language codes and their corresponding
    human-readable names that are supported by the underlying translation service.
    
    Returns:
        tuple: A Flask JSON response with a list of languages and HTTP status 200 (OK).
    """
    logger.info("Received request for the list of supported languages on '/languages'.")
    try:
        languages = translation_service.get_all_supported_languages()
        logger.debug(f"Successfully retrieved {len(languages)} supported languages.")
        return _create_success_response({"languages": languages})
    except Exception as e:
        # This catch-all error handling is for unexpected issues during language list retrieval,
        # though it's less likely given the list is pre-generated on startup.
        logger.error(f"Failed to retrieve supported languages list: {e}", exc_info=True)
        return _create_error_response(
            AppConfig.MSG_INTERNAL_SERVER_ERROR, 500, "languages_fetch_failed"
        )

@app.route("/translate", methods=["POST"])
def translate_text_endpoint() -> tuple:
    """
    Primary API endpoint for text translation.
    
    This endpoint expects a JSON payload in the request body.
    
    Required parameters in JSON:
    - 'text': The string content that needs to be translated.
    - 'target_lang': The ISO 639-1 code of the language into which the text should be translated (e.g., "es" for Spanish).
    
    Optional parameters in JSON:
    - 'source_lang': The ISO 639-1 code of the original language of the text. If omitted,
                     the translation service will attempt to automatically detect the source language.
    
    Example Request Body (JSON):
    ```json
    {
        "text": "Hello, how are you today?",
        "target_lang": "fr",
        "source_lang": "en" (optional)
    }
    ```
    
    Returns:
        tuple: A Flask JSON response containing the translation result on success,
               or an appropriate error message and HTTP status code on failure.
    """
    logger.info(f"Received POST request on '/translate' from {request.remote_addr}.")
    
    try:
        # Attempt to parse the incoming JSON request data.
        data = _get_request_data()

        # Extract required parameters from the parsed JSON payload.
        text_to_translate = data.get("text")
        target_language = data.get("target_lang")
        source_language = data.get("source_lang") # This parameter is optional.

        # --- Input Validation ---
        if not text_to_translate or not isinstance(text_to_translate, str) or not text_to_translate.strip():
            logger.warning("Validation failed: 'text' parameter is missing, empty, or not a string.")
            return _create_error_response(AppConfig.MSG_MISSING_TEXT, 400, "missing_text")
        
        if not target_language or not isinstance(target_language, str) or not target_language.strip():
            logger.warning("Validation failed: 'target_lang' parameter is missing, empty, or not a string.")
            return _create_error_response(AppConfig.MSG_MISSING_TARGET_LANG, 400, "missing_target_lang")

        logger.debug(f"Attempting translation: Text='{text_to_translate[:100]}...', "
                     f"Target='{target_language}', Source='{source_language if source_language else 'auto'}'.")

        # Call the translation service to perform the actual translation.
        translation_result = translation_service.translate_text(
            text=text_to_translate,
            target_lang=target_language,
            source_lang=source_language
        )
        
        logger.info("Text translation completed successfully.")
        return _create_success_response(translation_result, 200)

    except ValueError as ve:
        # This block handles validation errors, such as invalid JSON or unsupported language codes.
        error_message = str(ve)
        if AppConfig.MSG_INVALID_JSON in error_message:
            return _create_error_response(AppConfig.MSG_INVALID_JSON, 400, "invalid_json_payload")
        elif AppConfig.MSG_INVALID_LANGUAGE.split(':')[0] in error_message:
            # Attempt to extract the specific invalid language code for a more informative error.
            lang_code_detail = error_message.split(':')[-1].strip().replace("'", "")
            return _create_error_response(
                AppConfig.MSG_INVALID_LANGUAGE.format(lang_code=lang_code_detail if lang_code_detail else 'unknown'),
                400, "invalid_language_code"
            )
        else:
            logger.error(f"An unexpected ValueError occurred during translation request processing: {ve}", exc_info=True)
            return _create_error_response(AppConfig.MSG_INTERNAL_SERVER_ERROR, 500, "unexpected_validation_error")

    except TranslationError as te:
        # This block specifically catches errors reported by the `TranslatorService`
        # (e.g., issues with the external translation API).
        logger.error(f"Translation service reported a specific error: {te}", exc_info=True)
        return _create_error_response(str(te), 500, "translation_service_error")

    except Exception as e:
        # This is a general catch-all for any other unforeseen or unhandled exceptions
        # that might occur during the processing of the translation request.
        logger.critical(f"An unhandled exception occurred in /translate endpoint: {e}", exc_info=True)
        return _create_error_response(AppConfig.MSG_INTERNAL_SERVER_ERROR, 500, "unhandled_exception")

# --- Flask Global Error Handlers ---
# These handlers catch HTTP errors that Flask might raise automatically
# (e.g., for routes not found, invalid methods). They ensure all error responses
# follow the standardized JSON format defined by `_create_error_response`.

@app.errorhandler(400)
def handle_bad_request_error(error) -> tuple:
    """Handles HTTP 400 Bad Request errors globally."""
    logger.warning(f"Global Error Handler: HTTP 400 Bad Request - {error.description if hasattr(error, 'description') else str(error)}")
    return _create_error_response(
        f"Bad Request: {error.description if hasattr(error, 'description') else 'The request could not be understood by the server due to malformed syntax.'}",
        400, "bad_request"
    )

@app.errorhandler(404)
def handle_not_found_error(error) -> tuple:
    """Handles HTTP 404 Not Found errors globally."""
    logger.warning(f"Global Error Handler: HTTP 404 Not Found - Requested path: {request.path}")
    return _create_error_response(
        AppConfig.MSG_RESOURCE_NOT_FOUND, 404, "not_found"
    )

@app.errorhandler(405)
def handle_method_not_allowed_error(error) -> tuple:
    """Handles HTTP 405 Method Not Allowed errors globally."""
    logger.warning(f"Global Error Handler: HTTP 405 Method Not Allowed - Method '{request.method}' for path '{request.path}'")
    return _create_error_response(
        AppConfig.MSG_METHOD_NOT_ALLOWED.format(method=request.method), 405, "method_not_allowed"
    )

@app.errorhandler(500)
def handle_internal_server_error(error) -> tuple:
    """
    Handles HTTP 500 Internal Server Error globally.
    This is a crucial handler for catching unexpected server-side issues.
    """
    logger.critical(f"Global Error Handler: HTTP 500 Internal Server Error - An unhandled exception occurred: {error}", exc_info=True)
    return _create_error_response(
        AppConfig.MSG_INTERNAL_SERVER_ERROR, 500, "internal_server_error"
    )

# --- Main Execution Block ---
# This block ensures that the Flask application only runs when the script is executed directly.

if __name__ == "__main__":
    logger.info(f"Starting {AppConfig.APP_NAME} v{AppConfig.APP_VERSION}...")
    logger.info(f"Application running in Debug Mode: {AppConfig.DEBUG_MODE}")
    logger.info(f"Server will listen on: http://{AppConfig.HOST}:{AppConfig.PORT}")
    
    # In a production deployment, it is highly recommended to use a production-ready
    # WSGI server (e.g., Gunicorn, uWSGI) to serve the Flask application.
    # The `app.run()` method is primarily for development and debugging purposes.
    try:
        app.run(
            host=AppConfig.HOST,
            port=AppConfig.PORT,
            debug=AppConfig.DEBUG_MODE,
            use_reloader=AppConfig.DEBUG_MODE # Auto-reload code changes in debug mode.
        )
    except Exception as run_error:
        # Catch any errors that prevent the Flask development server from starting.
        logger.critical(f"Failed to start Flask application server: {run_error}", exc_info=True)
        sys.exit(1) # Exit the application if it cannot start.

    logger.info(f"{AppConfig.APP_NAME} has stopped.")
```