import os
import smtplib
import ssl
import logging
import re
import datetime
import uuid
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid

# Standard Flask imports (Flask is a strictly necessary 3rd party library for this microservice)
from flask import Flask, request, jsonify, make_response
from http import HTTPStatus # For cleaner status code representation

# It is highly recommended to use python-dotenv for local development to manage environment variables.
# You can install it with `pip install python-dotenv` and then add `from dotenv import load_dotenv; load_dotenv()`
# at the very beginning of the script to load variables from a .env file.
# For production, environment variables should be set directly in the deployment environment.

# --- Configuration Management ---
class EmailApiConfig:
    """
    Manages all configuration settings for the Email Sending API.
    Loads settings from environment variables, providing default values where appropriate.
    Raises an error if critical environment variables are not set.
    """
    _instance = None # Singleton pattern to ensure only one config object exists

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(EmailApiConfig, cls).__new__(cls)
            cls._instance._initialize_config()
        return cls._instance

    def _initialize_config(self):
        """Initializes configuration properties from environment variables."""
        self.SMTP_HOST = os.environ.get('SMTP_HOST')
        self.SMTP_PORT = int(os.environ.get('SMTP_PORT', 587)) # Default to 587 for TLS
        self.SMTP_USERNAME = os.environ.get('SMTP_USERNAME')
        self.SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD')
        self.DEFAULT_SENDER_EMAIL = os.environ.get('DEFAULT_SENDER_EMAIL')
        self.USE_TLS = self._str_to_bool(os.environ.get('USE_TLS', 'True')) # Default to True
        self.DEBUG_MODE = self._str_to_bool(os.environ.get('FLASK_DEBUG', 'False')) # Flask debug mode
        self.LOG_FILE_PATH = os.environ.get('LOG_FILE_PATH', 'email_api.log')
        self.FLASK_PORT = int(os.environ.get('FLASK_PORT', 5000))

        self._validate_critical_settings()
        self._log_initial_settings()

    def _str_to_bool(self, s):
        """Converts a string representation to a boolean."""
        return s.lower() in ('true', '1', 't', 'y', 'yes')

    def _validate_critical_settings(self):
        """
        Validates that all essential SMTP settings are provided.
        Raises a ValueError if any critical setting is missing.
        """
        missing_vars = []
        if not self.SMTP_HOST:
            missing_vars.append('SMTP_HOST')
        if not self.SMTP_USERNAME:
            missing_vars.append('SMTP_USERNAME')
        if not self.SMTP_PASSWORD:
            missing_vars.append('SMTP_PASSWORD')

        if missing_vars:
            raise ValueError(
                f"Critical environment variables are missing: {', '.join(missing_vars)}. "
                "Please set them before running the application. "
                "For local development, consider using a .env file with `python-dotenv`."
            )
        
        # Log a warning if default sender is not set, as it's good practice
        if not self.DEFAULT_SENDER_EMAIL:
            logging.warning("DEFAULT_SENDER_EMAIL is not set. The 'from' address in the payload will be used directly. "
                            "This might lead to issues if the SMTP server requires a specific sender.")


    def _log_initial_settings(self):
        """Logs the configuration settings (excluding sensitive data)."""
        logging.info("--- Email API Configuration Loaded ---")
        logging.info(f"SMTP Host: {self.SMTP_HOST}")
        logging.info(f"SMTP Port: {self.SMTP_PORT}")
        logging.info(f"SMTP Username: {self.SMTP_USERNAME[:3]}***{self.SMTP_USERNAME[-3:] if self.SMTP_USERNAME else ''}") # Mask username
        logging.info(f"Default Sender Email: {self.DEFAULT_SENDER_EMAIL if self.DEFAULT_SENDER_EMAIL else 'Not Set'}")
        logging.info(f"Use TLS: {self.USE_TLS}")
        logging.info(f"Debug Mode (Flask): {self.DEBUG_MODE}")
        logging.info(f"Log File Path: {self.LOG_FILE_PATH}")
        logging.info(f"Flask Server Port: {self.FLASK_PORT}")
        logging.info("------------------------------------")

    # Property decorators for read-only access to config attributes
    @property
    def smtp_host(self):
        return self.SMTP_HOST

    @property
    def smtp_port(self):
        return self.SMTP_PORT

    @property
    def smtp_username(self):
        return self.SMTP_USERNAME

    @property
    def smtp_password(self):
        return self.SMTP_PASSWORD

    @property
    def default_sender_email(self):
        return self.DEFAULT_SENDER_EMAIL

    @property
    def use_tls(self):
        return self.USE_TLS

    @property
    def debug_mode(self):
        return self.DEBUG_MODE

    @property
    def log_file_path(self):
        return self.LOG_FILE_PATH
    
    @property
    def flask_port(self):
        return self.FLASK_PORT


# --- Logging Setup ---
def setup_logging(config: EmailApiConfig):
    """
    Configures the application-wide logging system.
    Sets up a file handler and a stream handler (console output).
    Log level is controlled by the application's debug mode.
    """
    log_level = logging.DEBUG if config.debug_mode else logging.INFO
    
    # Create a custom logger
    logger = logging.getLogger(__name__) # Use __name__ to get a logger specific to this module
    logger.setLevel(log_level)

    # Prevent adding multiple handlers if setup_logging is called multiple times
    if not logger.handlers:
        # Create handlers
        c_handler = logging.StreamHandler()
        f_handler = logging.FileHandler(config.log_file_path)

        # Set levels for handlers
        c_handler.setLevel(logging.INFO) # Console generally shows INFO and above
        f_handler.setLevel(log_level)    # File handler respects the global log level

        # Create formatters and add them to handlers
        c_format = logging.Formatter('%(levelname)s: %(name)s: %(message)s')
        f_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        c_handler.setFormatter(c_format)
        f_handler.setFormatter(f_format)

        # Add handlers to the logger
        logger.addHandler(c_handler)
        logger.addHandler(f_handler)
        logger.info(f"Logging configured. Log level set to {logging.getLevelName(log_level)}")
        logger.info(f"Logs will be written to: {config.log_file_path}")

    return logger

# --- Utility Functions for Email Handling ---
def is_valid_email(email_address: str) -> bool:
    """
    Performs a basic validation of an email address using a regular expression.
    This regex is fairly comprehensive but not exhaustive (e.g., does not validate top-level domain existence).
    """
    if not isinstance(email_address, str):
        return False
    
    # A robust regex for email validation (from Django's EmailValidator, simplified)
    email_regex = re.compile(
        r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
    )
    is_valid = bool(email_regex.match(email_address))
    if not is_valid:
        app_logger.warning(f"Email address '{email_address}' failed basic validation.")
    return is_valid

def compose_email_message(
    from_addr: str,
    to_addr: str,
    subject: str,
    body_plain: str,
    body_html: str = None,
    cc_addrs: list = None,
    bcc_addrs: list = None,
    reply_to_addr: str = None
) -> MIMEMultipart:
    """
    Constructs a complete email message using MIME types, supporting both
    plain text and HTML bodies within a multipart/alternative container.
    Adds essential headers like Date and Message-ID.
    """
    # Create the base message container.
    # A 'multipart/alternative' container is used to send both plain text and HTML.
    # The recipient's email client will automatically display the version it prefers/can handle.
    msg = MIMEMultipart('alternative')
    msg['From'] = from_addr
    msg['To'] = to_addr # This can be a comma-separated string for multiple recipients

    # Handle multiple 'To' addresses if provided as a list.
    # The API payload only specifies a single 'to', but this function can handle more.
    if isinstance(to_addr, list):
        msg['To'] = ', '.join(to_addr)
    else:
        msg['To'] = to_addr

    msg['Subject'] = subject
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid(domain='email-sending-api.local') # Unique message ID

    # Add optional headers
    if cc_addrs:
        msg['Cc'] = ', '.join(cc_addrs)
    if bcc_addrs:
        # BCC is handled by the SMTP client, not a header in the message itself
        # This means the BCC header should NOT be added to the MIME message.
        pass
    if reply_to_addr:
        msg['Reply-To'] = reply_to_addr

    # Attach parts of the email message.
    # The order matters: plain text should come before HTML.
    part1 = MIMEText(body_plain, 'plain', 'utf-8')
    msg.attach(part1)

    if body_html:
        part2 = MIMEText(body_html, 'html', 'utf-8')
        msg.attach(part2)
    
    app_logger.debug(f"Email message composed from '{from_addr}' to '{to_addr}' with subject '{subject}'.")
    return msg

# --- SMTP Client Service ---
class SmtpServiceClient:
    """
    Handles the actual connection, authentication, and sending of emails
    via an SMTP server using smtplib. Encapsulates all SMTP-related logic.
    """
    def __init__(self, config: EmailApiConfig, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.smtp_server = None
        self._context = None # SSL context for secure connection

        self.logger.info("SmtpServiceClient initialized.")

    def _get_ssl_context(self):
        """
        Creates and returns an SSL context for secure SMTP communication (TLS).
        Caches the context for performance.
        """
        if self._context is None:
            self.logger.debug("Creating a new SSL context.")
            self._context = ssl.create_default_context()
            # Recommended security practices for TLS:
            # context.check_hostname = True # Ensure hostname matches certificate
            # context.verify_mode = ssl.CERT_REQUIRED # Ensure server certificate is valid
            # For simplicity in a general microservice, default context is often sufficient
            # for common providers like SendGrid/SES, as they are well-known CAs.
        return self._context

    def _connect(self):
        """
        Establishes a connection to the SMTP server.
        Handles both non-TLS (rarely used now) and TLS connections.
        """
        if self.smtp_server:
            self.logger.warning("SMTP server connection already exists. Attempting to quit previous and reconnect.")
            try:
                self.smtp_server.quit()
            except smtplib.SMTPServerDisconnected:
                self.logger.debug("Previous SMTP server was already disconnected.")
            self.smtp_server = None

        try:
            self.logger.info(f"Attempting to connect to SMTP server at {self.config.smtp_host}:{self.config.smtp_port}...")
            if self.config.use_tls:
                # Use SMTPS for implicit TLS on a dedicated port (e.g., 465)
                # or SMTP with STARTTLS on port 587.
                # Here we assume port 587 with STARTTLS.
                # For implicit TLS (port 465), one would use smtplib.SMTP_SSL()
                self.smtp_server = smtplib.SMTP(self.config.smtp_host, self.config.smtp_port, timeout=30)
                self.logger.debug("Connected to SMTP server. Initiating STARTTLS...")
                self.smtp_server.ehlo() # Can be called before or after starttls
                self.smtp_server.starttls(context=self._get_ssl_context())
                self.smtp_server.ehlo() # Calling again after STARTTLS
                self.logger.info("STARTTLS initiated successfully.")
            else:
                self.smtp_server = smtplib.SMTP(self.config.smtp_host, self.config.smtp_port, timeout=30)
                self.logger.warning("Connecting to SMTP server without TLS. This is INSECURE for production environments.")
            self.logger.info("Successfully connected to SMTP server.")
        except smtplib.SMTPConnectError as e:
            self.logger.error(f"SMTP connection failed: {e}")
            raise ConnectionError(f"Failed to connect to SMTP server: {e}")
        except smtplib.SMTPException as e:
            self.logger.error(f"An SMTP error occurred during connection: {e}")
            raise ConnectionError(f"SMTP error during connection: {e}")
        except Exception as e:
            self.logger.error(f"An unexpected error occurred during SMTP connection: {e}", exc_info=True)
            raise ConnectionError(f"Unexpected error during connection: {e}")

    def _authenticate(self):
        """Authenticates with the SMTP server using the provided credentials."""
        if not self.smtp_server:
            self.logger.error("Cannot authenticate: No active SMTP server connection.")
            raise ConnectionError("No active SMTP server connection.")

        try:
            self.logger.info(f"Attempting to authenticate as user: {self.config.smtp_username}...")
            self.smtp_server.login(self.config.smtp_username, self.config.smtp_password)
            self.logger.info("Successfully authenticated with SMTP server.")
        except smtplib.SMTPAuthenticationError as e:
            self.logger.error(f"SMTP authentication failed for user '{self.config.smtp_username}': {e}")
            raise smtplib.SMTPAuthenticationError(e.smtp_code, e.smtp_error)
        except smtplib.SMTPException as e:
            self.logger.error(f"An SMTP error occurred during authentication: {e}")
            raise ConnectionError(f"SMTP error during authentication: {e}")
        except Exception as e:
            self.logger.error(f"An unexpected error occurred during SMTP authentication: {e}", exc_info=True)
            raise ConnectionError(f"Unexpected error during authentication: {e}")

    def send_email(
        self,
        from_addr: str,
        to_addr: str,
        subject: str,
        body_plain: str,
        body_html: str = None,
        cc_addrs: list = None,
        bcc_addrs: list = None
    ) -> dict:
        """
        Composes and sends an email. Manages the full lifecycle: connect, authenticate, send, quit.
        Returns a dictionary indicating success or failure.
        """
        email_id = str(uuid.uuid4()) # Generate a unique ID for this email sending attempt
        self.logger.info(f"[{email_id}] Preparing to send email: From='{from_addr}', To='{to_addr}', Subject='{subject}'")

        try:
            # 1. Compose the email message
            msg = compose_email_message(
                from_addr=from_addr,
                to_addr=to_addr,
                subject=subject,
                body_plain=body_plain,
                body_html=body_html,
                cc_addrs=cc_addrs
            )
            
            # Prepare recipient list for smtplib.send_message
            recipients = [to_addr] if isinstance(to_addr, str) else to_addr
            if cc_addrs:
                recipients.extend(cc_addrs)
            if bcc_addrs:
                recipients.extend(bcc_addrs)
            
            # Ensure no duplicate recipients if any overlap between To, CC, BCC
            recipients = list(set(recipients)) 

            # 2. Establish connection and authenticate
            self._connect()
            self._authenticate()

            # 3. Send the email
            self.logger.info(f"[{email_id}] Attempting to send message...")
            self.smtp_server.send_message(msg, from_addr=from_addr, to_addrs=recipients)
            self.logger.info(f"[{email_id}] Email successfully sent from '{from_addr}' to '{to_addr}'.")
            
            return {
                "status": "success",
                "message": "Email sent successfully",
                "email_id": email_id
            }

        except (ConnectionError, smtplib.SMTPAuthenticationError) as e:
            self.logger.error(f"[{email_id}] Email sending failed due to connection or authentication issue: {e}")
            return {
                "status": "error",
                "message": f"Connection or authentication error: {e}",
                "email_id": email_id
            }
        except smtplib.SMTPDataError as e:
            self.logger.error(f"[{email_id}] SMTP Data Error (e.g., recipient rejected): Code={e.smtp_code}, Error='{e.smtp_error}'")
            return {
                "status": "error",
                "message": f"SMTP Data Error: {e.smtp_error} (Code: {e.smtp_code})",
                "email_id": email_id
            }
        except smtplib.SMTPRecipientsRefused as e:
            self.logger.error(f"[{email_id}] All recipients refused: {e.recipients}")
            return {
                "status": "error",
                "message": f"SMTP Error: All recipients refused: {e.recipients}",
                "email_id": email_id
            }
        except smtplib.SMTPSenderRefused as e:
            self.logger.error(f"[{email_id}] Sender address '{from_addr}' refused: Code={e.smtp_code}, Error='{e.smtp_error}'")
            return {
                "status": "error",
                "message": f"SMTP Error: Sender '{from_addr}' refused: {e.smtp_error} (Code: {e.smtp_code})",
                "email_id": email_id
            }
        except smtplib.SMTPException as e:
            self.logger.error(f"[{email_id}] An unhandled SMTP error occurred: {e}", exc_info=True)
            return {
                "status": "error",
                "message": f"An unhandled SMTP error occurred: {e}",
                "email_id": email_id
            }
        except Exception as e:
            self.logger.error(f"[{email_id}] An unexpected error occurred during email sending: {e}", exc_info=True)
            return {
                "status": "error",
                "message": f"An unexpected internal server error occurred: {e}",
                "email_id": email_id
            }
        finally:
            # 4. Quit the SMTP server connection to ensure it's properly closed
            if self.smtp_server:
                try:
                    self.smtp_server.quit()
                    self.logger.debug(f"[{email_id}] SMTP server connection closed.")
                except smtplib.SMTPServerDisconnected:
                    self.logger.debug(f"[{email_id}] SMTP server was already disconnected.")
                except Exception as e:
                    self.logger.warning(f"[{email_id}] Error while quitting SMTP server: {e}")
                self.smtp_server = None # Reset for next use


# --- Flask Application Setup ---
app = Flask(__name__)

# Load configuration and setup logging before routing
try:
    api_config = EmailApiConfig()
    app_logger = setup_logging(api_config)
    smtp_client = SmtpServiceClient(api_config, app_logger)
except ValueError as e:
    # If critical environment variables are missing, the app cannot start.
    # Log the error and exit or raise it for the WSGI server to handle.
    # For a direct script run, print and exit. For WSGI, it will likely crash on import.
    print(f"FATAL CONFIGURATION ERROR: {e}", flush=True)
    app_logger.critical(f"FATAL CONFIGURATION ERROR: {e}")
    # In a production WSGI environment, this might lead to a 500 error on startup.
    # For standalone script, sys.exit(1) would be appropriate.
    # We'll let Flask's debug mode (if on) surface this, or rely on WSGI server to report.


# --- Flask Routes ---
@app.route('/')
def health_check():
    """
    A simple health check endpoint to verify the API is running.
    """
    app_logger.info("Health check endpoint accessed.")
    return jsonify({
        "status": "healthy",
        "message": "Email Sending API is operational.",
        "timestamp": datetime.datetime.now().isoformat()
    }), HTTPStatus.OK # 200 OK

@app.route('/send-email', methods=['POST'])
def send_email_api():
    """
    API endpoint to send emails.
    Expects a JSON payload with 'to', 'from', 'subject', and 'body' (plain text).
    An optional 'html_body' field can be provided for HTML content.
    Optional 'cc', 'bcc' (lists of emails) can also be provided.
    """
    app_logger.info(f"Received POST request for /send-email from {request.remote_addr}")

    if not request.is_json:
        app_logger.warning("Request content-type is not application/json.")
        return jsonify({
            "status": "error",
            "message": "Request must be JSON."
        }), HTTPStatus.BAD_REQUEST # 400 Bad Request

    payload = request.get_json()
    app_logger.debug(f"Received payload: {payload}")

    # --- Payload Validation ---
    required_fields = ['to', 'subject', 'body']
    missing_fields = [field for field in required_fields if field not in payload]
    if missing_fields:
        app_logger.warning(f"Missing required fields in payload: {', '.join(missing_fields)}")
        return jsonify({
            "status": "error",
            "message": f"Missing required fields: {', '.join(missing_fields)}"
        }), HTTPStatus.BAD_REQUEST

    # Extract fields
    to_address = payload.get('to')
    from_address = payload.get('from') # Optional, will default to config if not provided
    subject = payload.get('subject')
    body_plain = payload.get('body')
    body_html = payload.get('html_body') # Optional HTML body
    cc_addrs = payload.get('cc', []) # Optional CC list
    bcc_addrs = payload.get('bcc', []) # Optional BCC list

    # Validate 'to' address
    if not is_valid_email(to_address):
        app_logger.warning(f"Invalid 'to' email address provided: '{to_address}'")
        return jsonify({
            "status": "error",
            "message": f"Invalid 'to' email address format: '{to_address}'"
        }), HTTPStatus.BAD_REQUEST
    
    # If 'from' address is not provided in payload, use the default from config
    if not from_address:
        if api_config.default_sender_email:
            from_address = api_config.default_sender_email
            app_logger.info(f"Using default sender email from config: '{from_address}'")
        else:
            app_logger.warning("No 'from' address in payload and no DEFAULT_SENDER_EMAIL configured.")
            return jsonify({
                "status": "error",
                "message": "No 'from' address provided in payload and no default sender email configured."
            }), HTTPStatus.BAD_REQUEST
    elif not is_valid_email(from_address):
        app_logger.warning(f"Invalid 'from' email address provided: '{from_address}'")
        return jsonify({
            "status": "error",
            "message": f"Invalid 'from' email address format: '{from_address}'"
        }), HTTPStatus.BAD_REQUEST

    # Validate CC/BCC addresses if present
    invalid_cc = [addr for addr in cc_addrs if not is_valid_email(addr)]
    if invalid_cc:
        app_logger.warning(f"Invalid CC email addresses found: {invalid_cc}")
        return jsonify({
            "status": "error",
            "message": f"Invalid CC email address format(s): {', '.join(invalid_cc)}"
        }), HTTPStatus.BAD_REQUEST

    invalid_bcc = [addr for addr in bcc_addrs if not is_valid_email(addr)]
    if invalid_bcc:
        app_logger.warning(f"Invalid BCC email addresses found: {invalid_bcc}")
        return jsonify({
            "status": "error",
            "message": f"Invalid BCC email address format(s): {', '.join(invalid_bcc)}"
        }), HTTPStatus.BAD_REQUEST

    # Call the SMTP client to send the email
    send_result = smtp_client.send_email(
        from_addr=from_address,
        to_addr=to_address,
        subject=subject,
        body_plain=body_plain,
        body_html=body_html,
        cc_addrs=cc_addrs,
        bcc_addrs=bcc_addrs
    )

    if send_result["status"] == "success":
        app_logger.info(f"API request for email_id {send_result['email_id']} completed successfully.")
        return jsonify(send_result), HTTPStatus.OK # 200 OK
    else:
        app_logger.error(f"API request for email_id {send_result.get('email_id', 'N/A')} failed: {send_result['message']}")
        # Determine appropriate HTTP status based on error type
        if "Authentication" in send_result["message"] or "Connection" in send_result["message"]:
            return jsonify(send_result), HTTPStatus.INTERNAL_SERVER_ERROR # 500 Internal Server Error
        elif "SMTP Data Error" in send_result["message"] or "Recipients refused" in send_result["message"] or "Sender refused" in send_result["message"]:
            # If the SMTP server refused the request due to bad data (e.g., bad recipient), it's a client error.
            return jsonify(send_result), HTTPStatus.BAD_REQUEST # 400 Bad Request
        else:
            return jsonify(send_result), HTTPStatus.INTERNAL_SERVER_ERROR # Default to 500 for unclassified errors

# --- Global Error Handlers ---
@app.errorhandler(HTTPStatus.NOT_FOUND) # 404
def not_found_error(error):
    """Handles 404 Not Found errors."""
    app_logger.warning(f"404 Not Found: {request.path}")
    return make_response(jsonify({
        "status": "error",
        "message": f"The requested URL '{request.path}' was not found on the server. Please check the endpoint."
    }), HTTPStatus.NOT_FOUND)

@app.errorhandler(HTTPStatus.METHOD_NOT_ALLOWED) # 405
def method_not_allowed_error(error):
    """Handles 405 Method Not Allowed errors."""
    app_logger.warning(f"405 Method Not Allowed for {request.method} {request.path}")
    return make_response(jsonify({
        "status": "error",
        "message": f"The method '{request.method}' is not allowed for the requested URL. Allowed methods are: {request.url_rule.methods if request.url_rule else 'N/A'}"
    }), HTTPStatus.METHOD_NOT_ALLOWED)

@app.errorhandler(Exception) # General internal server error (500)
def internal_error(error):
    """Handles any unhandled exceptions, returning a generic 500 error."""
    app_logger.exception("An unhandled internal server error occurred!")
    return make_response(jsonify({
        "status": "error",
        "message": "An unexpected internal server error occurred. Please try again later or contact support."
    }), HTTPStatus.INTERNAL_SERVER_ERROR)

# --- Main Application Runner ---
if __name__ == '__main__':
    app_logger.info(f"Starting Flask application in {'DEBUG' if api_config.debug_mode else 'PRODUCTION'} mode on port {api_config.flask_port}...")
    app.run(host='0.0.0.0', port=api_config.flask_port, debug=api_config.debug_mode)
    app_logger.info("Flask application stopped.")