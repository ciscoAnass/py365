import argparse
import logging
import sys
import os
import ssl
from datetime import timedelta

# It's explicitly stated that ldap3 is required.
# If it's not installed, the script will naturally fail.
# A quick note for the user about installation can be added in comments.
# If you encounter an ImportError, please install ldap3 using:
# pip install ldap3
from ldap3 import Server, Connection, SUBTREE, ALL, NTLM, SASL, GSSAPI, core
from ldap3.core.exceptions import LDAPInvalidCredentialsResult, LDAPBindError, LDAPSocketOpenError, LDAPStartTLSError, LDAPSessionError

# --- Configuration Constants ---
# Default LDAP port for unencrypted communication
DEFAULT_LDAP_PORT = 389
# Default LDAPS port for SSL/TLS encrypted communication
DEFAULT_LDAPS_PORT = 636

# Recommended minimum password length for flagging as weak.
# AD default is 7 characters. NIST SP 800-63B recommends 8 characters (minimum)
# but often 12-14 is considered a stronger baseline.
WEAK_MIN_PASSWORD_LENGTH_THRESHOLD = 8

# Account lockout threshold:
# A value of 0 means account lockout is disabled, which is a critical security flaw.
# A higher value means more attempts are allowed before lockout.
# Typically, 3-5 is a reasonable range. If it's above this, it might be considered weak.
WEAK_LOCKOUT_THRESHOLD = 5 # If lockout threshold is > 5, it's considered weak. 0 also needs to be flagged.

# Minimum recommended account lockout duration in 100-nanosecond intervals.
# If 0, it means indefinite lockout, which can be an anti-DoS measure, but also problematic for users.
# A very short duration (e.g., < 30 minutes) can be considered weak.
# Calculation for 30 minutes: 30 minutes * 60 seconds/minute * 10,000,000 100ns/second = 18,000,000,000 ns
MIN_LOCKOUT_DURATION_NS = 18000000000

# Maximum recommended lockout observation window in 100-nanosecond intervals.
# This is the period over which failed login attempts are counted.
# If 0, it means the counter never resets unless the account is locked or manually reset.
# A very long window (e.g., > 1 hour) might be considered less effective.
# Calculation for 1 hour: 1 hour * 3600 seconds/hour * 10,000,000 100ns/second = 36,000,000,000 ns
MAX_LOCKOUT_OBSERVATION_WINDOW_NS = 36000000000

# LDAP attribute names used to query Active Directory for policy settings.
ATTR_MIN_PWD_LENGTH = 'minPwdLength'
ATTR_PWD_PROPERTIES = 'pwdProperties'
ATTR_LOCKOUT_THRESHOLD = 'lockoutThreshold'
ATTR_LOCKOUT_DURATION = 'lockoutDuration'
ATTR_LOCKOUT_OBSERVATION_WINDOW = 'lockOutObservationWindow'

# Bitmask values for the 'pwdProperties' attribute.
# These bits indicate various password policy settings.
PWD_COMPLEX_SCENARIO_BIT = 0x0004 # Indicates if password complexity is enabled.
PWD_REVERSIBLE_ENCRYPTION_BIT = 0x0008 # Indicates if passwords are stored using reversible encryption (CRITICAL VULNERABILITY).
# Other bits exist but are not part of this audit's scope:
# ACCT_LOCKOUT_RESET_TIME = 0x0001
# PWD_NO_MAX_AGE = 0x0002
# PWD_HISTORY_ENABLED = 0x0010 (not directly available via this attribute, but implied by password history setting)

# Result categories for audit reporting to provide clear status indicators.
RESULT_PASS = "PASS"        # Policy meets or exceeds security recommendations.
RESULT_WARNING = "WARNING"  # Policy is acceptable but could be strengthened.
RESULT_CRITICAL = "CRITICAL" # Policy represents a significant security risk and requires immediate attention.
RESULT_INFO = "INFO"        # Informational note about a policy setting.
RESULT_ERROR = "ERROR"      # An error occurred while checking this policy.

# --- Logging Setup ---
# Configure the default logging settings.
# Messages will be formatted with timestamp, log level, and the message itself.
# By default, logs go to stdout. Verbose mode or --output-file can change this.
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
# Get a logger instance for this module.
logger = logging.getLogger(__name__)

def _configure_file_logging(log_file_path):
    """
    Configures an additional file handler for logging output.
    This allows logging to both console and a specified file.

    Args:
        log_file_path (str): The path to the file where logs should be written.
    """
    try:
        file_handler = logging.FileHandler(log_file_path)
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logger.addHandler(file_handler)
        logger.info(f"Logging output also directed to file: {log_file_path}")
    except Exception as e:
        logger.error(f"Failed to configure file logging for '{log_file_path}': {e}", exc_info=True)

def _convert_100ns_to_human_readable(value_100ns):
    """
    Converts a time value stored in 100-nanosecond intervals (as used in Active Directory)
    into a human-readable string (e.g., "30 minutes", "1 day, 5 hours").

    Args:
        value_100ns (int or None): The time value in 100-nanosecond intervals.

    Returns:
        str: A human-readable representation of the time, or "N/A", "Indefinite", "Not Set / Disabled".
    """
    if value_100ns is None:
        return "N/A"
    
    # Active Directory represents "never expire" or "indefinite" with very large negative numbers.
    # The lowest possible 64-bit signed integer value is typically used.
    if value_100ns <= -9223372036854775808: # This is Python's sys.maxsize for 64-bit negative, effectively "infinite"
        return "Indefinite (Never)"
    elif value_100ns == 0:
        return "Not Set / Disabled"

    # Convert 100-nanoseconds to total seconds.
    # 1 second = 10,000,000 (10^7) 100-nanosecond intervals.
    total_seconds = value_100ns / 10_000_000
    
    # Use timedelta from the datetime module for convenient conversion to days, hours, minutes, seconds.
    td = timedelta(seconds=total_seconds)

    # Deconstruct the timedelta object into its components for formatting.
    days = td.days
    hours, remainder = divmod(td.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)

    parts = []
    if days:
        parts.append(f"{days} day{'s' if days != 1 else ''}")
    if hours:
        parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
    if minutes:
        parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")
    if seconds:
        parts.append(f"{seconds} second{'s' if seconds != 1 else ''}")

    # Join the parts, or return a default for very small durations.
    return ", ".join(parts) if parts else "Less than a second"

def _interpret_pwd_properties(pwd_properties_value):
    """
    Interprets the 'pwdProperties' bitmask value from Active Directory
    and returns a dictionary indicating the status of specific flags.

    Args:
        pwd_properties_value (int or None): The integer value of the 'pwdProperties' attribute.

    Returns:
        dict: A dictionary with boolean flags for 'complexity_enabled' and 'reversible_encryption_enabled'.
              Returns "Unknown" for these values if input is None.
    """
    if pwd_properties_value is None:
        return {
            "complexity_enabled": "Unknown",
            "reversible_encryption_enabled": "Unknown"
        }

    # Check if the specific bit is set in the bitmask.
    # A bitwise AND operation will result in a non-zero value if the bit is set.
    return {
        "complexity_enabled": bool(pwd_properties_value & PWD_COMPLEX_SCENARIO_BIT),
        "reversible_encryption_enabled": bool(pwd_properties_value & PWD_REVERSIBLE_ENCRYPTION_BIT)
    }

def _get_domain_dn(connection_obj):
    """
    Retrieves the base Distinguished Name (DN) of the Active Directory domain
    by querying the RootDSE (Root Directory Service Entry).
    This is necessary to perform searches within the domain.

    Args:
        connection_obj (ldap3.Connection): An active LDAP connection object.

    Returns:
        str or None: The domain's DN (e.g., 'DC=example,DC=com') if found, otherwise None.
    """
    logger.debug("Attempting to retrieve domain DN from RootDSE.")
    try:
        # Search the RootDSE (base DN '') for the 'defaultNamingContext' attribute.
        # This attribute contains the DN of the domain.
        connection_obj.search(
            search_base='',                 # Search the RootDSE
            search_filter='(objectClass=*)', # Any object class will do at the root
            search_scope=core.BASE,         # Base search scope (only the entry itself)
            attributes=['defaultNamingContext'] # The attribute holding the domain DN
        )
        if connection_obj.entries:
            domain_dn = connection_obj.entries[0]['defaultNamingContext'].value
            logger.debug(f"Successfully retrieved domain DN: {domain_dn}")
            return domain_dn
        else:
            logger.error("Could not retrieve 'defaultNamingContext' from RootDSE. No entries returned.")
            return None
    except Exception as e:
        logger.error(f"Error querying RootDSE for domain DN: {e}", exc_info=True)
        return None

def initialize_ldap_connection(server_address, port, use_ssl, username, password, auth_method=NTLM, ca_certs_file=None):
    """
    Initializes an LDAP server object, configures TLS/SSL if requested, and attempts to bind to it.
    This function handles various connection and authentication errors.

    Args:
        server_address (str): The IP address or hostname of the Active Directory server.
        port (int): The network port to connect to (e.g., 389 for LDAP, 636 for LDAPS).
        use_ssl (bool): If True, use LDAPS (LDAP over SSL/TLS).
        username (str): The username for binding (e.g., 'user@domain.com' or 'DOMAIN\\user').
        password (str): The password for the specified user.
        auth_method (ldap3.core.const.AUTHENTICATION_METHOD): The authentication method (e.g., NTLM for Active Directory).
        ca_certs_file (str, optional): Path to a CA certificate bundle (.pem) for verifying the server's certificate.

    Returns:
        ldap3.Connection: An active LDAP connection object if successful, otherwise None.
    """
    logger.info(f"Attempting to connect to AD server: {server_address}:{port} (SSL: {use_ssl})")

    try:
        tls_config = None
        if use_ssl:
            # Create a default SSL context for client-side connections.
            _ssl_context = ssl.create_default_context(
                cafile=ca_certs_file if ca_certs_file else None
            )
            # Active Directory typically uses server authentication only. Client certificates are rare.
            # Hostname verification can be problematic with IP addresses or non-matching common names.
            # Setting check_hostname to False is common for AD if CA is not perfectly aligned,
            # but CERT_REQUIRED means it still needs to be signed by a trusted CA.
            _ssl_context.check_hostname = False
            _ssl_context.verify_mode = ssl.CERT_REQUIRED if ca_certs_file else ssl.CERT_NONE # Require certs if CA file provided.

            # Configure TLS for ldap3.
            tls_config = core.Tls(
                local_private_key_path=None,         # No client certificate needed
                local_certificate_path=None,         # No client certificate needed
                ca_certs_path=ca_certs_file,         # Path to trusted CA bundle
                valid_cert_types=core.TLS_VALID_CERT_TYPES.SERVER_AUTH, # Only validate server certificate
                version=ssl.PROTOCOL_TLSv1_2,        # Prefer TLS 1.2 or higher for security
                ssl_context=_ssl_context             # Custom SSL context
            )
            logger.debug(f"SSL/TLS context configured. CA file: {ca_certs_file if ca_certs_file else 'None (verification disabled)'}")
        else:
            logger.warning("Connecting without SSL/TLS. Credentials will be sent in plain text if not using StartTLS. Consider using --ldaps for secure communication.")

        # Create the Server object with the specified parameters.
        server = Server(server_address, port=port, use_ssl=use_ssl, tls=tls_config, get_info=ALL)
        logger.debug(f"Server object created for {server_address}:{port}")

        # Create the Connection object and attempt to bind automatically.
        connection = Connection(
            server,
            user=username,
            password=password,
            authentication=auth_method,
            auto_bind=True,  # This will attempt to bind immediately upon connection creation
            version=3        # Specify LDAPv3
        )

        if not connection.bound:
            # If auto_bind failed, check the result for specific error codes.
            logger.critical(f"Failed to bind to AD server: {server_address}. Result: {connection.result}")
            if connection.result and connection.result.get('result') == 49: # 49 is 'Invalid Credentials'
                raise LDAPInvalidCredentialsResult(connection.result)
            raise LDAPBindError(connection.result) # General bind error

        logger.info(f"Successfully bound to AD server as '{username}'.")
        return connection

    # Specific exception handling for common LDAP connection errors.
    except LDAPInvalidCredentialsResult as e:
        logger.error(f"{RESULT_ERROR}: Authentication failed for user '{username}'. "
                     f"Please check your username and password. Details: {e}")
        return None
    except LDAPBindError as e:
        logger.error(f"{RESULT_ERROR}: LDAP bind error occurred. "
                     f"Ensure the server is reachable and credentials are correct. Details: {e}")
        return None
    except LDAPSocketOpenError as e:
        logger.error(f"{RESULT_ERROR}: Could not connect to the AD server at {server_address}:{port}. "
                     f"Check network connectivity, firewall rules, and server availability. Details: {e}")
        return None
    except LDAPStartTLSError as e:
        logger.error(f"{RESULT_ERROR}: StartTLS negotiation failed. "
                     f"Ensure the server supports StartTLS and certificates are valid. Details: {e}")
        return None
    except LDAPSessionError as e:
        logger.error(f"{RESULT_ERROR}: LDAP session error occurred. "
                     f"This might indicate issues with the LDAP server or network instability. Details: {e}")
        return None
    except ssl.SSLError as e:
        logger.error(f"{RESULT_ERROR}: SSL/TLS error during connection. "
                     f"Check certificate configuration, CA file path, and server TLS setup. Details: {e}")
        return None
    except Exception as e:
        logger.error(f"{RESULT_ERROR}: An unexpected error occurred during LDAP connection: {e}", exc_info=True)
        return None

def get_domain_policy_attributes(connection_obj, domain_dn):
    """
    Queries the Active Directory domain object for the relevant password and lockout policy attributes.
    These attributes are stored on the domain root entry itself.

    Args:
        connection_obj (ldap3.Connection): An active LDAP connection object.
        domain_dn (str): The Distinguished Name (DN) of the domain (e.g., 'DC=example,DC=com').

    Returns:
        dict: A dictionary containing the policy attributes and their values,
              or None if the retrieval process fails.
    """
    logger.info(f"Retrieving domain policy from domain DN: {domain_dn}")
    attributes_to_fetch = [
        ATTR_MIN_PWD_LENGTH,
        ATTR_PWD_PROPERTIES,
        ATTR_LOCKOUT_THRESHOLD,
        ATTR_LOCKOUT_DURATION,
        ATTR_LOCKOUT_OBSERVATION_WINDOW
    ]

    try:
        # Perform an LDAP search on the base DN of the domain.
        connection_obj.search(
            search_base=domain_dn,
            search_filter='(objectClass=domain)', # The domain object itself has these attributes
            search_scope=core.BASE,                # Search only the base entry
            attributes=attributes_to_fetch         # List of attributes to retrieve
        )

        if connection_obj.entries:
            entry = connection_obj.entries[0] # There should only be one domain entry at the base DN.
            # Extract attribute values, handling cases where an attribute might be missing.
            policy_data = {attr: entry[attr].value if attr in entry else None for attr in attributes_to_fetch}
            logger.debug(f"Raw policy attributes retrieved: {policy_data}")
            return policy_data
        else:
            logger.error(f"Failed to find domain object at DN: {domain_dn}. No policy data retrieved.")
            return None
    except Exception as e:
        logger.error(f"Error retrieving domain policy attributes: {e}", exc_info=True)
        return None

def check_password_complexity(pwd_properties_value):
    """
    Audits the Active Directory password complexity policy.
    This policy is determined by the PWD_COMPLEX_SCENARIO_BIT within the 'pwdProperties' attribute.

    Args:
        pwd_properties_value (int or None): The integer value of the 'pwdProperties' attribute.

    Returns:
        dict: A report dictionary detailing the audit findings for this policy.
    """
    report = {
        "Policy": "Password Complexity",
        "Current Value": "N/A",
        "Recommendation": "Ensure password complexity is enabled to enforce stronger passwords.",
        "Status": RESULT_ERROR,
        "Details": "Could not determine password complexity status due to missing data."
    }

    if pwd_properties_value is None:
        report["Status"] = RESULT_ERROR
        report["Details"] = "Password complexity attribute (pwdProperties) was not found or is empty."
        return report

    interpreted_properties = _interpret_pwd_properties(pwd_properties_value)
    is_complexity_enabled = interpreted_properties["complexity_enabled"]
    report["Current Value"] = "Enabled" if is_complexity_enabled else "Disabled"

    if is_complexity_enabled:
        report["Status"] = RESULT_PASS
        report["Details"] = "Password complexity is enabled, which is a fundamental security practice to mandate diverse character types (uppercase, lowercase, numbers, symbols) in passwords."
    else:
        report["Status"] = RESULT_CRITICAL
        report["Details"] = "Password complexity is DISABLED. This allows users to set weak and easily guessable passwords (e.g., 'password123', common dictionary words), significantly increasing the risk of brute-force attacks and credential stuffing against user accounts."

    return report

def check_minimum_password_length(min_pwd_length_value):
    """
    Audits the Active Directory minimum password length policy.

    Args:
        min_pwd_length_value (int or None): The integer value of the 'minPwdLength' attribute.

    Returns:
        dict: A report dictionary detailing the audit findings for this policy.
    """
    report = {
        "Policy": "Minimum Password Length",
        "Current Value": "N/A",
        "Recommendation": f"Set minimum password length to at least {WEAK_MIN_PASSWORD_LENGTH_THRESHOLD} characters, preferably 12-14 or more, in line with NIST recommendations.",
        "Status": RESULT_ERROR,
        "Details": "Could not determine minimum password length due to missing data."
    }

    if min_pwd_length_value is None:
        report["Status"] = RESULT_ERROR
        report["Details"] = "Minimum password length attribute (minPwdLength) was not found or is empty."
        return report

    report["Current Value"] = f"{min_pwd_length_value} characters"

    if min_pwd_length_value >= WEAK_MIN_PASSWORD_LENGTH_THRESHOLD:
        report["Status"] = RESULT_PASS
        report["Details"] = f"Minimum password length is {min_pwd_length_value} characters, which meets or exceeds the recommended minimum of {WEAK_MIN_PASSWORD_LENGTH_THRESHOLD}."
        if min_pwd_length_value < 12: # Add a warning for stronger recommendations, even if it passes basic threshold
            report["Status"] = RESULT_WARNING
            report["Details"] += " For enhanced security, consider increasing the minimum length to 12-14 characters or more to improve password entropy and resilience against modern cracking techniques."
    else:
        report["Status"] = RESULT_CRITICAL
        report["Details"] = f"Minimum password length is {min_pwd_length_value} characters, which is BELOW the recommended minimum of {WEAK_MIN_PASSWORD_LENGTH_THRESHOLD}. Short passwords are significantly easier to guess or crack via brute-force attacks."

    return report

def check_reversible_encryption_status(pwd_properties_value):
    """
    Audits whether Active Directory is configured to store passwords using reversible encryption.
    This is a severe security risk and should always be disabled.

    Args:
        pwd_properties_value (int or None): The integer value of the 'pwdProperties' attribute.

    Returns:
        dict: A report dictionary detailing the audit findings for this policy.
    """
    report = {
        "Policy": "Reversible Password Encryption",
        "Current Value": "N/A",
        "Recommendation": "Disable reversible password encryption immediately. This is a severe security risk.",
        "Status": RESULT_ERROR,
        "Details": "Could not determine reversible encryption status due to missing data."
    }

    if pwd_properties_value is None:
        report["Status"] = RESULT_ERROR
        report["Details"] = "Password properties attribute (pwdProperties) was not found or is empty."
        return report

    interpreted_properties = _interpret_pwd_properties(pwd_properties_value)
    is_reversible_encryption_enabled = interpreted_properties["reversible_encryption_enabled"]
    report["Current Value"] = "Enabled" if is_reversible_encryption_enabled else "Disabled"

    if is_reversible_encryption_enabled:
        report["Status"] = RESULT_CRITICAL
        report["Details"] = "Passwords are ENABLED for reversible encryption storage. This is a MAJOR security vulnerability as it allows for easy recovery of plaintext passwords, making them highly susceptible to theft and compromise if the Active Directory database is compromised. This setting should be disabled immediately."
    else:
        report["Status"] = RESULT_PASS
        report["Details"] = "Passwords are NOT stored using reversible encryption, which is the secure and recommended configuration."

    return report

def check_account_lockout_policy(lockout_threshold_value, lockout_duration_value, lockout_observation_window_value):
    """
    Audits the Active Directory account lockout policies, including lockout threshold, duration,
    and the observation window.

    Args:
        lockout_threshold_value (int or None): The value of 'lockoutThreshold'.
        lockout_duration_value (int or None): The value of 'lockoutDuration' in 100ns intervals.
        lockout_observation_window_value (int or None): The value of 'lockOutObservationWindow' in 100ns intervals.

    Returns:
        list: A list of report dictionaries, one for each sub-policy checked.
    """
    results = []

    # --- Audit Lockout Threshold ---
    report_threshold = {
        "Policy": "Account Lockout Threshold",
        "Current Value": "N/A",
        "Recommendation": f"Set lockout threshold between 3-5 failed attempts. A value of 0 disables lockout, which is critical. A very high value is also weak.",
        "Status": RESULT_ERROR,
        "Details": "Could not determine lockout threshold status due to missing data."
    }
    if lockout_threshold_value is None:
        report_threshold["Details"] = "Lockout threshold attribute (lockoutThreshold) was not found or is empty."
    else:
        report_threshold["Current Value"] = f"{lockout_threshold_value} attempts"
        if lockout_threshold_value == 0:
            report_threshold["Status"] = RESULT_CRITICAL
            report_threshold["Details"] = "Account lockout threshold is set to 0, meaning accounts will NEVER lock out, regardless of failed attempts. This makes accounts extremely vulnerable to unlimited brute-force attacks and credential stuffing, which is a severe security risk."
        elif 1 <= lockout_threshold_value <= WEAK_LOCKOUT_THRESHOLD:
            report_threshold["Status"] = RESULT_PASS
            report_threshold["Details"] = f"Account lockout threshold is set to {lockout_threshold_value} attempts, which is an appropriate setting to deter brute-force attacks without causing excessive denial-of-service for legitimate users."
        else: # lockout_threshold_value > WEAK_LOCKOUT_THRESHOLD
            report_threshold["Status"] = RESULT_WARNING
            report_threshold["Details"] = f"Account lockout threshold is set to {lockout_threshold_value} attempts. This value is higher than the recommended maximum of {WEAK_LOCKOUT_THRESHOLD}, potentially allowing too many brute-force attempts before an account locks out, increasing the risk of password guessing."
    results.append(report_threshold)

    # --- Audit Lockout Duration ---
    report_duration = {
        "Policy": "Account Lockout Duration",
        "Current Value": "N/A",
        "Recommendation": f"Set lockout duration to a reasonable period, typically at least {_convert_100ns_to_human_readable(MIN_LOCKOUT_DURATION_NS)} (e.g., 30 minutes to an hour).",
        "Status": RESULT_ERROR,
        "Details": "Could not determine lockout duration status due to missing data."
    }
    if lockout_duration_value is None:
        report_duration["Details"] = "Lockout duration attribute (lockoutDuration) was not found or is empty."
    else:
        # Duration is stored as a negative number for "until reset by administrator".
        human_readable_duration = _convert_100ns_to_human_readable(abs(lockout_duration_value))
        report_duration["Current Value"] = human_readable_duration

        if lockout_duration_value == 0: # This typically means 'not configured' or 'disabled' and account is locked indefinitely.
            report_duration["Status"] = RESULT_WARNING
            report_duration["Details"] = "Account lockout duration is set to 0 ('Not Set / Disabled'). This often means the account is locked indefinitely until an administrator manually unlocks it. While preventing attackers, it can lead to operational overhead and potential denial-of-service if users are frequently locked out."
        elif lockout_duration_value < 0: # This explicitly means indefinite lockout.
            report_duration["Status"] = RESULT_INFO # Can be a strong security posture, depends on operational needs
            report_duration["Details"] = "Account lockout duration is set to 'Indefinite' (negative value). Accounts must be manually unlocked by an administrator. This is a very strong security measure against brute-force, but requires good operational procedures for account recovery."
        elif lockout_duration_value >= MIN_LOCKOUT_DURATION_NS:
            report_duration["Status"] = RESULT_PASS
            report_duration["Details"] = f"Account lockout duration is set to {human_readable_duration}, which is sufficient to deter rapid brute-force attempts while allowing accounts to automatically unlock."
        else: # lockout_duration_value < MIN_LOCKOUT_DURATION_NS (and positive)
            report_duration["Status"] = RESULT_CRITICAL
            report_duration["Details"] = f"Account lockout duration is set to {human_readable_duration}, which is less than the recommended {_convert_100ns_to_human_readable(MIN_LOCKOUT_DURATION_NS)}. A very short duration allows attackers to quickly retry failed login attempts after a brief lockout, weakening the effectiveness of the lockout policy."
    results.append(report_duration)

    # --- Audit Lockout Observation Window ---
    report_observation = {
        "Policy": "Lockout Observation Window",
        "Current Value": "N/A",
        "Recommendation": f"Set observation window to a reasonable period (e.g., 30 minutes to {_convert_100ns_to_human_readable(MAX_LOCKOUT_OBSERVATION_WINDOW_NS)}). A value of 0 means the counter never resets.",
        "Status": RESULT_ERROR,
        "Details": "Could not determine lockout observation window status due to missing data."
    }
    if lockout_observation_window_value is None:
        report_observation["Details"] = "Lockout observation window attribute (lockOutObservationWindow) was not found or is empty."
    else:
        human_readable_window = _convert_100ns_to_human_readable(lockout_observation_window_value)
        report_observation["Current Value"] = human_readable_window

        if lockout_observation_window_value == 0:
            report_observation["Status"] = RESULT_WARNING
            report_observation["Details"] = "Lockout observation window is set to 0. This means the bad password count never resets unless the account is locked out or an administrator manually resets it. This can lead to accounts being locked out indefinitely by a single failed login attempt if the threshold is low, impacting user availability."
        elif lockout_observation_window_value <= MAX_LOCKOUT_OBSERVATION_WINDOW_NS:
            report_observation["Status"] = RESULT_PASS
            report_observation["Details"] = f"Lockout observation window is set to {human_readable_window}, which is within an acceptable range for resetting failed login attempts, balancing security with user convenience."
        else: # lockout_observation_window_value > MAX_LOCKOUT_OBSERVATION_WINDOW_NS
            report_observation["Status"] = RESULT_CRITICAL
            report_observation["Details"] = f"Lockout observation window is set to {human_readable_window}, which is significantly longer than recommended {_convert_100ns_to_human_readable(MAX_LOCKOUT_OBSERVATION_WINDOW_NS)}. A very long window allows a broad period for attackers to attempt logins over an extended time without resetting the counter, effectively weakening the lockout protection."
    results.append(report_observation)

    return results

def print_audit_report(audit_results):
    """
    Prints the formatted audit report to the console, summarizing all findings.
    It categorizes policies by their status (PASS, WARNING, CRITICAL) and provides details.

    Args:
        audit_results (list): A list of dictionaries, where each dictionary represents
                              a policy audit result from functions like check_password_complexity.

    Returns:
        str: The overall audit status (e.g., RESULT_PASS, RESULT_WARNING, RESULT_CRITICAL).
    """
    separator = "=" * 80
    sub_separator = "-" * 80

    print("\n" + separator)
    print(" Active Directory Domain Policy Audit Report".center(80))
    print(f"Report Generated: {logging.Formatter().formatTime(logging.LogRecord('', 0, '', 0, '', [], None))}".center(80))
    print(separator)

    overall_status = RESULT_PASS
    critical_findings_count = 0
    warning_findings_count = 0
    pass_findings_count = 0
    info_findings_count = 0
    error_findings_count = 0

    # Iterate through each group of results (a single policy check might return multiple sub-checks)
    for result_group in audit_results:
        # Ensure result_group is always treated as a list for consistent iteration
        if not isinstance(result_group, list):
            result_group = [result_group]

        for report in result_group:
            status = report.get("Status", RESULT_ERROR)
            policy = report.get("Policy", "Unknown Policy")
            current_value = report.get("Current Value", "N/A")
            details = report.get("Details", "No details provided.")
            recommendation = report.get("Recommendation", "No specific recommendation.")

            print(f"\nPolicy: {policy}")
            print(f"  Current Setting: {current_value}")
            print(f"  Audit Status:    {status}")
            print(f"  Details:         {details}")
            if status in [RESULT_WARNING, RESULT_CRITICAL]:
                print(f"  Recommendation:  {recommendation}")
            print(sub_separator)

            # Aggregate counts and determine overall status
            if status == RESULT_CRITICAL:
                overall_status = RESULT_CRITICAL
                critical_findings_count += 1
            elif status == RESULT_WARNING:
                if overall_status == RESULT_PASS: # Elevate status only if not already critical
                    overall_status = RESULT_WARNING
                warning_findings_count += 1
            elif status == RESULT_PASS:
                pass_findings_count += 1
            elif status == RESULT_INFO:
                info_findings_count += 1
            elif status == RESULT_ERROR:
                if overall_status == RESULT_PASS: # Elevate status only if not already critical/warning
                    overall_status = RESULT_ERROR
                error_findings_count += 1

    # Print summary section at the end of the report
    print("\n" + separator)
    print(" Audit Summary".center(80))
    print(separator)
    print(f" Total Policies Checked:    {critical_findings_count + warning_findings_count + pass_findings_count + info_findings_count + error_findings_count}")
    print(f" Critical Findings:         {critical_findings_count}")
    print(f" Warning Findings:          {warning_findings_count}")
    print(f" Informational Findings:    {info_findings_count}")
    print(f" Passing Policies:          {pass_findings_count}")
    print(f" Error during Checks:       {error_findings_count}")
    print(f"\n Overall Audit Status: {overall_status}")
    print(separator)
    print("End of Report".center(80))
    print(separator + "\n")

    return overall_status

def main():
    """
    Main execution function of the Active Directory Policy Auditor script.
    It parses command-line arguments, establishes an LDAP connection,
    retrieves and audits policies, and finally prints a detailed report.
    """
    parser = argparse.ArgumentParser(
        description="""
        Active Directory Policy Auditor - A security script to query Active Directory
        for weak domain-level password and account lockout policies using ldap3.

        Checks performed:
        - Password complexity enabled/disabled.
        - Minimum password length against a recommended threshold.
        - Reversible password encryption status (critical vulnerability if enabled).
        - Account lockout threshold, duration, and observation window.

        Recommendations will be provided for identified weak policies.
        """,
        formatter_class=argparse.RawTextHelpFormatter # Preserve newlines in description
    )
    # Define command-line arguments for server, credentials, and connection options.
    parser.add_argument('-s', '--server', required=True,
                        help="Active Directory server hostname or IP address (e.g., 'ad.example.com' or '192.168.1.10').")
    parser.add_argument('-p', '--port', type=int, default=DEFAULT_LDAP_PORT,
                        help=f"LDAP port to connect to. Default: {DEFAULT_LDAP_PORT} (LDAP) or {DEFAULT_LDAPS_PORT} (LDAPS, if --ldaps is used).")
    parser.add_argument('-u', '--username', required=True,
                        help="Username for LDAP binding (e.g., 'admin@example.com' or 'EXAMPLE\\adminuser'). "
                             "This user needs read permissions on domain policy attributes.")
    parser.add_argument('-w', '--password', required=False,
                        help="Password for LDAP binding. If not provided, the script will securely prompt for it.")
    parser.add_argument('--ldaps', action='store_true',
                        help=f"Use LDAPS (LDAP over SSL/TLS) for encrypted communication. "
                             f"If this flag is set and --port is not specified, default port will be {DEFAULT_LDAPS_PORT}.")
    parser.add_argument('--ca-certs', dest='ca_certs_file',
                        help="Path to a CA certificate bundle (.pem file) for LDAPS server certificate verification. "
                             "Recommended for production environments. If omitted with --ldaps, server cert validation may be relaxed.")
    parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose logging output (DEBUG level).")
    parser.add_argument('-o', '--output-file', dest='log_output_file',
                        help="Path to a file where log output will also be written, in addition to the console.")
    
    args = parser.parse_args()

    # Configure logging level based on verbose argument.
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled.")

    # Configure file logging if an output file is specified.
    if args.log_output_file:
        _configure_file_logging(args.log_output_file)

    # Assign parsed arguments to variables for clarity.
    server_address = args.server
    port = args.port
    use_ssl = args.ldaps
    username = args.username
    password = args.password
    ca_certs_file = args.ca_certs_file

    # Adjust default port if LDAPS is explicitly requested but a custom port wasn't set.
    if use_ssl and port == DEFAULT_LDAP_PORT:
        port = DEFAULT_LDAPS_PORT
        logger.info(f"LDAPS requested, and default LDAP port ({DEFAULT_LDAP_PORT}) was used. "
                    f"Adjusting port to default LDAPS port: {port}")
    
    # Prompt for password securely if it wasn't provided via the command line.
    if not password:
        try:
            import getpass
            password = getpass.getpass(f"Enter password for '{username}': ")
            if not password:
                logger.error("Password cannot be empty. Exiting.")
                sys.exit(1)
        except Exception as e:
            logger.error(f"Error while securely prompting for password: {e}", exc_info=True)
            sys.exit(1)

    connection = None # Initialize connection variable to None
    try:
        # Establish the LDAP connection.
        connection = initialize_ldap_connection(
            server_address=server_address,
            port=port,
            use_ssl=use_ssl,
            username=username,
            password=password,
            auth_method=NTLM, # NTLM is a common authentication method for Active Directory.
            ca_certs_file=ca_certs_file
        )

        if not connection:
            logger.critical("Failed to establish LDAP connection. Cannot proceed with audit. Exiting.")
            sys.exit(1)

        # Retrieve the domain's Distinguished Name (DN) which is essential for further searches.
        domain_dn = _get_domain_dn(connection)
        if not domain_dn:
            logger.critical("Could not determine the domain's Distinguished Name. Cannot proceed with audit. Exiting.")
            sys.exit(1)

        logger.info(f"Identified domain DN: {domain_dn}")

        # Retrieve the domain's password and lockout policy attributes.
        policy_attributes = get_domain_policy_attributes(connection, domain_dn)

        if not policy_attributes:
            logger.critical("Failed to retrieve domain policy attributes. Cannot proceed with audit. Exiting.")
            sys.exit(1)

        logger.info("\n--- Starting Active Directory Policy Audit ---")
        audit_results = [] # List to store all individual policy audit reports.

        # --- Perform Individual Policy Audits ---
        # Each function performs a specific check and returns a report dictionary (or a list of reports).

        # Audit Password Complexity
        audit_results.append(check_password_complexity(policy_attributes.get(ATTR_PWD_PROPERTIES)))

        # Audit Minimum Password Length
        audit_results.append(check_minimum_password_length(policy_attributes.get(ATTR_MIN_PWD_LENGTH)))

        # Audit Reversible Password Encryption Status
        audit_results.append(check_reversible_encryption_status(policy_attributes.get(ATTR_PWD_PROPERTIES)))

        # Audit Account Lockout Policy (this function returns a list of reports for its sub-policies)
        lockout_results = check_account_lockout_policy(
            policy_attributes.get(ATTR_LOCKOUT_THRESHOLD),
            policy_attributes.get(ATTR_LOCKOUT_DURATION),
            policy_attributes.get(ATTR_LOCKOUT_OBSERVATION_WINDOW)
        )
        audit_results.extend(lockout_results)

        # --- Generate and Print the Consolidated Audit Report ---
        overall_audit_status = print_audit_report(audit_results)

        # Exit with a status code indicating the severity of findings.
        if overall_audit_status == RESULT_CRITICAL:
            logger.warning("Audit completed with CRITICAL findings. Immediate attention and remediation are highly recommended.")
            sys.exit(2) # Exit with code 2 for critical issues
        elif overall_audit_status == RESULT_WARNING:
            logger.warning("Audit completed with WARNING findings. Review and consideration of recommendations are advised.")
            sys.exit(1) # Exit with code 1 for warnings
        elif overall_audit_status == RESULT_ERROR:
            logger.error("Audit completed with one or more ERRORs during policy checks. Manual investigation might be needed.")
            sys.exit(3) # Exit with code 3 for errors
        else: # RESULT_PASS or RESULT_INFO (no major issues)
            logger.info("Audit completed with no critical or warning findings. Active Directory policies appear to be compliant with best practices.")
            sys.exit(0) # Exit with code 0 for success

    except Exception as e:
        # Catch any unhandled exceptions during the main execution flow.
        logger.critical(f"An unhandled error occurred during the audit process: {e}", exc_info=True)
        sys.exit(1)
    finally:
        # Ensure the LDAP connection is unbound even if errors occur.
        if connection and connection.bound:
            try:
                connection.unbind()
                logger.info("LDAP connection unbound successfully.")
            except Exception as e:
                logger.error(f"Error during LDAP connection unbind: {e}", exc_info=True)


if __name__ == "__main__":
    main()