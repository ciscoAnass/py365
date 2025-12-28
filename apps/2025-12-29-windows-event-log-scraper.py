import win32evtlog
import win32api
import winerror
import logging
import logging.handlers
import json
import time
import os
import sys
import datetime
import socket # Required for TCP Syslog, import conditionally or always

# --- Configuration Section ---
# This section defines all the configurable parameters for the Windows Event Log Scraper.
# Modify these values to suit your environment.

CONFIG = {
    # The name of the Windows Event Log to monitor. Common options include 'Security', 'System', 'Application'.
    "LOG_NAME": "Security",

    # A list of specific Event IDs to scrape. For 'Security' log, common IDs include:
    # 4624: Successful Logon
    # 4625: Failed Logon
    # 4740: Account Locked Out
    # 4776: The computer attempted to validate the credentials for an account.
    # 4672: Special privileges assigned to new logon
    # Add or remove Event IDs as needed.
    "TARGET_EVENT_IDS": [4625, 4740, 4624, 4672],

    # Syslog server details where events will be forwarded.
    "SYSLOG_SERVER": "127.0.0.1",  # IP address or hostname of your syslog server
    "SYSLOG_PORT": 514,           # Standard syslog UDP port is 514. TCP is often 6514.
    "SYSLOG_PROTOCOL": "UDP",     # "UDP" or "TCP". UDP is more common for basic syslog.

    # Scraper's internal logging configuration. This logs the scraper's operations and errors.
    # It is separate from the syslog handler, which sends event data.
    "SCRAPER_LOG_FILE": "windows_event_scraper.log",
    "SCRAPER_LOG_LEVEL": logging.INFO, # Options: logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR

    # File to store the last successfully processed event record ID for each monitored log.
    # This ensures that the scraper doesn't re-process old events on restart.
    "STATE_FILE": "last_read_event.json",

    # Polling interval in seconds. How often the script checks for new events in the event log.
    "POLLING_INTERVAL_SECONDS": 300, # Default: 5 minutes (300 seconds)

    # Maximum number of events to read from the event log in a single batch.
    # Reading too many at once can consume significant memory and processing power.
    "MAX_EVENTS_PER_READ": 200,

    # Hostname of the local machine. This is automatically determined using win32api but can be overridden.
    "HOSTNAME": win32api.GetComputerName(),

    # Syslog facility. E.g., LOG_AUTH for security events, LOG_LOCAL0-7 for custom use.
    # Check your syslog server's configuration for preferred facility.
    "SYSLOG_FACILITY": logging.handlers.SysLogHandler.LOG_AUTH,

    # Default encoding for event log messages. Windows event messages are typically UTF-16 internally.
    # pywin32 handles this translation, but if any manual decoding is needed, this is the assumed encoding.
    "EVENT_MESSAGE_ENCODING": "utf-8",

    # Timeout for opening event log handle in milliseconds (not directly used by pywin32's OpenEventLog,
    # but could be used in custom retry logic if implemented).
    "EVENT_LOG_OPEN_TIMEOUT_MS": 1000, # 1 second
}

# --- Global Scraper Logger Setup ---
# This logger is dedicated to the scraper's operational messages, debugging information,
# and error reporting. It writes to a local file and the console.
scraper_logger = logging.getLogger("WindowsEventScraper")
scraper_logger.setLevel(CONFIG["SCRAPER_LOG_LEVEL"])

# Create file handler for the scraper's log, ensuring log file rotation in a real-world scenario.
# For simplicity, this example uses a basic file handler.
file_handler = logging.FileHandler(CONFIG["SCRAPER_LOG_FILE"])
file_handler.setFormatter(logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
))
scraper_logger.addHandler(file_handler)

# Create console handler for real-time output during execution.
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(logging.Formatter(
    "%(asctime)s - %(levelname)s - %(message)s"
))
scraper_logger.addHandler(console_handler)

# --- State Management Functions ---
# These functions handle the persistent storage of the last processed event ID for each
# monitored event log. This is crucial for resuming operation after restarts without
# reprocessing old events.

def load_last_read_event_id(state_file_path: str, log_name: str) -> int:
    """
    Loads the last successfully processed event record ID for a given log name
    from a JSON state file. The state file stores a dictionary mapping log names
    to their last processed record IDs.

    Args:
        state_file_path (str): The path to the JSON file storing scraper state.
        log_name (str): The name of the event log (e.g., 'Security') to load state for.

    Returns:
        int: The last processed record ID for the specified log. Returns 0 if the
             state file doesn't exist, is corrupted, or if no record for the
             specified log name is found.
    """
    try:
        if os.path.exists(state_file_path):
            with open(state_file_path, 'r', encoding='utf-8') as f:
                state_data = json.load(f)
                last_id = state_data.get(log_name, 0)
                scraper_logger.info(f"Loaded last read event ID for '{log_name}': {last_id}")
                return last_id
        else:
            scraper_logger.info(f"State file '{state_file_path}' not found. "
                                f"Starting '{log_name}' monitoring from the beginning (Record ID 0).")
            return 0
    except json.JSONDecodeError as e:
        scraper_logger.error(f"Error decoding state file '{state_file_path}': {e}. "
                             f"Resetting state for '{log_name}' and starting from ID 0.")
        return 0
    except IOError as e:
        scraper_logger.error(f"IO Error reading state file '{state_file_path}': {e}. "
                             f"Resetting state for '{log_name}' and starting from ID 0.")
        return 0
    except Exception as e:
        scraper_logger.error(f"Unexpected error loading state for '{log_name}': {e}. "
                             f"Resetting state for '{log_name}' and starting from ID 0.")
        return 0

def save_last_read_event_id(state_file_path: str, log_name: str, event_id: int):
    """
    Saves the last successfully processed event record ID for a given log name
    to a JSON state file. If the file exists, it updates the specific log's ID.
    If not, it creates a new file.

    Args:
        state_file_path (str): The path to the JSON file storing scraper state.
        log_name (str): The name of the event log (e.g., 'Security') to save state for.
        event_id (int): The record ID to save.
    """
    try:
        state_data = {}
        # Attempt to load existing state data if the file exists
        if os.path.exists(state_file_path):
            with open(state_file_path, 'r', encoding='utf-8') as f:
                try:
                    state_data = json.load(f)
                except json.JSONDecodeError:
                    scraper_logger.warning(f"State file '{state_file_path}' corrupted or empty. "
                                           "Initializing new state data.")
                    state_data = {}

        # Update the specific log's last read ID
        state_data[log_name] = event_id

        # Write the updated state back to the file
        with open(state_file_path, 'w', encoding='utf-8') as f:
            json.dump(state_data, f, indent=4) # Use indent for human-readable JSON
        scraper_logger.debug(f"Saved last read event ID for '{log_name}': {event_id}")
    except IOError as e:
        scraper_logger.error(f"IO Error writing to state file '{state_file_path}': {e}")
    except Exception as e:
        scraper_logger.error(f"Unexpected error saving state for '{log_name}': {e}")

# --- Syslog Handler Initialization ---

def initialize_syslog_handler(
    syslog_server: str,
    syslog_port: int,
    syslog_protocol: str,
    facility: int
) -> logging.handlers.SysLogHandler:
    """
    Initializes and returns a SysLogHandler configured to send events to a central syslog server.
    Supports both UDP and TCP protocols.

    Args:
        syslog_server (str): IP address or hostname of the syslog server.
        syslog_port (int): Port number for the syslog server.
        syslog_protocol (str): "UDP" or "TCP" (case-insensitive).
        facility (int): Syslog facility code (e.g., logging.handlers.SysLogHandler.LOG_AUTH).

    Returns:
        logging.handlers.SysLogHandler: Configured SysLogHandler instance.
    Raises:
        SystemExit: If the syslog handler cannot be initialized due to critical errors.
    """
    try:
        syslog_address = (syslog_server, syslog_port)

        if syslog_protocol.upper() == "TCP":
            handler = logging.handlers.SysLogHandler(
                address=syslog_address,
                facility=facility,
                socktype=socket.SOCK_STREAM # Specify TCP socket type
            )
            scraper_logger.info(f"Initialized TCP Syslog handler for {syslog_server}:{syslog_port} "
                                f"with facility {facility} and TCP protocol.")
        else: # Default to UDP if not explicitly TCP
            handler = logging.handlers.SysLogHandler(
                address=syslog_address,
                facility=facility
            )
            scraper_logger.info(f"Initialized UDP Syslog handler for {syslog_server}:{syslog_port} "
                                f"with facility {facility} and UDP protocol.")

        # For maximum control over the syslog message format (including headers),
        # we will directly format the message before sending it to the handler.
        # Thus, a simple formatter might suffice or no formatter at all as we'll pass a pre-formatted string.
        # This formatter just ensures no extra boilerplate from standard logging is added.
        handler.setFormatter(logging.Formatter('%(message)s'))
        return handler
    except Exception as e:
        scraper_logger.critical(f"Failed to initialize Syslog handler: {e}. "
                                "Please check syslog server settings and network connectivity.")
        sys.exit(1) # Exit the script if we can't even send logs.

# --- Event Parsing and Formatting Helper Functions ---
# These functions extract and structure relevant data from Windows Event Log records
# and format them into a standard syslog message.

def get_event_message(event_record) -> str:
    """
    Attempts to retrieve the human-readable message for a Windows event record.
    Uses `win32evtlog.FormatMessage`, which leverages the event source's message DLLs
    to reconstruct the event description from the event template and insertion strings.

    Args:
        event_record (PyEVENTLOGRECORD): The event log record object from pywin32.

    Returns:
        str: The formatted event message or an informative error string if formatting fails.
    """
    try:
        # `FormatMessage` can directly take the event record object.
        # It tries to find the correct message DLL based on `SourceName` and `EventID`.
        # The returned message is typically in the local system's language settings.
        return win32evtlog.FormatMessage(event_record)
    except win32evtlog.error as e:
        # Common error codes if the message template cannot be found in the associated DLLs.
        if e.winerror == winerror.ERROR_EVT_MESSAGE_NOT_FOUND or \
           e.winerror == winerror.ERROR_RESOURCE_DATA_NOT_FOUND or \
           e.winerror == winerror.ERROR_MR_MID_NOT_FOUND:
            # Fallback message if the template is unavailable.
            return (f"Could not format event message (Error {e.winerror}). "
                    f"EventID: {event_record.EventID}, Source: {event_record.SourceName}, "
                    f"Category: {event_record.EventCategory}, "
                    f"Raw Strings: {event_record.Strings}")
        else:
            # Log unexpected `win32evtlog` errors during message formatting.
            scraper_logger.warning(f"Unexpected win32evtlog error formatting event message "
                                   f"(EventID: {event_record.EventID}, Source: {event_record.SourceName}): {e}")
            return (f"Error formatting event message (Error {e.winerror}): {e}. "
                    f"EventID: {event_record.EventID}, Source: {event_record.SourceName}")
    except Exception as e:
        # Catch any other general exceptions during message retrieval.
        scraper_logger.error(f"General error in get_event_message for EventID {event_record.EventID}: {e}",
                             exc_info=True)
        return f"Unknown error retrieving event message: {e}"


def parse_security_event_strings(event_id: int, event_strings: tuple) -> dict:
    """
    Parses the 'Strings' attribute of a security event record to extract
    structured key-value data based on known Event IDs. This provides more
    structured access to specific event fields than the raw message.

    Args:
        event_id (int): The Event ID of the record.
        event_strings (tuple): The 'Strings' attribute from a PyEVENTLOGRECORD object,
                               which contains insertion strings for the event message.

    Returns:
        dict: A dictionary of parsed key-value pairs specific to the Event ID.
              Returns an empty dict if the Event ID is not specifically handled or on error.
    """
    parsed_data = {}

    try:
        if event_id == 4624: # Successful Logon
            # Reference: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
            # This mapping helps to extract specific fields by their index in the 'Strings' tuple.
            field_map = {
                0: "Subject_Security_ID", 1: "Subject_Account_Name", 2: "Subject_Account_Domain", 3: "Subject_Logon_ID",
                4: "Logon_Type", 5: "Logon_Process", 6: "Authentication_Package", 7: "Workstation_Name",
                8: "Logon_GUID", 9: "Transmitted_Services", 10: "Service_Name", 11: "Network_Address",
                12: "Port", 13: "Impersonation_Level", 14: "Restricted_Admin_Mode", 15: "Target_User_Name",
                16: "Target_User_SID", 17: "Target_Domain_Name", 18: "Target_Logon_ID",
                19: "Process_Information_Process_ID", 20: "Process_Information_Process_Name",
                21: "Key_Length"
            }
            # Populate parsed_data with available fields from the event_strings
            for i, field_name in field_map.items():
                if i < len(event_strings):
                    # Clean up common placeholder values
                    value = event_strings[i]
                    parsed_data[field_name] = value if value and value != '-' else "N/A"

        elif event_id == 4625: # Failed Logon
            # Reference: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625
            field_map = {
                0: "Subject_Security_ID", 1: "Subject_Account_Name", 2: "Subject_Account_Domain", 3: "Subject_Logon_ID",
                4: "Logon_Type", 5: "Logon_Process", 6: "Authentication_Package", 7: "Workstation_Name",
                8: "Logon_GUID", 9: "Transmitted_Services", 10: "Service_Name", 11: "Network_Address",
                12: "Port", 13: "Failure_Reason", 14: "Status_Code", 15: "Sub_Status_Code",
                16: "Target_User_Name", 17: "Target_User_SID", 18: "Target_Domain_Name"
            }
            for i, field_name in field_map.items():
                if i < len(event_strings):
                    value = event_strings[i]
                    parsed_data[field_name] = value if value and value != '-' else "N/A"

        elif event_id == 4740: # Account Locked Out
            # Reference: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4740
            field_map = {
                0: "Target_User_Name", 1: "Target_User_SID", 2: "Subject_User_Name", 3: "Subject_User_SID",
                4: "Subject_Logon_ID"
            }
            for i, field_name in field_map.items():
                if i < len(event_strings):
                    value = event_strings[i]
                    parsed_data[field_name] = value if value and value != '-' else "N/A"

        elif event_id == 4672: # Special privileges assigned to new logon
            # Reference: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4672
            field_map = {
                0: "Subject_Security_ID", 1: "Subject_Account_Name", 2: "Subject_Account_Domain", 3: "Subject_Logon_ID"
            }
            for i, field_name in field_map.items():
                if i < len(event_strings):
                    value = event_strings[i]
                    parsed_data[field_name] = value if value and value != '-' else "N/A"

        # Add more event IDs and their specific parsing logic here to enhance structured data extraction.
        # Example:
        # elif event_id == 1234: # Another custom event
        #     field_map = {0: "FieldA", 1: "FieldB"}
        #     for i, field_name in field_map.items():
        #         if i < len(event_strings):
        #             parsed_data[field_name] = event_strings[i]

    except IndexError as e:
        # Log a warning if the event_strings tuple doesn't have the expected number of elements
        # for a specific Event ID's parsing map.
        scraper_logger.warning(
            f"IndexError while parsing Event ID {event_id} strings: {e}. "
            f"Available strings ({len(event_strings)}): {event_strings}. "
            "Some structured fields might be missing or incomplete."
        )
    except Exception as e:
        # Catch any other general exceptions during parsing.
        scraper_logger.error(f"Error parsing event ID {event_id} strings: {e}", exc_info=True)

    return parsed_data

def format_event_for_syslog(
    event_record,
    hostname: str,
    full_message: str,
    parsed_data: dict
) -> str:
    """
    Formats a Windows event log record into a syslog-compatible string,
    adhering generally to RFC 5424 but simplified for common SysLogHandler usage.
    It includes a structured data part derived from `parsed_data`.

    Args:
        event_record (PyEVENTLOGRECORD): The event log record object from pywin32.
        hostname (str): The hostname of the machine where the event occurred.
        full_message (str): The full human-readable message of the event.
        parsed_data (dict): A dictionary of parsed key-value pairs from event strings.

    Returns:
        str: A single string formatted for syslog.
    """
    # Convert PyTime object (which is a datetime.datetime instance) to ISO 8601 format.
    # The 'TimeGenerated' attribute provides the timestamp of the event.
    timestamp = event_record.TimeGenerated.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    # Map Windows EventType to syslog severity levels.
    # Syslog severity: 0=Emergency, 1=Alert, 2=Critical, 3=Error, 4=Warning, 5=Notice, 6=Informational, 7=Debug.
    severity_map = {
        win32evtlog.EVENTLOG_ERROR_TYPE: 3,        # Error
        win32evtlog.EVENTLOG_WARNING_TYPE: 4,      # Warning
        win32evtlog.EVENTLOG_INFORMATION_TYPE: 6,  # Informational
        win32evtlog.EVENTLOG_AUDIT_SUCCESS: 5,     # Notice (Successful audit implies something notable happened)
        win32evtlog.EVENTLOG_AUDIT_FAILURE: 1,     # Alert (Failed audit is critical/requires immediate attention)
    }
    # Default to informational if EventType is unknown.
    syslog_severity = severity_map.get(event_record.EventType, 6) # Default to Informational (6)

    # The PRI (Priority) value combines facility and severity: PRI = facility * 8 + severity.
    # The facility is configured globally.
    priority_value = CONFIG['SYSLOG_FACILITY'] * 8 + syslog_severity

    # Construct the structured data string from the parsed_data dictionary.
    # This part adheres to RFC 5424's structured data format, e.g., [exampleSDID@32473 key="value"].
    structured_data_items = []
    if parsed_data:
        # Iterate through parsed key-value pairs to build structured data.
        for key, value in parsed_data.items():
            # Sanitize values to prevent breaking the syslog message format.
            # Replace backslashes, double quotes, and newlines.
            sanitized_value = str(value).replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')
            structured_data_items.append(f'{key}="{sanitized_value}"')
        # Use a generic SD_ID or derive one. 'winEvt@1' is a common convention for Windows events.
        structured_data_str = f"[winEvt@1 {syslog_severity} {event_record.EventID} {' '.join(structured_data_items)}]"
    else:
        structured_data_str = "-" # RFC 5424 requires '-' if no structured data

    # Construct the final syslog message according to RFC 5424 format:
    # <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
    # VERSION: 1 (for RFC 5424)
    # APP-NAME: We use the configured LOG_NAME (e.g., 'Security')
    # PROCID: We use the event's SourceName (e.g., 'Microsoft-Windows-Security-Auditing')
    # MSGID: We use the EventID.
    # MSG: The full human-readable event message. Trim whitespace.
    syslog_message = (
        f"<{priority_value}>1 {timestamp} {hostname} {CONFIG['LOG_NAME']} "
        f"{event_record.SourceName.replace(' ', '_')} {event_record.EventID} " # Replace spaces in SourceName for consistency
        f"{structured_data_str} {full_message.strip()}"
    )

    return syslog_message

# --- Core Scraper Functions ---
# These functions manage the interaction with the Windows Event Log API and orchestrate
# the processing and forwarding of events.

def query_event_log(
    log_name: str,
    last_record_id: int,
    target_event_ids: list,
    max_events_per_read: int
) -> tuple[list, int]:
    """
    Queries the specified Windows Event Log for new events starting from a given record ID.
    Filters events by a list of target Event IDs.

    Args:
        log_name (str): The name of the event log (e.g., 'Security').
        last_record_id (int): The record ID from which to start reading events.
                              Events with RecordNumber <= last_record_id will be skipped.
        target_event_ids (list): A list of integer Event IDs to filter for.
        max_events_per_read (int): Maximum number of events to retrieve in one call to ReadEventLog.

    Returns:
        tuple[list, int]: A tuple containing:
                          - A list of PyEVENTLOGRECORD objects for new, matching events.
                          - The highest RecordNumber found among the retrieved events that were *actually newer*
                            than `last_record_id`. If no new events, it returns the original `last_record_id`.
    """
    new_events = []
    current_max_record_id = last_record_id # This will track the highest RecordNumber seen in the current read cycle.
    hEventLog = None # Handle to the event log.

    try:
        # Open the event log. `EVENTLOG_SEQUENTIAL_READ` is crucial for reading events in order,
        # and `EVENTLOG_FORWARDS_READ` ensures we read from oldest to newest.
        hEventLog = win32evtlog.OpenEventLog(CONFIG["HOSTNAME"], log_name)
        scraper_logger.debug(f"Successfully opened event log '{log_name}'.")

        flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        
        # Determine the initial offset for reading. If last_record_id is 0, we read from the beginning.
        # Otherwise, we start reading from the event *after* the last processed one.
        # win32evtlog.ReadEventLog with EVENTLOG_SEQUENTIAL_READ automatically moves the cursor.
        # The `Offset` parameter is ignored when `EVENTLOG_SEQUENTIAL_READ` is used.
        # We handle skipping already processed events manually after reading.

        scraper_logger.info(f"Checking for new events in '{log_name}' starting from "
                            f"Record ID {last_record_id + 1}...")

        # Loop to read events in batches until no more events are returned or `max_events_per_read` limit is hit.
        while True:
            events_batch = win32evtlog.ReadEventLog(
                hEventLog,
                flags,
                0, # Offset is ignored for sequential read.
                max_events_per_read
            )
            
            # If `ReadEventLog` returns an empty list, it means we've reached the end of the log.
            if not events_batch:
                scraper_logger.debug(f"No more events found in '{log_name}' during this read cycle.")
                break

            for event in events_batch:
                # Only process events with a RecordNumber greater than the last successfully processed ID.
                if event.RecordNumber > last_record_id:
                    # Keep track of the highest record number encountered in the current batch.
                    # This will be the candidate for the next `last_processed_record_id`.
                    current_max_record_id = max(current_max_record_id, event.RecordNumber)

                    # Filter events by the configured `TARGET_EVENT_IDS`.
                    if event.EventID in target_event_ids:
                        new_events.append(event)
                        scraper_logger.debug(
                            f"Discovered new target event: Record ID {event.RecordNumber}, Event ID {event.EventID}, "
                            f"Source: {event.SourceName}, Time: {event.TimeGenerated}"
                        )
                else:
                    scraper_logger.debug(f"Skipping old event Record ID {event.RecordNumber} (already processed: <= {last_record_id}).")

            # If the number of events read in this batch is less than `max_events_per_read`,
            # it indicates we've reached the end of the log or a temporary pause in new events.
            if len(events_batch) < max_events_per_read:
                scraper_logger.debug(f"Read {len(events_batch)} events, less than max batch size. End of current log stream reached.")
                break
            
            # If we read a full batch, there might be more, so the loop continues.
            scraper_logger.debug(f"Read a full batch of {len(events_batch)} events. Continuing to read next batch.")

        scraper_logger.info(f"Finished querying '{log_name}'. Found {len(new_events)} new matching events "
                            f"since Record ID {last_record_id}.")

    except win32evtlog.error as e:
        # Handle specific `win32evtlog` errors for better diagnostics.
        if e.winerror == winerror.ERROR_ACCESS_DENIED:
            scraper_logger.error(
                f"Access Denied to event log '{log_name}'. "
                f"Ensure the script is running with sufficient privileges (e.g., as Administrator)."
            )
        elif e.winerror == winerror.ERROR_FILE_NOT_FOUND:
             scraper_logger.error(f"Event log '{log_name}' not found. Please check the log name in configuration.")
        else:
            scraper_logger.error(f"Error accessing event log '{log_name}': {e}", exc_info=True)
    except Exception as e:
        scraper_logger.error(f"An unexpected error occurred while querying event log '{log_name}': {e}", exc_info=True)
    finally:
        # Always ensure the event log handle is closed to release resources.
        if hEventLog:
            win32evtlog.CloseEventLog(hEventLog)
            scraper_logger.debug(f"Closed event log handle for '{log_name}'.")

    # Return the list of new events and the highest record ID processed in this cycle.
    # If no new events were found, `current_max_record_id` will still be `last_record_id`.
    return new_events, current_max_record_id

def process_and_forward_event(
    event_record,
    syslog_handler: logging.handlers.SysLogHandler,
    scraper_logger: logging.Logger,
    hostname: str
):
    """
    Processes a single Windows event log record:
    1. Retrieves its human-readable message.
    2. Parses specific fields from its insertion strings.
    3. Formats the event into a syslog-compatible string (RFC 5424 inspired).
    4. Forwards the formatted message to the central syslog server.

    Args:
        event_record (PyEVENTLOGRECORD): The event log record object from pywin32.
        syslog_handler (logging.handlers.SysLogHandler): The configured syslog handler instance.
        scraper_logger (logging.Logger): The scraper's internal logger for status and error reporting.
        hostname (str): The hostname of the machine where the event occurred.
    """
    try:
        # Step 1: Get the full human-readable message for the event.
        full_message = get_event_message(event_record)
        scraper_logger.debug(f"Retrieved message for Event ID {event_record.EventID}, "
                             f"Record #: {event_record.RecordNumber}: {full_message[:150]}...")

        # Step 2: Parse specific event strings for structured data.
        # This enhances the detail available for analysis on the syslog server.
        parsed_data = parse_security_event_strings(event_record.EventID, event_record.Strings)
        scraper_logger.debug(f"Parsed data for Event ID {event_record.EventID}: {parsed_data}")

        # Step 3: Format the event into a syslog-compatible string.
        syslog_formatted_message = format_event_for_syslog(
            event_record, hostname, full_message, parsed_data
        )
        scraper_logger.debug(f"Syslog formatted message for Event ID {event_record.EventID}, "
                             f"Record #: {event_record.RecordNumber}: {syslog_formatted_message[:250]}...")

        # Step 4: Send the formatted message to syslog.
        # The SysLogHandler expects a LogRecord object. We create a dummy one
        # with the fully pre-formatted message. The handler's formatter is set
        # to just pass the message through (`%(message)s`).
        dummy_record = logging.LogRecord(
            name=CONFIG["LOG_NAME"],      # Source name for syslog (APP-NAME)
            level=logging.INFO,           # Generic level; actual severity is in the message PRI part
            pathname=None,                # Not applicable for this type of log record
            lineno=None,                  # Not applicable
            msg=syslog_formatted_message, # Our pre-formatted syslog string
            args=None,
            exc_info=None,
            func=None,
            sinfo=None
        )
        syslog_handler.emit(dummy_record) # Emit the record directly to the handler.

        scraper_logger.info(
            f"Successfully forwarded event (ID: {event_record.EventID}, Record #: {event_record.RecordNumber}) "
            f"from '{event_record.SourceName}' to syslog."
        )

    except Exception as e:
        # Log any errors encountered during processing or forwarding of an individual event.
        scraper_logger.error(
            f"Failed to process or forward event (ID: {event_record.EventID}, Record #: {event_record.RecordNumber}): {e}",
            exc_info=True
        )

# --- Main Scraper Execution Function ---

def run_scraper():
    """
    The main execution function for the Windows Event Log Scraper.
    It initializes all necessary components, enters a continuous polling loop,
    and handles graceful shutdown or critical errors.
    """
    scraper_logger.info("Starting Windows Event Log Scraper service...")
    scraper_logger.info(f"Monitoring log: '{CONFIG['LOG_NAME']}' for Event IDs: {CONFIG['TARGET_EVENT_IDS']}")
    scraper_logger.info(f"Forwarding to syslog server: {CONFIG['SYSLOG_SERVER']}:{CONFIG['SYSLOG_PORT']} "
                        f"using {CONFIG['SYSLOG_PROTOCOL']} protocol.")
    scraper_logger.info(f"Scraper internal logs are written to: {CONFIG['SCRAPER_LOG_FILE']}")

    # Initialize the syslog handler once at startup.
    syslog_handler = initialize_syslog_handler(
        CONFIG["SYSLOG_SERVER"],
        CONFIG["SYSLOG_PORT"],
        CONFIG["SYSLOG_PROTOCOL"],
        CONFIG["SYSLOG_FACILITY"]
    )

    # Main continuous polling loop. The script will remain in this loop until interrupted.
    while True:
        # Load the last processed record ID to avoid reprocessing old events.
        last_processed_record_id = load_last_read_event_id(CONFIG["STATE_FILE"], CONFIG["LOG_NAME"])
        # Initialize `new_max_record_id_in_cycle` with the currently loaded ID.
        # This will be updated if new events are found and processed.
        new_max_record_id_in_cycle = last_processed_record_id

        try:
            # Query the event log for new events.
            new_events, current_batch_max_record_id = query_event_log(
                CONFIG["LOG_NAME"],
                last_processed_record_id,
                CONFIG["TARGET_EVENT_IDS"],
                CONFIG["MAX_EVENTS_PER_READ"]
            )

            if new_events:
                scraper_logger.info(f"Found {len(new_events)} new events to process and forward.")
                # Sort events by RecordNumber to ensure they are processed in chronological order.
                # This is important for consistent `last_read_event_id` tracking.
                new_events.sort(key=lambda x: x.RecordNumber)

                # Process and forward each new event.
                for event in new_events:
                    process_and_forward_event(event, syslog_handler, scraper_logger, CONFIG["HOSTNAME"])
                    # After successfully processing an event, update the highest record ID
                    # processed in *this specific monitoring cycle*.
                    new_max_record_id_in_cycle = max(new_max_record_id_in_cycle, event.RecordNumber)
            else:
                scraper_logger.info("No new matching events found in this polling cycle.")

            # Save the updated `last_read_event_id` if any new events were successfully processed.
            # This ensures persistence across restarts.
            if new_max_record_id_in_cycle > last_processed_record_id:
                save_last_read_event_id(CONFIG["STATE_FILE"], CONFIG["LOG_NAME"], new_max_record_id_in_cycle)
                scraper_logger.info(f"Updated last processed record ID for '{CONFIG['LOG_NAME']}' to: {new_max_record_id_in_cycle}")
            else:
                scraper_logger.debug("No update to last processed record ID needed as no new events were processed or found.")

        except Exception as e:
            # Catch any unexpected critical errors that occur during a polling cycle.
            scraper_logger.critical(f"Critical error in main scraper loop: {e}", exc_info=True)
            # Depending on error severity and recovery strategy,
            # you might implement retry logic with exponential backoff or simply continue after logging.
            # For this script, we log and continue to the next polling interval.
        
        # Pause for the configured interval before the next polling cycle.
        scraper_logger.info(f"Sleeping for {CONFIG['POLLING_INTERVAL_SECONDS']} seconds before next poll...")
        time.sleep(CONFIG["POLLING_INTERVAL_SECONDS"])

# --- Script Entry Point ---

if __name__ == "__main__":
    # Perform a quick check to ensure the script is running on a Windows operating system.
    # 'pywin32' is Windows-specific, so the script will not function elsewhere.
    if sys.platform != "win32":
        scraper_logger.critical("This script is designed to run on Windows only due to its dependency on 'pywin32'.")
        sys.exit(1)

    try:
        # Start the main scraper function.
        run_scraper()
    except KeyboardInterrupt:
        # Handle graceful shutdown if the user interrupts the script (e.g., Ctrl+C).
        scraper_logger.info("Windows Event Log Scraper stopped by user (KeyboardInterrupt). Exiting.")
        sys.exit(0)
    except Exception as e:
        # Catch any unhandled, fatal exceptions that escape the main loop.
        scraper_logger.critical(f"An unhandled fatal error occurred, causing the scraper to terminate: {e}", exc_info=True)
        sys.exit(1)