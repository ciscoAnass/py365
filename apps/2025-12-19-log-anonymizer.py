import re
import os
import argparse
import sys
import logging
from collections import defaultdict
from datetime import datetime

# --- Configuration Constants ---
# Define regular expressions for various types of PII
# These regex patterns are designed to be relatively robust but may not cover all edge cases.
# For production systems, consider more extensive and validated regex libraries or PII detection services.
#
# IP Address Patterns:
#   - IPv4: Matches standard IPv4 addresses (e.g., 192.168.1.1, 10.0.0.100).
#     It accounts for the three-digit number range (0-255).
#   - IPv6: A more complex pattern to match common IPv6 formats.
#     This is a simplified version and might not catch all valid IPv6 addresses.
#     A full IPv6 regex is extremely long. This aims for common representations.
IP_ADDRESS_PATTERNS = [
    re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),  # IPv4
    re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:[0-9a-fA-F]{0,4}\b|\b[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){0,6}::\b') # Simplified IPv6
]

# Email Address Pattern:
#   - Standard email format: user@domain.tld
#     Handles various valid characters for local-part and domain.
EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

# User/Name Patterns:
#   - Common Name formats: First Last, First.Last, etc.
#     These are heuristic and prone to false positives/negatives.
#     They look for patterns like "Name: [Value]", "user=[Value]", "referrer=...", etc.
#     This section is highly dependent on log file format.
#     For general text, identifying names without context is extremely hard.
NAME_PATTERNS = [
    re.compile(r'(?i)(?:user|username|client|name)[:=\s][\'"]?([a-zA-Z0-9._%+-]+)[\'"]?'),
    re.compile(r'(?i)(?:full_name|display_name)[:=\s][\'"]?([a-zA-Z ]+)[\'"]?'),
    re.compile(r'(?i)account_id[:=\s][\'"]?([a-zA-Z0-9-]+)[\'"]?'),
    re.compile(r'(?i)uid[:=\s][\'"]?([a-zA-Z0-9-]+)[\'"]?'),
    re.compile(r'(?i)user_id[:=\s][\'"]?([a-zA-Z0-9-]+)[\'"]?'),
    re.compile(r'(?i)referrer=https?:\/\/(?:www\.)?([a-zA-Z0-9.-]+)') # General domain in referrer might be PII
]

# Session ID / Token Patterns:
#   - Often long alphanumeric strings, sometimes with hyphens.
#     These are highly specific and might need tuning based on actual log formats.
SESSION_ID_PATTERNS = [
    re.compile(r'(?i)(?:session_id|sid|token|auth_token)[:=\s][\'"]?([a-f0-9]{32,64})[\'"]?'), # Common for GUIDs/Hashes
    re.compile(r'(?i)(?:jsessionid|PHPSESSID)=([a-zA-Z0-9]{16,64})')
]

# Phone Number Patterns:
#   - Various international formats.
#     This is a simplified set. Real-world phone number regex is complex.
PHONE_NUMBER_PATTERNS = [
    re.compile(r'\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'), # US/Canadian style
    re.compile(r'\b(?:\+?\d{1,3}[-.\s]?)?\d{2,4}[-.\s]?\d{2,4}[-.\s]?\d{2,4}[-.\s]?\d{2,4}\b') # More general international
]

# URL Parameter PII patterns:
#   - Identifies sensitive parameters in URLs
URL_PARAMETER_PATTERNS = [
    re.compile(r'(?i)(?:email|user|username|uid|id|account|client)=([^& ]+)'),
    re.compile(r'(?i)token=([^& ]+)'),
    re.compile(r'(?i)password=([^& ]+)')
]

# Combined list of all PII patterns
ALL_PII_PATTERNS = {
    'IP_ADDRESS': IP_ADDRESS_PATTERNS,
    'EMAIL': [EMAIL_PATTERN],
    'NAME': NAME_PATTERNS,
    'SESSION_ID': SESSION_ID_PATTERNS,
    'PHONE_NUMBER': PHONE_NUMBER_PATTERNS,
    'URL_PARAMETER_PII': URL_PARAMETER_PATTERNS
}

# --- Anonymization Configuration ---
# Prefix for anonymized values. 'XXX' will be replaced by a unique ID.
ANONYMIZED_PREFIX = "ANON_"
# Separator for type and ID
ANONYMIZED_SEPARATOR = "_"

# --- Logging Configuration ---
LOG_FILE_NAME = "log_anonymizer.log"
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT, filename=LOG_FILE_NAME, filemode='a')
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter(LOG_FORMAT))
logging.getLogger().addHandler(console_handler)

def initialize_logger():
    """
    Initializes and configures the logging system for the script.
    Ensures logs are written to a file and also output to the console.
    """
    logging.info("Log anonymizer script started.")
    logging.info(f"Logging configured. Output will be written to '{LOG_FILE_NAME}' and console.")

def create_output_directory(output_path):
    """
    Ensures that the specified output directory exists.
    If it doesn't exist, it creates it.

    Args:
        output_path (str): The path to the desired output directory.

    Raises:
        OSError: If the directory cannot be created for some reason
                 (e.g., permission issues).
    """
    if not os.path.exists(output_path):
        try:
            os.makedirs(output_path)
            logging.info(f"Created output directory: {output_path}")
        except OSError as e:
            logging.error(f"Error creating output directory '{output_path}': {e}")
            raise
    else:
        logging.info(f"Output directory '{output_path}' already exists.")

class Anonymizer:
    """
    Manages the anonymization process, including PII detection, replacement,
    and mapping storage.
    """
    def __init__(self, anonymized_prefix=ANONYMIZED_PREFIX, anonymized_separator=ANONYMIZED_SEPARATOR):
        """
        Initializes the Anonymizer with PII patterns and mapping storage.

        Args:
            anonymized_prefix (str): The prefix for anonymized placeholders (e.g., 'ANON_').
            anonymized_separator (str): Separator between prefix and ID (e.g., '_').
        """
        self.anonymized_prefix = anonymized_prefix
        self.anonymized_separator = anonymized_separator
        self.pii_mapping = defaultdict(lambda: {})  # Stores {pii_type: {original_value: anonymized_value}}
        self.pii_counters = defaultdict(int)       # Stores {pii_type: counter_value}
        self.total_replacements = 0
        logging.info("Anonymizer initialized.")
        logging.debug(f"Anonymization prefix: {self.anonymized_prefix}, separator: {self.anonymized_separator}")

    def _get_next_anonymized_id(self, pii_type):
        """
        Generates a unique anonymized ID for a given PII type.

        Args:
            pii_type (str): The type of PII (e.g., 'IP_ADDRESS', 'EMAIL').

        Returns:
            str: A unique anonymized identifier string.
        """
        self.pii_counters[pii_type] += 1
        return f"{self.anonymized_prefix}{pii_type}{self.anonymized_separator}{self.pii_counters[pii_type]:04d}"

    def anonymize_value(self, pii_type, original_value):
        """
        Retrieves or generates an anonymized value for a given original PII value.

        Args:
            pii_type (str): The type of PII.
            original_value (str): The original PII string.

        Returns:
            str: The anonymized replacement string.
        """
        if original_value not in self.pii_mapping[pii_type]:
            anonymized_id = self._get_next_anonymized_id(pii_type)
            self.pii_mapping[pii_type][original_value] = anonymized_id
            logging.debug(f"Mapped new PII: Type='{pii_type}', Original='{original_value}', Anonymized='{anonymized_id}'")
        else:
            logging.debug(f"Re-using existing PII mapping for Type='{pii_type}', Original='{original_value}'")

        return self.pii_mapping[pii_type][original_value]

    def process_line(self, line):
        """
        Processes a single log line, finding and replacing all detected PII.

        Args:
            line (str): The raw log line string.

        Returns:
            str: The anonymized log line string.
        """
        anonymized_line = line
        replacements_made_in_line = 0

        for pii_type, patterns_list in ALL_PII_PATTERNS.items():
            for pattern in patterns_list:
                # Use a while loop with re.sub to ensure all occurrences are handled
                # This also allows for capturing groups to be used if the pattern has them
                # For patterns without groups, match.group(0) is the full match.
                # For patterns with groups, we need to decide which group to anonymize.
                # Here, we assume if there's a group, that's the part we want,
                # otherwise, the full match.
                
                # We need to iterate and replace to ensure that replacements don't
                # interfere with subsequent pattern matching within the same line.
                # Using a custom replacer function with re.sub is robust.
                
                def replacement_func(match):
                    nonlocal replacements_made_in_line
                    # Determine the value to anonymize. If there are groups, use the first group.
                    # Otherwise, use the full match.
                    original_value_to_anonymize = match.group(1) if len(match.groups()) > 0 else match.group(0)
                    
                    # Ensure we don't accidentally anonymize part of our own anonymized IDs
                    if original_value_to_anonymize.startswith(self.anonymized_prefix):
                        return match.group(0) # Don't anonymize already anonymized data

                    anonymized_value = self.anonymize_value(pii_type, original_value_to_anonymize)
                    replacements_made_in_line += 1
                    
                    # Construct the replacement string. If the original pattern had groups
                    # and we anonymized a specific group, we need to reconstruct the string
                    # to keep the surrounding non-PII parts.
                    if len(match.groups()) > 0:
                        # This assumes the first group is the PII to replace.
                        # This requires careful regex design.
                        # Example: r'(user=)([^& ]+)' -> replaces group 2, keeps group 1
                        # This implementation just replaces the entire matched string if groups are present.
                        # For more nuanced group replacement, `re.sub` needs more sophisticated handling or
                        # a custom iteration over matches.
                        # For simplicity, for now, if there's a group, we just replace the whole match
                        # with the anonymized value, which might not be ideal for all scenarios.
                        # A better approach for group-specific replacement is to build the replacement string
                        # piece by piece.
                        
                        # Let's adjust to replace *only* the captured group if it exists,
                        # and the full match otherwise.
                        
                        # Find the span of the captured group within the full match.
                        # Example: original string "user=johndoe", match.group(0) is "user=johndoe"
                        # match.group(1) is "johndoe".
                        # match.start(1) and match.end(1) give the indices within the original string.
                        
                        # A more robust way:
                        # If a group was captured, we assume the pattern implies the PII is *within*
                        # the full match but only represented by the group.
                        # For example, `(user=)([^& ]+)` should replace `([^& ]+)`.
                        # If we just do `anonymized_value` for `match.group(0)`, then `user=johndoe` becomes `ANON_USER_0001`.
                        # But we probably want `user=ANON_USER_0001`.
                        
                        # So, we rebuild the string:
                        full_match_string = match.group(0)
                        group_start, group_end = match.span(1) # Span of the first captured group
                        
                        # Calculate indices relative to the start of the full match
                        relative_group_start = group_start - match.start(0)
                        relative_group_end = group_end - match.start(0)
                        
                        # Reconstruct: part before group + anonymized + part after group
                        return (full_match_string[:relative_group_start] + 
                                anonymized_value + 
                                full_match_string[relative_group_end:])
                    else:
                        return anonymized_value # No groups, replace full match

                # Apply the replacement function to all non-overlapping matches
                anonymized_line, count = pattern.subn(replacement_func, anonymized_line)
                if count > 0:
                    logging.debug(f"Pattern for '{pii_type}' made {count} replacements in a line.")
                    self.total_replacements += count
                    replacements_made_in_line += count # This is already counted within replacement_func, so don't double count.
                                                      # The `count` from `subn` refers to the number of *substitutions*,
                                                      # which is what `replacements_made_in_line` should reflect.
                                                      # Let's adjust the logic slightly. The function `replacement_func`
                                                      # is called for each match. `subn` returns the number of times
                                                      # the function was called. So we just need `self.total_replacements += count`.
                                                      # And for line-specific count, we can calculate it too.
                                                      # To ensure the line-specific count is correct, we should update it here.
                                                      # The `nonlocal replacements_made_in_line` might be tricky if a single
                                                      # pattern matches multiple times in the same line.
                                                      # The `subn` approach is cleaner.
                                                      #
                                                      # Let's revert `replacements_made_in_line` to be local to `process_line`
                                                      # and just accumulate the `count` returned by `subn`.
                                                      # The `self.total_replacements` will sum up all replacements.
                                                      #
                                                      # Corrected flow:
                                                      # `replacement_func` just returns the anonymized value.
                                                      # `subn` counts how many times `replacement_func` was invoked.
                                                      # We increment `total_replacements` by this count.
                                                      # The issue is that `replacement_func` needs `self.anonymize_value`
                                                      # and access to the anonymizer instance.
                                                      # It's better to make `replacement_func` a method or a closure
                                                      # that captures `self`.

                # Let's refine the `replacement_func` to be a method for clarity and proper scope.
                # However, `re.sub` expects a callable, and binding `self` explicitly within a loop
                # for `replacement_func` can be slightly awkward.
                # A lambda or a nested function is often used.
                # Let's stick with the nested function but ensure `self` is accessible.
                # The `nonlocal replacements_made_in_line` and `self` reference is fine.

                # Redefine replacement_func for proper state management within the loop.
                def _get_anonymized_replacement_for_match(match, pii_type_context):
                    original_value_to_anonymize = match.group(1) if len(match.groups()) > 0 else match.group(0)

                    # Important safeguard: Prevent re-anonymizing data that's already anonymized
                    if original_value_to_anonymize.startswith(self.anonymized_prefix):
                        logging.debug(f"Skipping re-anonymization of already anonymized value: {original_value_to_anonymize}")
                        return match.group(0)

                    anonymized_replacement_value = self.anonymize_value(pii_type_context, original_value_to_anonymize)
                    
                    if len(match.groups()) > 0:
                        # Reconstruct if a group was captured (implies PII is part of a larger string)
                        full_match_string = match.group(0)
                        group_start, group_end = match.span(1) # Span of the first captured group
                        
                        relative_group_start = group_start - match.start(0)
                        relative_group_end = group_end - match.start(0)
                        
                        return (full_match_string[:relative_group_start] + 
                                anonymized_replacement_value + 
                                full_match_string[relative_group_end:])
                    else:
                        return anonymized_replacement_value

                anonymized_line, count = pattern.subn(
                    lambda match: _get_anonymized_replacement_for_match(match, pii_type),
                    anonymized_line
                )
                self.total_replacements += count
                if count > 0:
                    logging.debug(f"Pattern for '{pii_type}' made {count} replacements in the current line.")

        return anonymized_line

    def save_mapping_to_file(self, output_dir, timestamp):
        """
        Saves the PII mapping to a file in the specified output directory.

        Args:
            output_dir (str): The directory to save the mapping file.
            timestamp (str): A timestamp string to include in the filename.
        """
        mapping_file_path = os.path.join(output_dir, f"pii_mapping_{timestamp}.txt")
        try:
            with open(mapping_file_path, 'w', encoding='utf-8') as f:
                f.write(f"# PII Anonymization Mapping - Generated on {datetime.now().isoformat()}\n")
                f.write(f"# Total replacements made: {self.total_replacements}\n")
                f.write("# Format: PII_TYPE | Original Value | Anonymized Value\n\n")

                for pii_type in sorted(self.pii_mapping.keys()):
                    f.write(f"--- {pii_type} ---\n")
                    for original_val in sorted(self.pii_mapping[pii_type].keys()):
                        anonymized_val = self.pii_mapping[pii_type][original_val]
                        f.write(f"{pii_type} | {original_val} | {anonymized_val}\n")
                    f.write("\n")
            logging.info(f"PII mapping saved to: {mapping_file_path}")
        except IOError as e:
            logging.error(f"Error saving PII mapping to file '{mapping_file_path}': {e}")
            raise

def process_single_file(input_filepath, output_filepath, anonymizer_instance):
    """
    Processes a single log file, anonymizing its content and writing to an output file.

    Args:
        input_filepath (str): The path to the input log file.
        output_filepath (str): The path to the output anonymized log file.
        anonymizer_instance (Anonymizer): An instance of the Anonymizer class.

    Returns:
        int: The number of lines processed in the file.
    """
    lines_processed = 0
    logging.info(f"Processing file: {input_filepath}")
    logging.info(f"Output will be written to: {output_filepath}")

    try:
        with open(input_filepath, 'r', encoding='utf-8', errors='ignore') as infile, \
             open(output_filepath, 'w', encoding='utf-8') as outfile:
            for line_num, line in enumerate(infile, 1):
                try:
                    anonymized_line = anonymizer_instance.process_line(line)
                    outfile.write(anonymized_line)
                    lines_processed += 1
                except Exception as line_e:
                    logging.error(f"Error processing line {line_num} in '{input_filepath}': {line_e}. Skipping line.")
                    outfile.write(line) # Write original line if error occurs

        logging.info(f"Finished processing '{input_filepath}'. Processed {lines_processed} lines.")
    except FileNotFoundError:
        logging.error(f"Input file not found: {input_filepath}")
        raise
    except IOError as e:
        logging.error(f"I/O error processing '{input_filepath}': {e}")
        raise
    except Exception as e:
        logging.error(f"An unexpected error occurred while processing '{input_filepath}': {e}")
        raise

    return lines_processed

def process_files_in_directory(input_dir, output_dir, anonymizer_instance):
    """
    Processes all log files within a specified input directory,
    writing anonymized versions to an output directory.

    Args:
        input_dir (str): The path to the input directory containing log files.
        output_dir (str): The path to the output directory for anonymized log files.
        anonymizer_instance (Anonymizer): An instance of the Anonymizer class.

    Returns:
        int: The total number of files processed.
    """
    total_files_processed = 0
    if not os.path.isdir(input_dir):
        logging.error(f"Input directory not found or is not a directory: {input_dir}")
        raise FileNotFoundError(f"Input directory not found: {input_dir}")

    create_output_directory(output_dir)

    logging.info(f"Scanning directory: {input_dir} for log files...")
    for filename in os.listdir(input_dir):
        if filename.endswith(('.log', '.txt', '.access', '.error')): # Common log file extensions
            input_filepath = os.path.join(input_dir, filename)
            output_filepath = os.path.join(output_dir, f"anonymized_{filename}")
            
            # Skip if it's a directory or a special file
            if not os.path.isfile(input_filepath):
                logging.debug(f"Skipping non-file entry: {input_filepath}")
                continue

            try:
                process_single_file(input_filepath, output_filepath, anonymizer_instance)
                total_files_processed += 1
            except Exception as e:
                logging.warning(f"Failed to process file '{input_filepath}': {e}")
                # Continue to next file despite error in one file
                
    logging.info(f"Finished processing all files in directory '{input_dir}'. Total files processed: {total_files_processed}")
    return total_files_processed

def setup_arg_parser():
    """
    Sets up and returns the argument parser for command-line arguments.

    Returns:
        argparse.ArgumentParser: Configured argument parser.
    """
    parser = argparse.ArgumentParser(
        description="""
        Log Anonymizer Script:
        Parses log files to find and replace PII (Personally Identifiable Information)
        like IP addresses, email addresses, names, etc., with anonymized placeholders.
        The script supports processing individual files or entire directories.
        A mapping file is generated to record the original to anonymized value relationships.
        """,
        formatter_class=argparse.RawTextHelpFormatter # For better help message formatting
    )

    # Mutually exclusive group for file or directory input
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        '-f', '--file',
        type=str,
        help='Path to a single log file to anonymize.'
    )
    input_group.add_argument(
        '-d', '--directory',
        type=str,
        help='Path to a directory containing log files to anonymize.'
    )

    parser.add_argument(
        '-o', '--output',
        type=str,
        required=True,
        help='Path to the output directory where anonymized logs and the PII mapping file will be saved.'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging output (DEBUG level).'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Perform a dry run. No output files will be written, but PII detection will occur.'
    )

    return parser

def main():
    """
    Main function to parse arguments, initialize anonymizer, and start the processing.
    """
    initialize_logger()
    parser = setup_arg_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose logging enabled.")

    output_dir = args.output
    if not args.dry_run:
        try:
            create_output_directory(output_dir)
        except Exception as e:
            logging.critical(f"Exiting due to output directory error: {e}")
            sys.exit(1)
    else:
        logging.info("Dry run enabled. No files will be written to disk.")
        if not os.path.exists(output_dir):
            logging.warning(f"Output directory '{output_dir}' does not exist, but will not be created due to dry-run.")

    current_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    anonymizer = Anonymizer()

    total_files = 0
    total_lines_processed = 0

    try:
        if args.file:
            input_filepath = args.file
            base_filename = os.path.basename(input_filepath)
            output_filepath = os.path.join(output_dir, f"anonymized_{base_filename}")
            
            if not args.dry_run:
                lines = process_single_file(input_filepath, output_filepath, anonymizer)
                total_files += 1
                total_lines_processed += lines
            else:
                logging.info(f"DRY RUN: Would process file '{input_filepath}'.")
                # Simulate processing for dry run to collect mapping
                with open(input_filepath, 'r', encoding='utf-8', errors='ignore') as infile:
                    for line_num, line in enumerate(infile, 1):
                        anonymizer.process_line(line) # Still run processing to build mapping
                        total_lines_processed += 1
                total_files += 1
                logging.info(f"DRY RUN: Detected PII from {total_lines_processed} lines in '{input_filepath}'.")

        elif args.directory:
            input_dir = args.directory
            if not args.dry_run:
                files_processed = process_files_in_directory(input_dir, output_dir, anonymizer)
                total_files += files_processed
                # For directory processing, getting exact line count without re-reading files is complex.
                # We can update total_lines_processed inside process_single_file or estimate.
                # For now, let's keep it simple and just count lines when doing single file.
                # For directories, we'll indicate lines processed per file.
            else:
                logging.info(f"DRY RUN: Would process files in directory '{input_dir}'.")
                
                if not os.path.isdir(input_dir):
                    logging.error(f"DRY RUN: Input directory not found: {input_dir}")
                    sys.exit(1)

                for filename in os.listdir(input_dir):
                    if filename.endswith(('.log', '.txt', '.access', '.error')):
                        input_filepath = os.path.join(input_dir, filename)
                        if os.path.isfile(input_filepath):
                            logging.info(f"DRY RUN: Would process file '{input_filepath}'.")
                            with open(input_filepath, 'r', encoding='utf-8', errors='ignore') as infile:
                                lines_in_file = 0
                                for line in infile:
                                    anonymizer.process_line(line) # Build mapping even in dry run
                                    lines_in_file += 1
                                total_lines_processed += lines_in_file
                            total_files += 1
                            logging.info(f"DRY RUN: Detected PII from {lines_in_file} lines in '{input_filepath}'.")
                        else:
                            logging.debug(f"DRY RUN: Skipping non-file entry: {input_filepath}")
        
        logging.info("--- Anonymization Summary ---")
        logging.info(f"Total files processed: {total_files}")
        logging.info(f"Total lines processed (approx, if dry run/dir): {total_lines_processed}")
        logging.info(f"Total PII replacements made: {anonymizer.total_replacements}")

        if not args.dry_run:
            anonymizer.save_mapping_to_file(output_dir, current_timestamp)
        else:
            logging.info("Dry run complete. No output files were written. PII mapping was generated internally.")
            # For dry runs, we can still optionally save the mapping to show what *would* have been mapped.
            anonymizer.save_mapping_to_file(output_dir, f"DRY_RUN_{current_timestamp}")
            logging.info(f"Dry run PII mapping saved to '{os.path.join(output_dir, f'pii_mapping_DRY_RUN_{current_timestamp}.txt')}' for review.")

        logging.info("Log anonymization script finished successfully.")

    except Exception as e:
        logging.critical(f"Script terminated due to a critical error: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()