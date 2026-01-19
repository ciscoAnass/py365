import os
import sqlite3
import logging
import tempfile
import shutil
import sys
import time
from datetime import datetime

# --- Configuration Section ---
# This section defines various parameters for the database schema migration tester.
# In a real CI/CD environment, many of these settings would typically be sourced
# from environment variables, command-line arguments, or a dedicated configuration
# file (e.g., YAML, TOML) for better flexibility and separation of concerns.

class Config:
    """
    Configuration settings for the Database Schema Migration Tester.
    Encapsulates all tunable parameters, making it easy to manage and modify
    the behavior of the testing tool without altering the core logic.
    """
    
    # --- Logging Parameters ---
    LOG_LEVEL = logging.INFO  # Minimum level for console output. DEBUG, INFO, WARNING, ERROR, CRITICAL.
    LOG_FILE = "migration_tester.log"  # Path to the log file for persistent logging.
    
    # --- Database Configuration ---
    # For demonstration purposes, we utilize a temporary SQLite database.
    # This choice simplifies the script by avoiding external dependencies like Docker
    # for a database server (e.g., PostgreSQL, MySQL). However, the architecture
    # is designed to be extensible to other database types.
    DB_TYPE = "sqlite"  # Supported: "sqlite". Future expansion: "postgresql", "mysql".
    DB_NAME_PREFIX = "temp_migration_db_"  # Prefix for temporary database files/directories.
    
    # --- Migration Script Paths ---
    # These paths are relative to the script's execution directory.
    # In a typical project, these would point to actual migration scripts
    # located within a 'migrations' directory. For this script, dummy files
    # will be generated to ensure it's fully self-contained and runnable.
    MIGRATION_DIR = "migrations_test_scripts"
    MIGRATION_UP_FILE = "001_initial_schema.up.sql"    # Script to apply the new schema.
    MIGRATION_DOWN_FILE = "001_initial_schema.down.sql" # Script to reverse the schema changes.
    
    # --- Operation Timeouts ---
    DB_OPERATION_TIMEOUT_SECONDS = 30  # Maximum time to wait for a database connection or query.
    
    # --- Schema Verification Expectations ---
    # This dictionary defines the expected state of the database schema at
    # different stages of the migration process. It's a simplified representation
    # for illustrative purposes. In a real-world scenario, this could be
    # generated from a schema definition language, database introspection,
    # or a dedicated schema comparison tool.
    
    # Expected schema after applying the 'UP' migration.
    EXPECTED_SCHEMA_AFTER_UP = {
        "tables": {
            "users": ["id", "username", "email", "created_at"],
            "products": ["id", "name", "price"]
        },
        "views": [],    # Placeholder for future view verification.
        "indexes": []   # Placeholder for future index verification.
    }
    
    # Expected schema after applying the 'DOWN' (reverse) migration.
    # This typically implies a reversion to a previous state, often an empty schema.
    EXPECTED_SCHEMA_AFTER_DOWN = {
        "tables": {},   # Expecting all tables created by UP migration to be dropped.
        "views": [],
        "indexes": []
    }
    
    # Flag to enable or disable schema verification steps.
    ENABLE_SCHEMA_VERIFICATION = True
    
    # --- Placeholder for Advanced Database Configuration (e.g., Docker) ---
    # If using external database systems like PostgreSQL or MySQL in a CI pipeline,
    # you would typically spin up temporary instances using Docker.
    # DOCKER_IMAGE = "postgres:13-alpine"
    # DOCKER_PORT_MAPPING = "5432:5432"
    # DOCKER_ENV_VARS = ["POSTGRES_DB=testdb", "POSTGRES_USER=testuser", "POSTGRES_PASSWORD=testpass"]
    # DOCKER_CONTAINER_NAME = "migration-test-db-container"

# Instantiate the configuration object, making settings accessible throughout the script.
config = Config()

# --- Logging Setup ---
# A robust and informative logging mechanism is crucial for CI/CD tools,
# providing clear feedback on the execution status, success, and any failures.

class CustomFormatter(logging.Formatter):
    """
    A custom log formatter that enhances readability of console output by
    applying ANSI escape codes for colored text based on the log level.
    This makes it easier to quickly identify important messages (errors, warnings).
    """
    # ANSI color codes
    GREY = "\x1b[38;20m"
    BLUE = "\x1b[34;20m"
    YELLOW = "\x1b[33;20m"
    RED = "\x1b[31;20m"
    BOLD_RED = "\x1b[31;1m"
    GREEN = "\x1b[32;20m"
    RESET = "\x1b[0m" # Resets color to default

    # Define format strings for each logging level, incorporating color codes.
    FORMATS = {
        logging.DEBUG: GREY + "%(asctime)s - %(name)s - %(levelname)s - %(message)s" + RESET,
        logging.INFO: GREEN + "%(asctime)s - %(name)s - %(levelname)s - %(message)s" + RESET,
        logging.WARNING: YELLOW + "%(asctime)s - %(name)s - %(levelname)s - %(message)s" + RESET,
        logging.ERROR: RED + "%(asctime)s - %(name)s - %(levelname)s - %(message)s" + RESET,
        logging.CRITICAL: BOLD_RED + "%(asctime)s - %(name)s - %(levelname)s - %(message)s" + RESET
    }

    def format(self, record):
        """
        Overrides the default format method to apply custom formatting based
        on the log record's level.
        """
        # Retrieve the appropriate format string for the current log level.
        log_fmt = self.FORMATS.get(record.levelno)
        # Create a new Formatter instance with the level-specific format.
        formatter = logging.Formatter(log_fmt, datefmt='%Y-%m-%d %H:%M:%S')
        # Format the record.
        return formatter.format(record)

def setup_logging():
    """
    Configures a comprehensive logging system for the application.
    It sets up two handlers:
    1. A file handler that logs all messages (DEBUG level and above) to a file.
    2. A console handler that logs INFO level messages and above to standard output,
       using the custom colored formatter for better visibility.
    """
    # Get or create a logger instance for the MigrationTester.
    logger_instance = logging.getLogger("MigrationTester")
    logger_instance.setLevel(config.LOG_LEVEL) # Set the base logging level.

    # Prevent adding duplicate handlers if setup_logging is called multiple times.
    if not logger_instance.handlers:
        # File Handler: Logs all details to a file.
        file_handler = logging.FileHandler(config.LOG_FILE, mode='a', encoding='utf-8')
        file_handler.setLevel(logging.DEBUG) # File captures everything for detailed debugging.
        file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        file_handler.setFormatter(file_formatter)
        logger_instance.addHandler(file_handler)

        # Console Handler: Logs important messages to the console with colors.
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO) # Console typically shows INFO and above.
        console_formatter = CustomFormatter()
        console_handler.setFormatter(console_formatter)
        logger_instance.addHandler(console_handler)

    logger_instance.info("Logging system initialized successfully.")
    return logger_instance

# Global logger instance, accessible throughout the script.
logger = setup_logging()

# --- Utility Functions ---

def read_sql_script(filepath):
    """
    Reads the entire content of an SQL script file.
    This function is critical for loading migration definitions.
    
    Args:
        filepath (str): The full path to the SQL script file.
        
    Returns:
        str: The complete content of the SQL script as a single string.
        
    Raises:
        FileNotFoundError: If the specified file does not exist.
        IOError: For other issues encountered during file reading (e.g., permissions).
    """
    try:
        logger.debug(f"Attempting to read SQL script from: '{filepath}'")
        with open(filepath, 'r', encoding='utf-8') as f:
            script_content = f.read()
        logger.debug(f"Successfully read SQL script from '{filepath}'. Content length: {len(script_content)} characters.")
        return script_content
    except FileNotFoundError:
        logger.error(f"SQL script file NOT FOUND: '{filepath}'. Please ensure the path is correct.")
        raise
    except IOError as e:
        logger.error(f"An I/O error occurred while reading SQL script file '{filepath}': {e}")
        raise

def parse_sql_statements(sql_script_content):
    """
    Parses a given string containing SQL script content into individual SQL statements.
    Statements are typically delimited by semicolons. This basic parser handles
    splitting by semicolons and cleaning up whitespace.
    
    Note: For highly complex SQL (e.g., with semicolons inside stored procedures,
    triggers, or quoted strings), a more sophisticated SQL parser would be required.
    For typical DDL/DML migration scripts, this simple approach is usually sufficient.
    
    Args:
        sql_script_content (str): A string containing one or more SQL statements.
        
    Returns:
        list: A list of individual SQL statements, with leading/trailing whitespace removed.
              Empty statements resulting from the split are filtered out.
    """
    statements = []
    # Split the script by semicolons.
    raw_statements = sql_script_content.split(';')
    for stmt in raw_statements:
        clean_stmt = stmt.strip()
        if clean_stmt: # Only add non-empty statements to the list.
            statements.append(clean_stmt)
    logger.debug(f"Parsed {len(statements)} individual SQL statements from the script content.")
    return statements

def generate_dummy_migration_files(migration_dir, up_file, down_file):
    """
    Creates a temporary directory and generates dummy 'up' and 'down' SQL migration
    files. These files provide concrete examples for the migration tester to execute,
    making the script fully runnable out-of-the-box without requiring pre-existing
    migration scripts.
    
    Args:
        migration_dir (str): The name of the directory to create for migration files.
        up_file (str): The filename for the 'up' migration script.
        down_file (str): The filename for the 'down' migration script.
        
    Raises:
        IOError: If there are issues creating the directory or writing the files.
    """
    # Ensure the migration directory exists; create it if it doesn't.
    os.makedirs(migration_dir, exist_ok=True)
    
    up_filepath = os.path.join(migration_dir, up_file)
    down_filepath = os.path.join(migration_dir, down_file)
    
    # Define the content for the 'up' migration script.
    # This script creates two tables: 'users' and 'products'.
    up_script_content = """
    PRAGMA foreign_keys = ON; -- Enable foreign key support in SQLite

    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        price REAL NOT NULL,
        description TEXT
    );

    -- Optional: Insert some initial data
    INSERT INTO users (username, email) VALUES ('admin', 'admin@example.com');
    INSERT INTO users (username, email) VALUES ('john_doe', 'john.doe@example.com');
    INSERT INTO products (name, price, description) VALUES ('Laptop', 1200.50, 'High-performance laptop');
    INSERT INTO products (name, price, description) VALUES ('Mouse', 25.99, 'Wireless ergonomic mouse');
    """
    
    # Define the content for the 'down' (reverse) migration script.
    # This script drops the tables created by the 'up' migration.
    down_script_content = """
    PRAGMA foreign_keys = OFF; -- Disable foreign key support temporarily for dropping tables if needed

    DROP TABLE IF EXISTS products;
    DROP TABLE IF EXISTS users;
    """
    
    try:
        # Write the 'up' migration script content to its file.
        with open(up_filepath, 'w', encoding='utf-8') as f:
            f.write(up_script_content.strip())
        logger.info(f"Generated dummy UP migration script: '{up_filepath}'")

        # Write the 'down' migration script content to its file.
        with open(down_filepath, 'w', encoding='utf-8') as f:
            f.write(down_script_content.strip())
        logger.info(f"Generated dummy DOWN migration script: '{down_filepath}'")
            
    except IOError as e:
        logger.critical(f"Failed to generate dummy migration files. Check directory permissions or disk space: {e}")
        raise

# --- Database Management Layer ---

class DatabaseManager:
    """
    A core component responsible for all interactions with the database.
    This class handles connecting, disconnecting, executing SQL scripts,
    and performing schema introspection (e.g., getting table and column names).
    It abstracts database-specific details, making the main testing logic
    more generic and potentially reusable across different database types.
    """
    
    def __init__(self, db_type, db_path_or_conn_str, timeout_seconds=config.DB_OPERATION_TIMEOUT_SECONDS):
        """
        Initializes the DatabaseManager instance.
        
        Args:
            db_type (str): The type of the database (e.g., 'sqlite').
            db_path_or_conn_str (str): The file path for SQLite, or a connection string
                                       for other database types (e.g., "host=localhost dbname=testdb").
            timeout_seconds (int): Timeout duration for database connection attempts and queries.
        """
        self.db_type = db_type
        self.db_path_or_conn_str = db_path_or_conn_str
        self.connection = None # Stores the active database connection object.
        self.timeout_seconds = timeout_seconds
        logger.info(f"DatabaseManager initialized for DB type: '{self.db_type}', target: '{self.db_path_or_conn_str}'")

    def connect(self):
        """
        Establishes a connection to the specified database.
        This method includes specific logic for different database types.
        
        Raises:
            ValueError: If an unsupported database type is specified.
            sqlite3.Error: For any issues encountered during SQLite connection.
        """
        if self.connection:
            logger.debug("Database is already connected. Skipping reconnection.")
            return

        logger.info(f"Attempting to connect to {self.db_type} database...")
        
        if self.db_type == "sqlite":
            try:
                # For SQLite, connect to the database file.
                # `timeout` parameter specifies how long to wait for the database file to become unlocked.
                self.connection = sqlite3.connect(self.db_path_or_conn_str, timeout=self.timeout_seconds)
                # Set isolation_level to None for autocommit mode, which is often desired for DDL.
                # DDL statements in SQLite are often implicitly committed anyway, but this ensures it.
                self.connection.isolation_level = None
                logger.info(f"Successfully connected to SQLite database: '{self.db_path_or_conn_str}'")
            except sqlite3.Error as e:
                logger.critical(f"FAILED to connect to SQLite database '{self.db_path_or_conn_str}': {e}")
                raise
        # Example for extending to PostgreSQL (requires 'psycopg2' package):
        # elif self.db_type == "postgresql":
        #     try:
        #         import psycopg2
        #         self.connection = psycopg2.connect(self.db_path_or_conn_str, connect_timeout=self.timeout_seconds)
        #         self.connection.autocommit = True # Similar to SQLite's isolation_level = None for DDL
        #         logger.info(f"Successfully connected to PostgreSQL database.")
        #     except ImportError:
        #         logger.critical("psycopg2 not installed. Please install it for PostgreSQL support: pip install psycopg2-binary")
        #         raise
        #     except psycopg2.Error as e:
        #         logger.critical(f"FAILED to connect to PostgreSQL database: {e}")
        #         raise
        else:
            logger.critical(f"Unsupported database type specified: '{self.db_type}'. Connection failed.")
            raise ValueError(f"Unsupported database type: {self.db_type}")

    def disconnect(self):
        """
        Closes the active database connection if one exists.
        Important for releasing resources, especially for file-based databases
        like SQLite or when managing connection pools.
        """
        if self.connection:
            self.connection.close()
            self.connection = None
            logger.info(f"Disconnected from database: '{self.db_path_or_conn_str}'")
        else:
            logger.debug("No active database connection to close.")

    def execute_script(self, script_content, script_name="anonymous_script"):
        """
        Executes a sequence of SQL statements provided as a single string.
        Each statement is executed individually within a transaction (if not autocommit).
        
        Args:
            script_content (str): The complete SQL script content.
            script_name (str): A descriptive name for the script (used in logging).
            
        Returns:
            bool: True if all statements were executed successfully, False otherwise.
        """
        if not self.connection:
            logger.error(f"Cannot execute script '{script_name}': No active database connection established.")
            return False

        statements = parse_sql_statements(script_content)
        if not statements:
            logger.warning(f"No executable SQL statements found in '{script_name}' script. Skipping execution.")
            return True # Consider it successful if there's nothing to do.

        logger.info(f"Executing SQL script '{script_name}' with {len(statements)} statements...")
        
        try:
            cursor = self.connection.cursor()
            for i, statement in enumerate(statements):
                # Log a snippet of the statement for debugging, avoiding excessively long log lines.
                logger.debug(f"[{script_name}] Executing statement {i+1}/{len(statements)}: {statement[:120]}{'...' if len(statement) > 120 else ''}")
                cursor.execute(statement)
            
            # Explicitly commit if not in autocommit mode.
            if self.connection.isolation_level is not None:
                self.connection.commit()
            
            logger.info(f"Successfully executed all statements in script '{script_name}'.")
            return True
        except sqlite3.Error as e:
            # Rollback on error if not in autocommit mode.
            if self.connection.isolation_level is not None:
                self.connection.rollback()
            logger.error(f"DATABASE ERROR executing statement in script '{script_name}': {e}. Failed statement: '{statement}'")
            return False
        except Exception as e:
            # Catch any other unexpected exceptions.
            if self.connection.isolation_level is not None:
                self.connection.rollback()
            logger.error(f"AN UNEXPECTED ERROR occurred during script '{script_name}' execution: {e}", exc_info=True)
            return False

    def get_table_names(self):
        """
        Introspects the database to retrieve a list of all user-defined table names.
        This is a key function for schema verification.
        
        Returns:
            list: A list of strings, where each string is the name of a table.
                  Returns an empty list if no connection or if the DB type is unsupported for introspection.
        """
        if not self.connection:
            logger.warning("Cannot retrieve table names: No active database connection.")
            return []
        
        if self.db_type == "sqlite":
            cursor = self.connection.cursor()
            # Query sqlite_master table to get user-defined tables, excluding internal SQLite tables.
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
            tables = [row[0] for row in cursor.fetchall()]
            logger.debug(f"Discovered {len(tables)} tables in SQLite DB: {tables}")
            return tables
        # Example for PostgreSQL:
        # elif self.db_type == "postgresql":
        #     cursor = self.connection.cursor()
        #     cursor.execute("SELECT tablename FROM pg_tables WHERE schemaname = 'public';")
        #     tables = [row[0] for row in cursor.fetchall()]
        #     logger.debug(f"Discovered {len(tables)} tables in PostgreSQL DB: {tables}")
        #     return tables
        else:
            logger.warning(f"Schema introspection for tables not implemented for DB type: '{self.db_type}'")
            return []

    def get_table_columns(self, table_name):
        """
        Introspects the database to retrieve a list of column names for a specific table.
        Another critical function for detailed schema verification.
        
        Args:
            table_name (str): The name of the table to inspect.
            
        Returns:
            list: A list of strings, where each string is a column name for the specified table.
                  Returns an empty list if the table is not found, no connection, or DB type is unsupported.
        """
        if not self.connection:
            logger.warning("Cannot retrieve table columns: No active database connection.")
            return []
            
        if self.db_type == "sqlite":
            cursor = self.connection.cursor()
            try:
                # `PRAGMA table_info()` is a SQLite-specific way to get table schema.
                cursor.execute(f"PRAGMA table_info({table_name});")
                # The column name is the second element (index 1) in each row returned by PRAGMA.
                columns = [row[1] for row in cursor.fetchall()]
                logger.debug(f"Table '{table_name}' has {len(columns)} columns: {columns}")
                return columns
            except sqlite3.Error as e:
                logger.warning(f"Could not retrieve columns for table '{table_name}'. It might not exist or an error occurred: {e}")
                return []
        # Example for PostgreSQL:
        # elif self.db_type == "postgresql":
        #     cursor = self.connection.cursor()
        #     cursor.execute(f"SELECT column_name FROM information_schema.columns WHERE table_schema = 'public' AND table_name = '{table_name}';")
        #     columns = [row[0] for row in cursor.fetchall()]
        #     logger.debug(f"Table '{table_name}' has {len(columns)} columns: {columns}")
        #     return columns
        else:
            logger.warning(f"Schema introspection for columns not implemented for DB type: '{self.db_type}'")
            return []

# --- Migration Testing Core Logic ---

class MigrationTester:
    """
    The central orchestrator of the migration testing process.
    This class manages the lifecycle of the test, from setting up a temporary
    database to applying migrations, verifying schema changes, and cleaning up.
    It encapsulates the workflow of a DevOps schema migration testing tool.
    """
    
    def __init__(self, config_obj):
        """
        Initializes the MigrationTester.
        
        Args:
            config_obj (Config): An instance of the configuration object.
        """
        self.config = config_obj
        self.db_manager = None       # Will hold an instance of DatabaseManager.
        self.temp_db_path = None     # Path to the temporary SQLite database file.
        # Construct full paths to migration scripts.
        self.migration_up_filepath = os.path.join(self.config.MIGRATION_DIR, self.config.MIGRATION_UP_FILE)
        self.migration_down_filepath = os.path.join(self.config.MIGRATION_DIR, self.config.MIGRATION_DOWN_FILE)
        logger.info("MigrationTester component initialized and ready.")

    def _create_temp_db_environment(self):
        """
        Sets up the temporary database environment.
        For SQLite, this involves creating a unique temporary directory and a database file within it.
        For other DB types (e.g., PostgreSQL, MySQL), this method would typically
        invoke `docker run` commands to start a database container.
        """
        logger.info(f"Initiating temporary database environment creation for DB type: '{self.config.DB_TYPE}'...")
        
        if self.config.DB_TYPE == "sqlite":
            # Create a unique temporary directory. This is safer than a direct file in `/tmp`
            # and allows for better cleanup if the script crashes.
            temp_dir = tempfile.mkdtemp(prefix=self.config.DB_NAME_PREFIX)
            self.temp_db_path = os.path.join(temp_dir, "migration_test.db")
            logger.info(f"Temporary SQLite database will be created at: '{self.temp_db_path}'")
            
            self.db_manager = DatabaseManager(self.config.DB_TYPE, self.temp_db_path)
            self.db_manager.connect() # Establish the connection to the new database.
        # Placeholder for Docker-based database setup:
        # elif self.config.DB_TYPE in ["postgresql", "mysql"]:
        #     logger.info(f"Spinning up Docker container for {self.config.DB_TYPE}...")
        #     # Example using subprocess to execute Docker commands:
        #     # subprocess.run(["docker", "run", "--name", config.DOCKER_CONTAINER_NAME, "-p", config.DOCKER_PORT_MAPPING, "-e", ..., config.DOCKER_IMAGE], check=True)
        #     # time.sleep(10) # Wait for DB to start up
        #     # self.db_manager = DatabaseManager(self.config.DB_TYPE, self._get_docker_db_connection_string())
        #     # self.db_manager.connect()
        else:
            logger.critical(f"Unsupported database type '{self.config.DB_TYPE}' specified for temporary environment creation. Cannot proceed.")
            raise ValueError(f"Unsupported DB type for setup: {self.config.DB_TYPE}")

    def _cleanup_temp_db_environment(self):
        """
        Cleans up the temporary database environment.
        For SQLite, this means closing the connection and deleting the temporary database file
        along with its containing directory.
        For Docker, this would involve stopping and removing the database container.
        """
        logger.info("Initiating cleanup of temporary database environment...")
        
        if self.db_manager:
            self.db_manager.disconnect()
            self.db_manager = None # Dereference the manager to aid garbage collection.

        if self.config.DB_TYPE == "sqlite" and self.temp_db_path:
            db_dir = os.path.dirname(self.temp_db_path)
            if os.path.exists(db_dir):
                try:
                    # Recursively remove the temporary directory and all its contents.
                    shutil.rmtree(db_dir)
                    logger.info(f"Successfully cleaned up temporary SQLite database directory: '{db_dir}'")
                except OSError as e:
                    logger.error(f"Error removing temporary database directory '{db_dir}': {e}. Manual cleanup might be required.")
            self.temp_db_path = None # Clear the path reference.
        # Placeholder for Docker container cleanup:
        # elif self.config.DB_TYPE in ["postgresql", "mysql"]:
        #     logger.info(f"Stopping and removing Docker container for {self.config.DB_TYPE}...")
        #     # subprocess.run(["docker", "stop", config.DOCKER_CONTAINER_NAME], check=True)
        #     # subprocess.run(["docker", "rm", config.DOCKER_CONTAINER_NAME], check=True)
        #     logger.info("Docker database container removed.")

    def _verify_schema(self, expected_schema, stage_name="unknown"):
        """
        Compares the current live database schema against a predefined expected schema.
        This function performs checks for:
        1. Presence/absence of expected tables.
        2. Presence/absence of expected columns within those tables.
        
        Args:
            expected_schema (dict): A dictionary defining the expected schema structure
                                    (e.g., {"tables": {"users": ["id", "name"]}}).
            stage_name (str): A descriptive name for the current verification stage (e.g., 'after UP').
            
        Returns:
            bool: True if the current schema matches the expected schema, False otherwise.
        """
        if not self.config.ENABLE_SCHEMA_VERIFICATION:
            logger.warning(f"Schema verification is explicitly disabled in configuration. Skipping for stage: '{stage_name}'")
            return True # If disabled, always pass this step.

        logger.info(f"Initiating schema verification for stage: '{stage_name}'...")
        
        # Retrieve current table names from the database.
        current_tables = set(self.db_manager.get_table_names())
        # Extract expected table names from the configuration.
        expected_tables = set(expected_schema.get("tables", {}).keys())
        
        # Check for tables that are expected but not found.
        missing_tables = expected_tables - current_tables
        # Check for tables that exist but were not expected.
        extra_tables = current_tables - expected_tables

        overall_schema_match = True # Flag to track overall verification success.

        if missing_tables:
            logger.error(f"SCHEMA MISMATCH (FAIL) for stage '{stage_name}': The following EXPECTED tables are MISSING: {', '.join(missing_tables)}")
            overall_schema_match = False
        if extra_tables:
            logger.warning(f"SCHEMA WARNING for stage '{stage_name}': The following UNEXPECTED tables were FOUND: {', '.join(extra_tables)}")
            # Depending on strictness, extra tables could be a failure. For this tool, it's a warning.

        # Now, verify columns for all tables that are expected and actually exist.
        for table_name in expected_tables:
            if table_name in current_tables:
                expected_columns = set(expected_schema["tables"][table_name])
                current_columns = set(self.db_manager.get_table_columns(table_name))
                
                missing_columns = expected_columns - current_columns
                extra_columns = current_columns - expected_columns
                
                if missing_columns:
                    logger.error(f"SCHEMA MISMATCH (FAIL) for stage '{stage_name}', table '{table_name}': MISSING expected columns: {', '.join(missing_columns)}")
                    overall_schema_match = False
                if extra_columns:
                    logger.warning(f"SCHEMA WARNING for stage '{stage_name}', table '{table_name}': FOUND unexpected columns: {', '.join(extra_columns)}")
            elif table_name not in current_tables:
                # This case is already covered by missing_tables, but good for explicit logging.
                logger.debug(f"Skipping column check for '{table_name}' as it was already identified as missing.")

        if overall_schema_match:
            logger.info(f"Schema verification PASSED for stage '{stage_name}'. Database schema matches expectations.")
            return True
        else:
            logger.error(f"Schema verification FAILED for stage '{stage_name}'. Please review the detailed logs above for discrepancies.")
            return False

    def run_full_test_cycle(self):
        """
        Executes the complete migration test cycle, which includes:
        1. Setting up a temporary database instance.
        2. Applying the 'up' migration script.
        3. Verifying the database schema after the 'up' migration.
        4. Applying the 'down' (reverse) migration script.
        5. Verifying the database schema after the 'down' migration.
        6. Cleaning up the temporary database environment.
        
        This method is the primary entry point for initiating the testing process.
        
        Returns:
            bool: True if the entire test cycle completes successfully (all migrations
                  applied and verified as expected), False otherwise.
        """
        logger.info("\n=== Starting DATABASE SCHEMA MIGRATION TEST CYCLE ===\n")
        test_start_time = time.monotonic() # Record start time for duration calculation.
        
        overall_test_success = True # Flag to track the outcome of the entire test.
        
        try:
            # --- Step 1: Create Temporary Database Environment ---
            logger.info("\n--- STEP 1/6: Setting up temporary database environment ---\n")
            self._create_temp_db_environment()
            if not self.db_manager or not self.db_manager.connection:
                logger.critical("FAILED to set up temporary database environment. Aborting migration test cycle.")
                return False # Critical failure, cannot proceed.
            
            # --- Step 1.5 (Optional but Recommended): Verify Initial Empty/Baseline Schema ---
            # This step ensures that the temporary database truly starts from an expected state
            # (e.g., completely empty), preventing false positives or negatives from pre-existing data/schema.
            logger.info("\n--- STEP 1.5/6: Verifying initial (empty) database schema ---\n")
            initial_schema_ok = self._verify_schema(config.EXPECTED_SCHEMA_AFTER_DOWN, "initial_empty_state")
            if not initial_schema_ok and config.ENABLE_SCHEMA_VERIFICATION:
                logger.warning("Initial database schema verification failed. This might indicate an issue with the temporary database setup, but continuing with migration testing.")
                # Deciding whether to fail here depends on strictness. For now, it's a warning.

            # --- Step 2: Apply 'UP' Migration Script ---
            logger.info("\n--- STEP 2/6: Applying 'UP' migration script ---\n")
            up_script_content = read_sql_script(self.migration_up_filepath)
            if not self.db_manager.execute_script(up_script_content, "UP_MIGRATION"):
                logger.critical("FAILED to apply UP migration. This indicates a problem with the new schema script itself. Aborting further steps.")
                overall_test_success = False
                return overall_test_success # Critical failure.

            # --- Step 3: Verify Schema After 'UP' Migration ---
            logger.info("\n--- STEP 3/6: Verifying schema AFTER 'UP' migration ---\n")
            if not self._verify_schema(self.config.EXPECTED_SCHEMA_AFTER_UP, "after_UP_migration"):
                logger.error("Schema verification FAILED after UP migration. The 'up' script did not result in the expected schema.")
                overall_test_success = False
                # We continue to the DOWN migration test even if UP verification fails,
                # as ensuring the DOWN script works (for rollback) is a primary goal.
            else:
                logger.info("Schema verification PASSED after UP migration. The 'up' script successfully applied the expected schema.")

            # --- Step 4: Apply 'DOWN' (Reverse) Migration Script ---
            logger.info("\n--- STEP 4/6: Applying 'DOWN' (reverse) migration script ---\n")
            down_script_content = read_sql_script(self.migration_down_filepath)
            if not self.db_manager.execute_script(down_script_content, "DOWN_MIGRATION"):
                logger.critical("FAILED to apply DOWN migration. This is CRITICAL! A production rollback using this script would likely FAIL.")
                overall_test_success = False
                # This is a highly critical failure as it prevents successful rollback.
                # However, we still want to proceed to schema verification of the down state to log what happened.

            # --- Step 5: Verify Schema After 'DOWN' Migration ---
            logger.info("\n--- STEP 5/6: Verifying schema AFTER 'DOWN' (reverse) migration ---\n")
            if not self._verify_schema(self.config.EXPECTED_SCHEMA_AFTER_DOWN, "after_DOWN_migration"):
                logger.error("Schema verification FAILED after DOWN migration. The 'down' script did NOT revert to the expected state. Rollback integrity issue detected.")
                overall_test_success = False
            else:
                logger.info("Schema verification PASSED after DOWN migration. The 'down' script successfully reverted the schema.")
                
        except (FileNotFoundError, IOError, ValueError, sqlite3.Error, Exception) as e:
            # Catch any unexpected errors that might occur during the test cycle.
            logger.critical(f"AN UNHANDLED CRITICAL ERROR occurred during the migration test cycle: {e}", exc_info=True)
            overall_test_success = False
        finally:
            # --- Step 6: Cleanup Temporary Database Environment ---
            logger.info("\n--- STEP 6/6: Cleaning up temporary database environment ---\n")
            try:
                self._cleanup_temp_db_environment()
            except Exception as e:
                logger.error(f"AN ERROR occurred during cleanup of the temporary database environment: {e}. This might leave residual files/containers.")
                # Cleanup errors typically don't change the overall test pass/fail status,
                # but are important to log as they indicate environment issues.

        test_end_time = time.monotonic()
        duration = test_end_time - test_start_time
        
        if overall_test_success:
            logger.info(f"\n=== Migration test cycle COMPLETED SUCCESSFULLY in {duration:.2f} seconds. All migrations (UP and DOWN) passed verification. ===\n")
        else:
            logger.critical(f"\n=== Migration test cycle FAILED after {duration:.2f} seconds. Review the logs above for detailed failure reasons. ===\n")
            
        return overall_test_success

# --- Main Execution Block ---

def main():
    """
    The main entry point of the script. This function orchestrates the
    overall execution flow:
    1. Sets up dummy migration files for demonstration.
    2. Instantiates and runs the MigrationTester.
    3. Cleans up the dummy migration files and directory.
    4. Exits with an appropriate status code (0 for success, 1 for failure).
    """
    logger.info("Database Schema Migration Tester application started.")
    
    # --- 0. Prepare: Generate dummy migration files for testing ---
    logger.info("\n--- Preparing dummy migration files for the test ---\n")
    try:
        generate_dummy_migration_files(config.MIGRATION_DIR, config.MIGRATION_UP_FILE, config.MIGRATION_DOWN_FILE)
    except Exception as e:
        logger.critical(f"FATAL: Failed to generate dummy migration files. Cannot proceed with testing: {e}")
        sys.exit(1) # Exit with an error code if setup fails.

    # --- 1. Execute: Initialize and run the MigrationTester ---
    tester = MigrationTester(config)
    test_passed = tester.run_full_test_cycle()
    
    # --- 2. Post-test Cleanup: Remove dummy migration files and directory ---
    logger.info("\n--- Cleaning up dummy migration script directory ---\n")
    if os.path.exists(config.MIGRATION_DIR):
        try:
            shutil.rmtree(config.MIGRATION_DIR)
            logger.info(f"Successfully removed dummy migration directory: '{config.MIGRATION_DIR}'")
        except OSError as e:
            logger.error(f"ERROR removing dummy migration directory '{config.MIGRATION_DIR}': {e}. Manual intervention may be needed.")
            
    # --- 3. Final Report and Exit ---
    if test_passed:
        logger.info("The database schema migration test suite finished successfully.")
        sys.exit(0) # Standard exit code for success.
    else:
        logger.error("The database schema migration test suite encountered failures.")
        sys.exit(1) # Standard exit code for general error.

# Ensure the `main` function is called when the script is executed directly.
if __name__ == "__main__":
    main()