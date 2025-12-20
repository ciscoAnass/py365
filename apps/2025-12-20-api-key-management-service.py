# Standard library imports
import os
import secrets
import hashlib
import sqlite3
import datetime
import uuid
import json
import time

# Third-party library imports (strictly necessary for secure hashing and web API)
# To run this script, you will need to install Flask and bcrypt:
# pip install Flask bcrypt
from flask import Flask, request, jsonify, g

# --- Configuration Section ---
# This section defines various configuration parameters for the API Key Management Service.
# These parameters can be externalized to a separate configuration file (e.g., config.ini, .env)
# in a more robust production environment. For simplicity, they are defined directly here.

# Database configuration
DATABASE_NAME = "api_key_management.db"
# The absolute path where the SQLite database file will be stored.
# Using os.path.abspath ensures that the script locates the database
# relative to its own execution directory, making it portable.
DATABASE_PATH = os.path.abspath(DATABASE_NAME)

# API Key generation configuration
API_KEY_LENGTH = 32  # Defines the length of the generated cryptographic key in bytes.
# A 32-byte key (256 bits) is generally considered very secure.
# When base64 encoded (which `secrets.token_urlsafe` does), it will result in approximately
# (32 * 4 / 3) = 42-44 characters, providing a long and complex key string.

# Bcrypt hashing configuration
# Bcrypt is a deliberately slow, adaptive password-hashing function designed to make
# brute-force attacks computationally expensive. It automatically handles salting.
# The 'rounds' parameter (also known as the work factor or cost factor) determines
# the computational difficulty. A higher number of rounds increases security but also
# increases the time required to hash and verify keys.
BCRYPT_ROUNDS = 12  # A recommended value. Adjust based on server performance,
                    # security requirements, and how fast hardware evolves.
                    # Higher values are better if performance allows.

# Admin API Configuration
# For this demonstration, a simple static API key is used for administrative access.
# In a real-world production system, this should be replaced with a more robust
# authentication mechanism, such as OAuth 2.0, JWT, or certificate-based authentication.
ADMIN_API_KEY = "SUPER_SECRET_ADMIN_KEY_DO_NOT_USE_IN_PROD" # !!! CHANGE THIS FOR PRODUCTION !!!

# Default rate limiting rules for newly generated keys if no specific rules are provided.
# This ensures that every new key has some form of rate limiting applied by default.
DEFAULT_MAX_REQUESTS = 1000 # The maximum number of requests allowed within the period.
DEFAULT_PERIOD_SECONDS = 3600 # The time window in seconds (e.g., 3600 seconds = 1 hour).
                                # So, 1000 requests per hour by default.

# --- Database Manager Class ---
# This class is a foundational component responsible for all direct interactions
# with the SQLite database. It encapsulates database connection management,
# schema creation, and generic query execution, making the rest of the application
# logic cleaner and database-agnostic to some extent.
class DatabaseManager:
    """
    Manages all database operations for the API Key Management Service.
    It handles:
    - Initializing the database schema (creating tables if they don't exist).
    - Providing and managing database connections (especially within a Flask request context).
    - Executing SQL queries with parameter binding for security.
    - Error handling for database operations.
    """
    def __init__(self, db_path):
        """
        Initializes the DatabaseManager.
        Connects to the specified SQLite database file and ensures the schema is set up.

        Args:
            db_path (str): The absolute file path to the SQLite database file.
        """
        self.db_path = db_path
        self._initialize_database() # Set up tables when the manager is instantiated.

    def _initialize_database(self):
        """
        Connects to the database directly (outside of a Flask request context)
        to create necessary tables if they do not already exist.
        This ensures the database schema is prepared before the application starts serving requests.
        """
        # A direct connection is used here because Flask's `g` object (used for per-request
        # connections) is not available during application startup/initialization.
        conn = self._get_connection_direct()
        cursor = conn.cursor()
        print(f"[{datetime.datetime.now()}] Initializing database schema at {self.db_path}...")

        # SQL DDL (Data Definition Language) to create the 'api_keys' table.
        # This table stores the core metadata and the securely hashed version of each API key.
        # - `id`: Primary key for internal database referencing.
        # - `key_id`: A public, unique UUID string that identifies the key without revealing the secret.
        # - `hashed_key`: The bcrypt-hashed secret API key string. This is never the plain key.
        # - `service_name`: The application or microservice this key belongs to.
        # - `description`: A human-readable description of the key's purpose.
        # - `owner`: Contact information for the key's owner.
        # - `created_at`: Timestamp of key creation.
        # - `last_used_at`: Timestamp of the last successful validation/usage.
        # - `is_active`: A boolean flag (1 for active, 0 for inactive/revoked).
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_id TEXT UNIQUE NOT NULL,
                hashed_key TEXT NOT NULL,
                service_name TEXT NOT NULL,
                description TEXT,
                owner TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_used_at DATETIME,
                is_active BOOLEAN DEFAULT 1
            )
        """)
        print(f"[{datetime.datetime.now()}] 'api_keys' table checked/created.")

        # SQL DDL to create the 'key_usage' table.
        # This table logs every recorded API call, providing data for analytics and rate limiting.
        # - `id`: Primary key for internal database referencing.
        # - `key_id`: Foreign key referencing `api_keys.key_id`, linking usage to a specific key.
        # - `endpoint`: The specific API endpoint accessed (e.g., "/data/fetch", "/user/profile").
        # - `timestamp`: The exact time the API call was made.
        # `ON DELETE CASCADE` ensures that if an API key is deleted, all its associated usage records are also deleted.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS key_usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_id TEXT NOT NULL,
                endpoint TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (key_id) REFERENCES api_keys(key_id) ON DELETE CASCADE
            )
        """)
        print(f"[{datetime.datetime.now()}] 'key_usage' table checked/created.")

        # SQL DDL to create the 'rate_limits' table.
        # This table stores the specific rate limiting rules for each API key.
        # - `id`: Primary key.
        # - `key_id`: Unique foreign key to `api_keys.key_id`, meaning each key can only have one rate limit rule.
        # - `max_requests`: The maximum number of requests allowed within the defined period.
        # - `period_seconds`: The duration of the time window for the rate limit, in seconds.
        # `ON DELETE CASCADE` ensures that if an API key is deleted, its associated rate limit rule is also deleted.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS rate_limits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_id TEXT UNIQUE NOT NULL,
                max_requests INTEGER NOT NULL,
                period_seconds INTEGER NOT NULL,
                FOREIGN KEY (key_id) REFERENCES api_keys(key_id) ON DELETE CASCADE
            )
        """)
        print(f"[{datetime.datetime.now()}] 'rate_limits' table checked/created.")

        # Commit all pending changes to make the table creations permanent.
        conn.commit()
        # Close the direct connection to release resources.
        conn.close()
        print(f"[{datetime.datetime.now()}] Database schema initialization complete.")

    def _get_connection_direct(self):
        """
        Establishes and returns a new, direct connection to the SQLite database.
        This method is primarily for internal use during application initialization
        or in contexts where Flask's `g` object is not available.

        Returns:
            sqlite3.Connection: A new SQLite database connection object.
        """
        return sqlite3.connect(self.db_path)

    def get_connection(self):
        """
        Retrieves a database connection. It cleverly reuses an existing connection
        stored in Flask's `g` object if one is already open for the current request.
        If no connection exists in `g`, a new one is created and stored.
        This pattern ensures that each web request uses a single, consistent database connection,
        which is efficient and prevents potential issues with multiple connections.

        Returns:
            sqlite3.Connection: The SQLite database connection object for the current request.
        """
        # `g` is a special proxy object provided by Flask that is unique for each request.
        # It's an ideal place to store resources that need to be accessed throughout a request.
        if 'db_conn' not in g:
            g.db_conn = sqlite3.connect(self.db_path)
            # Setting `row_factory` to `sqlite3.Row` makes database rows behave like dictionaries.
            # This allows accessing columns by name (e.g., `row['column_name']`) instead of
            # by index (e.g., `row[0]`), which improves code readability.
            g.db_conn.row_factory = sqlite3.Row
        return g.db_conn

    def close_connection(self, exception=None):
        """
        Closes the database connection associated with the current request, if one exists.
        This function is designed to be registered as a `teardown_appcontext` callback in Flask,
        meaning it will be automatically called after each request completes,
        regardless of whether it succeeded or failed, ensuring proper resource cleanup.

        Args:
            exception (Exception, optional): An exception object if the request processing
                                             resulted in an error. Flask passes this. Defaults to None.
        """
        # `g.pop('db_conn', None)` safely retrieves the connection from `g` and removes it.
        # If 'db_conn' doesn't exist, it returns None, preventing errors.
        conn = g.pop('db_conn', None)
        if conn is not None:
            conn.close()
            # print(f"[{datetime.datetime.now()}] Database connection closed.") # Uncomment for verbose logging

    def execute_query(self, query, params=(), fetchone=False, fetchall=False, commit=False):
        """
        Executes a SQL query, optionally fetching results and committing changes.
        This method is a centralized point for all database interactions (SELECT, INSERT, UPDATE, DELETE).

        Args:
            query (str): The SQL query string to be executed.
            params (tuple): A tuple of parameters to bind to the query. This prevents SQL injection.
            fetchone (bool): If True, only the first matching row is fetched and returned.
            fetchall (bool): If True, all matching rows are fetched and returned as a list.
            commit (bool): If True, the transaction is committed immediately after execution.
                           Necessary for INSERT, UPDATE, DELETE operations.

        Returns:
            list or dict or None: Returns a list of `sqlite3.Row` objects (acting like dicts) for `fetchall=True`,
                                  a single `sqlite3.Row` object for `fetchone=True`, or None for DDL/DML
                                  statements that do not return results.
        Raises:
            sqlite3.Error: Re-raises any SQLite database errors after logging and rolling back.
        """
        conn = self.get_connection() # Get the request-local connection.
        cursor = conn.cursor()
        try:
            cursor.execute(query, params) # Execute the query with bound parameters.
            if commit:
                conn.commit() # Commit changes if requested (e.g., for data modification).
            if fetchone:
                return cursor.fetchone() # Return a single row.
            if fetchall:
                return cursor.fetchall() # Return all rows.
            return None # For DDL/DML statements that don't inherently return data.
        except sqlite3.Error as e:
            conn.rollback() # Rollback the transaction on error to maintain data integrity.
            print(f"[{datetime.datetime.now()}] Database Error: {e} - Query: {query} with params: {params}")
            raise # Re-raise the exception so the caller can handle it (e.g., return a 500 error).

# --- API Key Manager Class ---
# This class contains the core business logic for handling API keys,
# including their secure generation, storage, retrieval, and status management.
class APIKeyManager:
    """
    Manages the lifecycle of API keys within the service.
    Key responsibilities include:
    - Securely generating new API keys.
    - Hashing keys using bcrypt for storage (never storing plain keys).
    - Verifying presented plain keys against stored hashes.
    - Retrieving key details by either public `key_id` or the plain API key itself.
    - Revoking or activating keys to control their usability.
    - Listing all managed API keys for administrative purposes.
    """
    def __init__(self, db_manager):
        """
        Initializes the APIKeyManager.

        Args:
            db_manager (DatabaseManager): An instance of the DatabaseManager
                                         to interact with the persistent storage.
        """
        self.db = db_manager
        # Attempt to import `bcrypt`. This is a crucial third-party library for secure hashing.
        # If bcrypt is not found, a less secure fallback (SHA-256) is used with a warning.
        try:
            import bcrypt
            self._bcrypt = bcrypt
            print(f"[{datetime.datetime.now()}] bcrypt library loaded successfully for secure key hashing.")
        except ImportError:
            self._bcrypt = None
            print(f"[{datetime.datetime.now()}] WARNING: 'bcrypt' not found. Key hashing will use a simpler (less secure) SHA-256 method for demonstration.")
            print(f"[{datetime.datetime.now()}] Please install 'bcrypt' with 'pip install bcrypt' for production environments.")
            print(f"[{datetime.datetime.now()}] This is NOT recommended for production use of API Key Management.")

    def _generate_secret_key(self, length=API_KEY_LENGTH):
        """
        Generates a cryptographically strong, random API key string.
        Uses Python's `secrets` module, which is designed for generating
        randomness suitable for security-sensitive applications.

        Args:
            length (int): The number of random bytes to generate.
                          Defaults to `API_KEY_LENGTH` from configuration.

        Returns:
            str: A URL-safe base64 encoded string representing the API key.
                 This format is convenient for use in URLs or headers.
        """
        return secrets.token_urlsafe(length)

    def _hash_key(self, plain_key):
        """
        Hashes a plain-text API key for secure storage.
        Prioritizes bcrypt for strong, salt-enabled, adaptive hashing.
        Falls back to SHA-256 if bcrypt is unavailable (with a warning).

        Args:
            plain_key (str): The plain-text API key string to be hashed.

        Returns:
            str: The hashed API key. For bcrypt, it's a UTF-8 string encoding the hash.
                 For SHA-256 fallback, it's a hexadecimal string.
        Raises:
            RuntimeError: If bcrypt is unavailable and a secure hashing method is deemed
                          absolutely mandatory (though this demo continues with a warning).
        """
        if self._bcrypt:
            # `bcrypt.gensalt()` generates a new random salt for each hash.
            # The `rounds` parameter controls the computational cost.
            # `bcrypt.hashpw()` performs the actual hashing.
            hashed = self._bcrypt.hashpw(plain_key.encode('utf-8'), self._bcrypt.gensalt(rounds=BCRYPT_ROUNDS))
            return hashed.decode('utf-8') # Store the bcrypt hash as a UTF-8 string in the database.
        else:
            # Fallback to SHA-256. This is a one-way hash, but it lacks the
            # adaptive difficulty and inherent salting of bcrypt, making it
            # less resistant to brute-force attacks on long-term stored hashes.
            print(f"[{datetime.datetime.now()}] WARNING: Using SHA-256 fallback for hashing due to missing bcrypt. NOT SECURE FOR PRODUCTION!")
            return hashlib.sha256(plain_key.encode('utf-8')).hexdigest()

    def _verify_key(self, plain_key, hashed_key):
        """
        Verifies a provided plain-text API key against a stored hashed key.
        Uses bcrypt's `checkpw` function if available, which safely handles
        salt extraction and comparison in a timing-attack resistant manner.
        Falls back to SHA-256 comparison if bcrypt is not available.

        Args:
            plain_key (str): The plain-text API key provided by a client for validation.
            hashed_key (str): The hashed key retrieved from the database.

        Returns:
            bool: True if the `plain_key` matches the `hashed_key`, False otherwise.
        """
        if self._bcrypt:
            try:
                # `bcrypt.checkpw()` safely compares the plain key with the hash.
                # It handles the decoding, salting, hashing, and timing-safe comparison.
                return self._bcrypt.checkpw(plain_key.encode('utf-8'), hashed_key.encode('utf-8'))
            except ValueError:
                # This can happen if the `hashed_key` retrieved from the DB is not a valid
                # bcrypt hash format (e.g., corrupted, or an old hash from a different algorithm).
                print(f"[{datetime.datetime.now()}] Verification failed for key: Malformed bcrypt hash or invalid format.")
                return False
        else:
            # Fallback verification for SHA-256. Simple hash comparison.
            return hashlib.sha256(plain_key.encode('utf-8')).hexdigest() == hashed_key

    def generate_api_key(self, service_name, description=None, owner=None, initial_rate_limit=None):
        """
        Generates a new API key, securely hashes it, and stores its metadata in the database.
        Also initializes rate limiting rules for the newly generated key.

        Args:
            service_name (str): A required name identifying the microservice or application
                                 that will use this API key.
            description (str, optional): An optional, human-readable description of the key's purpose.
            owner (str, optional): Optional contact information for the person or team responsible for the key.
            initial_rate_limit (dict, optional): A dictionary specifying the initial rate limit rules.
                                                 Expected format: `{'max_requests': int, 'period_seconds': int}`.
                                                 If None, default rate limits will be applied.

        Returns:
            tuple: A tuple containing two elements:
                   1. (str) The plain-text generated API key (this is returned ONLY ONCE).
                   2. (dict) A dictionary containing the stored details of the new key (excluding the hash).
                   Returns `(None, None)` if the key generation or storage fails.
        """
        try:
            plain_key = self._generate_secret_key() # Generate the actual secret key.
            hashed_key = self._hash_key(plain_key)  # Hash it for secure storage.
            key_id = str(uuid.uuid4())              # Generate a unique public ID for this key.

            # Insert the new API key's details into the 'api_keys' table.
            query_insert_key = """
                INSERT INTO api_keys (key_id, hashed_key, service_name, description, owner)
                VALUES (?, ?, ?, ?, ?)
            """
            params_insert_key = (key_id, hashed_key, service_name, description, owner)
            self.db.execute_query(query_insert_key, params_insert_key, commit=True)

            # Determine the rate limit to apply for this new key.
            if initial_rate_limit:
                max_req = initial_rate_limit.get('max_requests', DEFAULT_MAX_REQUESTS)
                period_sec = initial_rate_limit.get('period_seconds', DEFAULT_PERIOD_SECONDS)
            else:
                max_req = DEFAULT_MAX_REQUESTS
                period_sec = DEFAULT_PERIOD_SECONDS
            
            # Insert the rate limit rule into the 'rate_limits' table.
            query_insert_rate_limit = "INSERT INTO rate_limits (key_id, max_requests, period_seconds) VALUES (?, ?, ?)"
            params_insert_rate_limit = (key_id, max_req, period_sec)
            self.db.execute_query(query_insert_rate_limit, params_insert_rate_limit, commit=True)

            # Prepare the response details. Note: the plain_key is returned separately.
            key_details = {
                "key_id": key_id,
                "service_name": service_name,
                "description": description,
                "owner": owner,
                "created_at": str(datetime.datetime.now()), # Using current time as an approximation for the response.
                "is_active": True,
                "rate_limit": {"max_requests": max_req, "period_seconds": period_sec}
            }

            print(f"[{datetime.datetime.now()}] Generated new key for service '{service_name}' with key_id '{key_id}'.")
            return plain_key, key_details

        except Exception as e:
            # Log any exceptions during key generation/storage.
            print(f"[{datetime.datetime.now()}] Error generating API key: {e}")
            return None, None

    def get_key_details(self, key_id, include_hash=False):
        """
        Retrieves all stored details for a specific API key using its public `key_id`.

        Args:
            key_id (str): The unique public identifier of the API key.
            include_hash (bool): If True, the `hashed_key` will be included in the returned details.
                                 This should typically be False for security reasons, used only
                                 in very specific, trusted administrative contexts.

        Returns:
            dict or None: A dictionary containing the key's attributes (e.g., service_name, owner,
                          active status, rate limits), or None if no key with the given `key_id` is found.
        """
        # Fetch the base key data from the 'api_keys' table.
        query_key_data = "SELECT * FROM api_keys WHERE key_id = ?"
        key_data = self.db.execute_query(query_key_data, (key_id,), fetchone=True)
        
        if key_data:
            key_details = dict(key_data) # Convert the Row object to a dictionary.
            if not include_hash:
                key_details.pop('hashed_key', None) # Remove the sensitive hashed key unless explicitly requested.
            
            # Fetch the associated rate limit rule for this key.
            query_rate_limit = "SELECT max_requests, period_seconds FROM rate_limits WHERE key_id = ?"
            rate_limit_data = self.db.execute_query(query_rate_limit, (key_id,), fetchone=True)
            if rate_limit_data:
                key_details['rate_limit'] = dict(rate_limit_data)
            else:
                key_details['rate_limit'] = None # Indicate no specific rate limit is defined.

            return key_details
        return None

    def get_key_details_by_plain_key(self, plain_key):
        """
        Validates a plain-text API key provided by a microservice and retrieves its full details.
        This is the primary method used for API key authentication by other services.
        It first searches for a matching hashed key among all active keys.

        Args:
            plain_key (str): The plain-text API key submitted by a client.

        Returns:
            dict or None: A dictionary containing the key's details (excluding its hash) if
                          the key is valid and active, otherwise None.
        """
        # To prevent timing attacks, we fetch all active hashed keys and iterate to verify.
        # This makes the verification time relatively consistent regardless of the key's position.
        # This approach is suitable for bcrypt due to its inherent slowness.
        query_active_keys = "SELECT key_id, hashed_key, is_active FROM api_keys WHERE is_active = 1"
        all_active_keys = self.db.execute_query(query_active_keys, fetchall=True)

        matched_key_id = None
        if all_active_keys:
            for key_data in all_active_keys:
                # Attempt to verify the plain key against each stored hash.
                if self._verify_key(plain_key, key_data['hashed_key']):
                    matched_key_id = key_data['key_id']
                    break # A match is found, no need to check further.

        if matched_key_id:
            # If a match is found, retrieve the full details for the authenticated key.
            key_details = self.get_key_details(matched_key_id, include_hash=False)
            
            # A final check for `is_active` in case of race conditions or data inconsistencies.
            if key_details and key_details.get('is_active'):
                # Update the `last_used_at` timestamp for the successfully validated key.
                query_update_last_used = "UPDATE api_keys SET last_used_at = ? WHERE key_id = ?"
                self.db.execute_query(query_update_last_used, (datetime.datetime.now(), matched_key_id), commit=True)
                return key_details
        return None # No matching, active key found.

    def revoke_key(self, key_id):
        """
        Revokes an API key by setting its `is_active` status to False.
        A revoked key can no longer be used for authentication.

        Args:
            key_id (str): The public identifier of the API key to revoke.

        Returns:
            bool: True if the key was successfully revoked, False otherwise (e.g., key not found).
        """
        query = "UPDATE api_keys SET is_active = 0 WHERE key_id = ?"
        try:
            # Execute the update and commit the change.
            self.db.execute_query(query, (key_id,), commit=True)
            # Check if any row was actually affected to confirm the key existed.
            # (sqlite3.Cursor.rowcount is not directly available from execute_query,
            # would need a slight modification to get it if strict validation is needed here).
            # For simplicity, we assume successful execution means key was found.
            print(f"[{datetime.datetime.now()}] Key '{key_id}' revoked successfully.")
            return True
        except Exception as e:
            print(f"[{datetime.datetime.now()}] Error revoking key '{key_id}': {e}")
            return False

    def activate_key(self, key_id):
        """
        Reactivates a previously revoked API key by setting its `is_active` status to True.

        Args:
            key_id (str): The public identifier of the API key to activate.

        Returns:
            bool: True if the key was successfully activated, False otherwise.
        """
        query = "UPDATE api_keys SET is_active = 1 WHERE key_id = ?"
        try:
            self.db.execute_query(query, (key_id,), commit=True)
            print(f"[{datetime.datetime.now()}] Key '{key_id}' activated successfully.")
            return True
        except Exception as e:
            print(f"[{datetime.datetime.now()}] Error activating key '{key_id}': {e}")
            return False

    def list_all_keys(self, include_inactive=False):
        """
        Retrieves a list of all API keys managed by the service.

        Args:
            include_inactive (bool): If True, keys marked as inactive (revoked) will also be included.
                                     If False (default), only active keys are returned.

        Returns:
            list: A list of dictionaries, where each dictionary represents an API key's details
                  (excluding its hashed secret).
        """
        # Construct the query based on whether inactive keys should be included.
        if include_inactive:
            query = "SELECT key_id, service_name, description, owner, created_at, last_used_at, is_active FROM api_keys"
            params = ()
        else:
            query = "SELECT key_id, service_name, description, owner, created_at, last_used_at, is_active FROM api_keys WHERE is_active = 1"
            params = ()

        all_keys_data = self.db.execute_query(query, params, fetchall=True)
        
        # Process each key row to include its rate limit details.
        keys_list = []
        if all_keys_data:
            for key_row in all_keys_data:
                key_details = dict(key_row) # Convert Row object to dict.
                # Fetch rate limit for each key.
                query_rate_limit = "SELECT max_requests, period_seconds FROM rate_limits WHERE key_id = ?"
                rate_limit_data = self.db.execute_query(query_rate_limit, (key_details['key_id'],), fetchone=True)
                if rate_limit_data:
                    key_details['rate_limit'] = dict(rate_limit_data)
                else:
                    key_details['rate_limit'] = None # No specific rate limit found.
                keys_list.append(key_details)
        return keys_list

# --- Usage Tracker Class ---
# This class is dedicated to recording and querying API key usage.
# It acts as a data source for rate limiting and provides usage analytics.
class UsageTracker:
    """
    Manages the tracking of API key usage.
    It logs each instance an API key is used, along with the endpoint accessed.
    This data is essential for both auditing and enforcing rate limits.
    """
    def __init__(self, db_manager):
        """
        Initializes the UsageTracker.

        Args:
            db_manager (DatabaseManager): An instance of the DatabaseManager
                                         for database interactions.
        """
        self.db = db_manager

    def record_usage(self, key_id, endpoint, timestamp=None):
        """
        Records a single usage event for a given API key and endpoint.

        Args:
            key_id (str): The public identifier of the API key that was used.
            endpoint (str): The specific API endpoint or resource accessed by the key.
            timestamp (datetime, optional): The exact time of the usage event. Defaults to `datetime.datetime.now()`.

        Returns:
            bool: True if the usage was recorded successfully, False otherwise.
        """
        if timestamp is None:
            timestamp = datetime.datetime.now() # Use current time if not explicitly provided.

        query = "INSERT INTO key_usage (key_id, endpoint, timestamp) VALUES (?, ?, ?)"
        try:
            self.db.execute_query(query, (key_id, endpoint, timestamp), commit=True)
            # print(f"[{datetime.datetime.now()}] Usage recorded for key '{key_id}' at endpoint '{endpoint}'.") # Uncomment for verbose logging
            return True
        except Exception as e:
            print(f"[{datetime.datetime.now()}] Error recording usage for key '{key_id}' at endpoint '{endpoint}': {e}")
            return False

    def get_usage_counts(self, key_id, since_datetime=None):
        """
        Retrieves the total number of usage events for a specific API key,
        optionally filtered to count only events occurring after a given timestamp.
        This is primarily used by the RateLimiter to count requests within a time window.

        Args:
            key_id (str): The public identifier of the API key.
            since_datetime (datetime, optional): If provided, only usage events
                                                on or after this time will be counted.

        Returns:
            int: The total count of usage events matching the criteria.
        """
        query = "SELECT COUNT(*) FROM key_usage WHERE key_id = ?"
        params = [key_id]

        if since_datetime:
            query += " AND timestamp >= ?" # Add time filter if specified.
            params.append(since_datetime)
        
        result = self.db.execute_query(query, tuple(params), fetchone=True)
        # The COUNT(*) query returns a single row with one column. `result[0]` accesses that count.
        return result[0] if result else 0

# --- Rate Limiter Class ---
# This class implements the logic for enforcing rate limits based on
# predefined rules and the usage data collected by the `UsageTracker`.
class RateLimiter:
    """
    Implements and enforces rate limiting rules for API keys.
    It retrieves rate limit configurations, checks current usage against those limits,
    and calculates remaining requests and reset times.
    """
    def __init__(self, db_manager, usage_tracker):
        """
        Initializes the RateLimiter.

        Args:
            db_manager (DatabaseManager): An instance of the DatabaseManager.
            usage_tracker (UsageTracker): An instance of the UsageTracker to query usage data.
        """
        self.db = db_manager
        self.usage_tracker = usage_tracker

    def set_rate_limit(self, key_id, max_requests, period_seconds):
        """
        Sets or updates the rate limiting rules for a specific API key.
        This operation uses an UPSERT (UPDATE or INSERT) strategy: if a rule
        for the `key_id` already exists, it's updated; otherwise, a new one is inserted.

        Args:
            key_id (str): The public identifier of the API key.
            max_requests (int): The maximum number of requests allowed within the `period_seconds`.
            period_seconds (int): The duration of the rate limit window in seconds.

        Returns:
            bool: True if the rate limit was successfully set or updated, False otherwise.
        """
        # SQLite's `ON CONFLICT` clause provides an efficient way to perform an UPSERT.
        # If a row with the given `key_id` already exists (due to `key_id` being UNIQUE),
        # it updates `max_requests` and `period_seconds`. Otherwise, it inserts a new row.
        query = """
            INSERT INTO rate_limits (key_id, max_requests, period_seconds)
            VALUES (?, ?, ?)
            ON CONFLICT(key_id) DO UPDATE SET
                max_requests = excluded.max_requests,
                period_seconds = excluded.period_seconds
        """
        try:
            self.db.execute_query(query, (key_id, max_requests, period_seconds), commit=True)
            print(f"[{datetime.datetime.now()}] Rate limit for key '{key_id}' set to {max_requests} requests per {period_seconds} seconds.")
            return True
        except Exception as e:
            print(f"[{datetime.datetime.now()}] Error setting rate limit for key '{key_id}': {e}")
            return False

    def get_rate_limit(self, key_id):
        """
        Retrieves the rate limit configuration for a specific API key.

        Args:
            key_id (str): The public identifier of the API key.

        Returns:
            dict or None: A dictionary containing 'max_requests' and 'period_seconds' for the key,
                          or None if no specific rate limit rule is defined for that key.
        """
        query = "SELECT max_requests, period_seconds FROM rate_limits WHERE key_id = ?"
        result = self.db.execute_query(query, (key_id,), fetchone=True)
        return dict(result) if result else None

    def check_rate_limit(self, key_id):
        """
        Checks if a given API key is currently within its defined rate limits.
        This function determines if an incoming request should be allowed or denied.

        Args:
            key_id (str): The public identifier of the API key to check.

        Returns:
            tuple: A tuple where:
                   - The first element (bool) is True if the request is allowed, False otherwise.
                   - The second element (dict) is a status dictionary containing:
                     'allowed', 'remaining', 'reset_in' (seconds), 'limit', and 'period'.
        """
        rate_limit = self.get_rate_limit(key_id)
        
        # If no explicit rate limit rule is found for the key, it's implicitly allowed.
        # In a real-world scenario, you might want to apply a stricter global default here.
        if not rate_limit:
            print(f"[{datetime.datetime.now()}] No explicit rate limit found for key '{key_id}'. Allowing by default.")
            return True, {"allowed": True, "remaining": "N/A", "reset_in": "N/A", "limit": "N/A", "period": "N/A"}

        max_requests = rate_limit['max_requests']
        period_seconds = rate_limit['period_seconds']

        # Determine the start time of the sliding window for rate limiting.
        current_time = datetime.datetime.now()
        since_time = current_time - datetime.timedelta(seconds=period_seconds)

        # Get the count of requests made by this key within the current sliding window.
        requests_in_period = self.usage_tracker.get_usage_counts(key_id, since_time)

        # Determine if the current request is allowed.
        allowed = requests_in_period < max_requests
        # Calculate remaining requests.
        remaining = max(0, max_requests - requests_in_period)
        
        reset_in = period_seconds # Default reset_in for a sliding window.

        # If the rate limit is exceeded, we calculate a more precise `reset_in` time.
        # This is the time until the oldest request in the current window "expires" and a slot frees up.
        if not allowed:
            # Find the timestamp of the oldest request that is still within the current window.
            query_oldest_request = """
                SELECT timestamp FROM key_usage
                WHERE key_id = ? AND timestamp >= ?
                ORDER BY timestamp ASC LIMIT 1
            """
            oldest_request_data = self.db.execute_query(query_oldest_request, (key_id, since_time), fetchone=True)
            
            if oldest_request_data and oldest_request_data['timestamp']:
                # Parse the timestamp string from the database.
                oldest_ts_str = oldest_request_data['timestamp']
                # The format needs to match exactly what SQLite stores (DATETIME DEFAULT CURRENT_TIMESTAMP)
                # which is typically "YYYY-MM-DD HH:MM:SS.mmmmmm".
                oldest_ts = datetime.datetime.strptime(oldest_ts_str, "%Y-%m-%d %H:%M:%S.%f")
                
                # The reset point is when this oldest request (which is currently counted)
                # falls out of the `period_seconds` window.
                reset_timestamp = oldest_ts + datetime.timedelta(seconds=period_seconds)
                time_difference = reset_timestamp - current_time
                reset_in = max(0, int(time_difference.total_seconds())) # Ensure it's non-negative.

        # Construct the status dictionary for the response.
        status = {
            "allowed": allowed,
            "remaining": remaining,
            "reset_in": reset_in, # Time in seconds until a slot becomes available.
            "limit": max_requests,
            "period": period_seconds
        }
        
        if not allowed:
            print(f"[{datetime.datetime.now()}] Rate limit exceeded for key '{key_id}'. {requests_in_period}/{max_requests} requests in {period_seconds}s. Resets in {reset_in}s.")
        # else:
            # print(f"[{datetime.datetime.now()}] Key '{key_id}' is within rate limits. {remaining}/{max_requests} remaining.") # Uncomment for verbose logging

        return allowed, status

# --- Flask Application Setup ---
# Initialize the Flask web application instance.
app = Flask(__name__)

# Initialize the core manager classes, injecting dependencies.
# This ensures that each manager has access to the database and other necessary components.
db_manager = DatabaseManager(DATABASE_PATH)
api_key_manager = APIKeyManager(db_manager)
usage_tracker = UsageTracker(db_manager)
rate_limiter = RateLimiter(db_manager, usage_tracker)

# Register a function to close the database connection after each request.
# This is crucial for resource management in web applications.
app.teardown_appcontext(db_manager.close_connection)

# --- Helper Functions for API Authentication/Authorization ---
# These functions act as decorators to simplify endpoint protection and authentication logic.

def require_admin_key(f):
    """
    Decorator function to enforce administrator authentication for specific endpoints.
    It checks for a valid `ADMIN_API_KEY` in the `X-Admin-API-Key` HTTP header.
    If the key is missing or invalid, it returns an unauthorized (401) response.
    """
    def decorated_function(*args, **kwargs):
        admin_key = request.headers.get('X-Admin-API-Key')
        if not admin_key or admin_key != ADMIN_API_KEY:
            return jsonify({"error": "Unauthorized: Invalid or missing admin API key"}), 401
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__ # Preserve original function name for Flask.
    return decorated_function

def authenticate_api_key(f):
    """
    Decorator function to authenticate a microservice's API key.
    It expects the API key in the `X-API-Key` HTTP header.
    If the key is valid and active, it stores its details in Flask's `g` object
    for easy access by the decorated view function. Otherwise, it returns 401.
    """
    def decorated_function(*args, **kwargs):
        plain_key = request.headers.get('X-API-Key')
        if not plain_key:
            return jsonify({"error": "Unauthorized: API key required in 'X-API-Key' header"}), 401

        key_details = api_key_manager.get_key_details_by_plain_key(plain_key)
        if not key_details:
            return jsonify({"error": "Unauthorized: Invalid or inactive API key"}), 401
        
        # Store the authenticated key's details in `g` for downstream use in the request.
        g.authenticated_key = key_details
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# --- API Endpoints ---
# This section defines the various HTTP API routes and their corresponding handlers.

@app.route('/')
def home():
    """
    Root endpoint for a basic health check and service status.
    Returns general information about the API Key Management Service.
    """
    return jsonify({"service": "API Key Management Service", "status": "running", "version": "1.0"})


# --- Admin Endpoints (Require ADMIN_API_KEY) ---
# These endpoints are intended for managing API keys by administrators and require
# the `X-Admin-API-Key` header for authentication.

@app.route('/admin/generate_key', methods=['POST'])
@require_admin_key
def admin_generate_key():
    """
    Admin endpoint to generate a new API key.
    Request Body (JSON):
    - `service_name` (str, required): Name of the microservice.
    - `description` (str, optional): Purpose of the key.
    - `owner` (str, optional): Contact for the key.
    - `rate_limit` (dict, optional): Custom rate limit, e.g., `{"max_requests": 500, "period_seconds": 60}`.

    Returns the generated plain API key (once) and its details.
    """
    data = request.get_json()
    if not data or 'service_name' not in data:
        return jsonify({"error": "Missing 'service_name' in request body."}), 400

    service_name = data['service_name']
    description = data.get('description')
    owner = data.get('owner')
    rate_limit_config = data.get('rate_limit')

    plain_key, key_details = api_key_manager.generate_api_key(
        service_name=service_name,
        description=description,
        owner=owner,
        initial_rate_limit=rate_limit_config
    )

    if plain_key and key_details:
        # IMPORTANT: The plain_key is highly sensitive and should only be returned ONCE
        # at the time of generation. It is not stored in plain-text and cannot be retrieved later.
        response = {
            "message": "API key generated successfully. Store this key securely, it will not be shown again.",
            "api_key": plain_key,
            "key_details": key_details
        }
        return jsonify(response), 201 # 201 Created status.
    else:
        return jsonify({"error": "Failed to generate API key due to an internal error."}), 500

@app.route('/admin/revoke_key/<string:key_id>', methods=['POST'])
@require_admin_key
def admin_revoke_key(key_id):
    """
    Admin endpoint to revoke an existing API key.
    The key will be marked as inactive and can no longer be used for authentication.
    """
    if api_key_manager.revoke_key(key_id):
        return jsonify({"message": f"API key '{key_id}' revoked successfully."}), 200
    else:
        # Check if the key existed at all to provide a more specific error.
        if api_key_manager.get_key_details(key_id) is None:
            return jsonify({"error": f"API key '{key_id}' not found."}), 404
        return jsonify({"error": f"Failed to revoke API key '{key_id}' due to an internal error."}), 500

@app.route('/admin/activate_key/<string:key_id>', methods=['POST'])
@require_admin_key
def admin_activate_key(key_id):
    """
    Admin endpoint to activate a previously revoked API key.
    The key will be marked as active and can resume being used for authentication.
    """
    if api_key_manager.activate_key(key_id):
        return jsonify({"message": f"API key '{key_id}' activated successfully."}), 200
    else:
        # Check if the key existed at all to provide a more specific error.
        if api_key_manager.get_key_details(key_id) is None:
            return jsonify({"error": f"API key '{key_id}' not found."}), 404
        return jsonify({"error": f"Failed to activate API key '{key_id}' due to an internal error."}), 500

@app.route('/admin/list_keys', methods=['GET'])
@require_admin_key
def admin_list_keys():
    """
    Admin endpoint to retrieve a list of all API keys managed by the service.
    Query Parameters:
    - `include_inactive` (boolean, optional): If 'true', includes revoked (inactive) keys in the list.
                                              Defaults to 'false'.
    """
    # Parse the `include_inactive` query parameter.
    include_inactive = request.args.get('include_inactive', 'false').lower() == 'true'
    keys = api_key_manager.list_all_keys(include_inactive=include_inactive)
    return jsonify(keys), 200

@app.route('/admin/get_key_details/<string:key_id>', methods=['GET'])
@require_admin_key
def admin_get_key_details(key_id):
    """
    Admin endpoint to get detailed information about a specific API key using its public `key_id`.
    """
    key_details = api_key_manager.get_key_details(key_id)
    if key_details:
        return jsonify(key_details), 200
    else:
        return jsonify({"error": f"API key '{key_id}' not found."}), 404

@app.route('/admin/set_rate_limit/<string:key_id>', methods=['POST'])
@require_admin_key
def admin_set_rate_limit(key_id):
    """
    Admin endpoint to set or update the rate limit rules for a specific API key.
    Request Body (JSON):
    - `max_requests` (int, required): Maximum number of requests allowed.
    - `period_seconds` (int, required): Time window in seconds.
    """
    data = request.get_json()
    if not data or 'max_requests' not in data or 'period_seconds' not in data:
        return jsonify({"error": "Missing 'max_requests' or 'period_seconds' in request body."}), 400

    max_requests = data['max_requests']
    period_seconds = data['period_seconds']

    # Validate input types and values.
    if not isinstance(max_requests, int) or not isinstance(period_seconds, int) or max_requests <= 0 or period_seconds <= 0:
        return jsonify({"error": "max_requests and period_seconds must be positive integers."}), 400

    # Ensure the `key_id` refers to an existing API key before setting its rate limit.
    existing_key = api_key_manager.get_key_details(key_id)
    if not existing_key:
        return jsonify({"error": f"API key '{key_id}' not found. Cannot set rate limit."}), 404

    if rate_limiter.set_rate_limit(key_id, max_requests, period_seconds):
        return jsonify({
            "message": f"Rate limit for key '{key_id}' updated successfully.",
            "rate_limit": {"max_requests": max_requests, "period_seconds": period_seconds}
        }), 200
    else:
        return jsonify({"error": f"Failed to set rate limit for API key '{key_id}' due to an internal error."}), 500


# --- Microservice Endpoints (Require X-API-Key header) ---
# These endpoints are designed for consumption by other microservices, requiring
# their individual API keys for authentication, provided in the `X-API-Key` header.

@app.route('/validate_key', methods=['GET'])
@authenticate_api_key
def validate_key():
    """
    Endpoint for microservices to validate their API key.
    If the key is valid and active, it returns the key's details.
    Authentication is handled by the `@authenticate_api_key` decorator.
    """
    key_details = g.authenticated_key # Key details are automatically populated by the decorator.
    response = {
        "message": "API key is valid and active.",
        "key_details": key_details
    }
    return jsonify(response), 200

@app.route('/track_usage', methods=['POST'])
@authenticate_api_key
def track_usage():
    """
    Endpoint for microservices to explicitly report an API usage event.
    This can be used to track specific actions that don't directly fall under
    a rate-limited "request" (e.g., specific internal events).
    Request Body (JSON):
    - `endpoint` (str, optional): The specific endpoint or resource that was used. Defaults to 'unknown'.
    """
    key_id = g.authenticated_key['key_id'] # Get the authenticated key_id from `g`.
    data = request.get_json()
    endpoint = data.get('endpoint', 'unknown') # Default to 'unknown' if not provided.

    if usage_tracker.record_usage(key_id, endpoint):
        return jsonify({"message": "Usage recorded successfully."}), 200
    else:
        return jsonify({"error": "Failed to record usage due to an internal error."}), 500

@app.route('/check_rate_limit', methods=['GET'])
@authenticate_api_key
def check_rate_limit():
    """
    Endpoint for microservices to proactively check their current rate limit status
    without consuming a request. This helps clients adjust their behavior.
    """
    key_id = g.authenticated_key['key_id']
    
    # The `check_rate_limit` function returns (allowed_status_bool, status_details_dict).
    allowed, status = rate_limiter.check_rate_limit(key_id)
    
    response = {
        "message": "Rate limit status retrieved.",
        "status": status
    }
    
    if allowed:
        return jsonify(response), 200
    else:
        # If the key is currently rate-limited, return a 429 Too Many Requests status.
        return jsonify(response), 429

@app.route('/consume_request', methods=['POST'])
@authenticate_api_key
def consume_request():
    """
    Endpoint for microservices to register a request that counts towards their rate limit.
    This endpoint first checks the rate limit and, if allowed, records the usage.
    Request Body (JSON):
    - `endpoint` (str, optional): The specific endpoint or resource being accessed. Defaults to 'unknown'.
    """
    key_id = g.authenticated_key['key_id']
    data = request.get_json()
    endpoint = data.get('endpoint', 'unknown')

    # Step 1: Check if the request is within the rate limits.
    allowed, status = rate_limiter.check_rate_limit(key_id)
    if not allowed:
        # If rate limit is exceeded, return 429 immediately.
        return jsonify({
            "message": "Rate limit exceeded for this API key. Please try again later.",
            "rate_limit_status": status # Provide current status details.
        }), 429 # HTTP 429 Too Many Requests

    # Step 2: If allowed, record the usage of this request.
    if not usage_tracker.record_usage(key_id, endpoint):
        # This is an unusual error, as rate limit check passed but usage record failed.
        # It could indicate a database issue.
        return jsonify({"error": "Failed to record usage after passing rate limit check. Internal service error."}), 500

    # Step 3: All checks passed. Return success with the updated rate limit status.
    # Re-check the rate limit to reflect this just-consumed request in the `remaining` count.
    # This is important for immediate feedback to the client on their actual remaining requests.
    _, updated_status = rate_limiter.check_rate_limit(key_id)

    return jsonify({
        "message": "Request consumed and usage tracked successfully.",
        "key_details": {
            "key_id": g.authenticated_key['key_id'],
            "service_name": g.authenticated_key['service_name']
        },
        "rate_limit_status": updated_status # Provide updated status after consumption.
    }), 200

# --- Main execution block ---
# This block ensures that the Flask application is run only when the script is executed directly.
if __name__ == '__main__':
    # A crucial check: ensure the `bcrypt` library is installed for production security.
    try:
        import bcrypt
    except ImportError:
        print("\n" + "="*80)
        print("!!! WARNING: 'bcrypt' library not found. Key hashing will be INSECURE. !!!")
        print("!!! Please install it for production use: pip install bcrypt         !!!")
        print("!!! This service is running with reduced security.                   !!!")
        print("="*80 + "\n")
        # The APIKeyManager will handle the fallback, so we don't exit here for the demo.
        pass

    # Log service startup details and configuration.
    print(f"[{datetime.datetime.now()}] Starting API Key Management Service...")
    print(f"[{datetime.datetime.now()}] Database path: {DATABASE_PATH}")
    print(f"[{datetime.datetime.now()}] Admin API Key: {ADMIN_API_KEY} (!!! CHANGE THIS FOR PRODUCTION !!!)")
    print(f"[{datetime.datetime.now()}] Default new key rate limit: {DEFAULT_MAX_REQUESTS} requests / {DEFAULT_PERIOD_SECONDS} seconds")
    print(f"[{datetime.datetime.now()}] Service endpoints available:")
    print("  - GET / (Service status check)")
    print("  - Admin Endpoints (Require 'X-Admin-API-Key' header):")
    print("    - POST /admin/generate_key (Generate new API key)")
    print("    - POST /admin/revoke_key/<key_id> (Revoke an API key)")
    print("    - POST /admin/activate_key/<key_id> (Activate a revoked API key)")
    print("    - GET /admin/list_keys (List all API keys)")
    print("    - GET /admin/get_key_details/<key_id> (Get details for a specific key)")
    print("    - POST /admin/set_rate_limit/<key_id> (Set/Update rate limit for a key)")
    print("  - Microservice Endpoints (Require 'X-API-Key' header):")
    print("    - GET /validate_key (Validate API key and get details)")
    print("    - POST /track_usage (Record a specific usage event)")
    print("    - GET /check_rate_limit (Check current rate limit status without consuming a request)")
    print("    - POST /consume_request (Consume a request, applies rate limit and records usage)")
    
    # Run the Flask application.
    # `debug=True` is suitable for development but should be `False` in production.
    # `host='0.0.0.0'` makes the server accessible externally (not just from localhost).
    # In a production deployment, a WSGI server like Gunicorn or uWSGI would be used
    # to run the Flask application for better performance, stability, and security.
    app.run(debug=True, host='0.0.0.0', port=5000)