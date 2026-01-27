import os
import sqlite3
import json
import logging
from functools import wraps
from collections import OrderedDict
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs

# Third-party library: Flask is essential for building a web API.
# pip install Flask
from flask import Flask, request, jsonify, abort, make_response

# --- Configuration Section ---
# This dictionary holds all configurable parameters for the application.
# Using a dictionary allows easy modification and access to settings.
# The `Config` dictionary is designed to be comprehensive, covering database,
# API server, logging, and schema settings.
class Config:
    """
    Configuration class to hold all application settings.
    This approach provides a structured way to manage parameters
    and can be easily extended (e.g., loading from environment variables or a config file).
    """
    # Database Configuration
    DATABASE_FILE = "api_data.db"  # Default SQLite database file name
    DATABASE_CONNECT_TIMEOUT = 10  # Seconds to wait for a database connection

    # API Server Configuration
    API_HOST = "127.0.0.1"  # Host address for the Flask API server
    API_PORT = 5000         # Port for the Flask API server
    DEBUG_MODE = True       # Enable Flask debug mode (reloader, debugger)
    JSON_INDENT = 4         # Indentation for pretty-printing JSON responses

    # Logging Configuration
    LOG_LEVEL = logging.DEBUG  # Minimum logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    LOG_FILE = "api_server.log" # Log file path

    # Schema Inspection Configuration
    SCHEMA_CACHE_TTL_SECONDS = 300 # Time-to-live for schema cache in seconds (5 minutes)
                                   # Set to 0 to disable caching and always query DB.

    # API Endpoint Configuration
    API_BASE_PATH = "/api" # Base URL path for all generated table endpoints
    DEFAULT_LIMIT = 100    # Default number of rows to return if _limit is not specified
    MAX_LIMIT = 1000       # Maximum allowed number of rows per request via _limit

    # Pagination Link Configuration
    PAGINATION_HEADER = "X-Pagination" # Custom header for pagination metadata

    # Allowed query parameters (prefix with underscore to avoid conflicts with column names)
    QUERY_PARAM_LIMIT = "_limit"
    QUERY_PARAM_OFFSET = "_offset"
    QUERY_PARAM_SORT = "_sort"
    QUERY_PARAM_FIELDS = "_fields"
    QUERY_PARAM_FILTER_PREFIX = "_filter_" # Example: _filter_column_name=value

    # SQLite Specifics
    # SQLite doesn't have a direct concept of primary key name unless specified,
    # often 'rowid' acts as an implicit primary key if no explicit integer PK is defined.
    # We will try to infer a primary key or fallback to 'rowid'.
    PRIMARY_KEY_IDENTIFIER = "rowid" # Fallback/default identifier for single-row lookups

# --- Logging Setup ---
# Initialize the logging system to provide detailed feedback on application activity.
# This helps in debugging and monitoring the server's operation.
logging.basicConfig(
    level=Config.LOG_LEVEL,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(Config.LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)
logger.info("Application logging initialized.")

# --- Flask Application Initialization ---
# Create the Flask application instance.
# This is the core object that manages routes, requests, and responses.
app = Flask(__name__)
# Configure Flask's JSON encoder to pretty-print output.
app.json_encoder.indent = Config.JSON_INDENT
app.json_encoder.sort_keys = False # Maintain insertion order for OrderedDicts

# --- Helper Functions and Decorators ---

def database_connection_required(func):
    """
    A decorator to ensure a database connection is available for the wrapped function.
    This helps in robust error handling for database operations.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except sqlite3.OperationalError as e:
            logger.error(f"Database operational error: {e}")
            abort(500, description=f"Database operational error: {e}")
        except Exception as e:
            logger.exception(f"An unexpected error occurred during database operation in {func.__name__}: {e}")
            abort(500, description=f"An internal server error occurred: {e}")
    return wrapper

def row_to_dict(cursor, row_data):
    """
    Converts a database row (tuple) along with cursor description into an OrderedDict.
    This ensures that column names are preserved and can be directly serialized to JSON.
    Using OrderedDict helps maintain column order for consistent JSON output.
    """
    if not row_data:
        return None
    columns = [col[0] for col in cursor.description]
    return OrderedDict(zip(columns, row_data))

def generate_pagination_links(current_url, total_records, limit, offset):
    """
    Generates HATEOAS-style pagination links (first, prev, next, last)
    for a given API endpoint.
    Returns a dictionary of links.
    """
    parsed_url = urlparse(current_url)
    query_params = parse_qs(parsed_url.query)

    links = {}

    # Helper to build a URL with new offset
    def build_url_with_offset(new_offset):
        # Ensure offset is not negative
        new_offset = max(0, new_offset)
        # Ensure limit is present in query parameters
        query_params[Config.QUERY_PARAM_LIMIT] = [str(limit)]
        query_params[Config.QUERY_PARAM_OFFSET] = [str(new_offset)]
        new_query_string = urlencode(query_params, doseq=True)
        return urlunparse(parsed_url._replace(query=new_query_string))

    # First page
    if offset > 0:
        links['first'] = build_url_with_offset(0)

    # Previous page
    if offset > 0:
        prev_offset = offset - limit
        links['prev'] = build_url_with_offset(prev_offset)

    # Next page
    if offset + limit < total_records:
        next_offset = offset + limit
        links['next'] = build_url_with_offset(next_offset)

    # Last page
    last_offset = (total_records // limit) * limit
    if total_records % limit == 0 and total_records > 0:
        last_offset -= limit # If total_records is a perfect multiple of limit
    if offset + limit < total_records: # Only if current is not last
        links['last'] = build_url_with_offset(last_offset)

    return links


# --- Database Management Class ---
# This class encapsulates all interactions with the SQLite database.
# It uses context managers for robust connection handling and provides
# methods for executing queries and fetching results.
class DatabaseManager:
    """
    Manages database connections and query execution.
    Uses context managers (`with` statement) to ensure connections are
    properly opened and closed, preventing resource leaks.
    """
    def __init__(self, db_path):
        self.db_path = db_path
        self._connection = None

    def __enter__(self):
        """Opens a database connection when entering the context."""
        try:
            self._connection = sqlite3.connect(self.db_path, timeout=Config.DATABASE_CONNECT_TIMEOUT)
            self._connection.row_factory = sqlite3.Row # Allows accessing columns by name
            logger.debug(f"Database connection opened to {self.db_path}")
            return self
        except sqlite3.Error as e:
            logger.error(f"Error connecting to database {self.db_path}: {e}")
            raise

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Closes the database connection when exiting the context."""
        if self._connection:
            self._connection.close()
            logger.debug(f"Database connection closed from {self.db_path}")
        if exc_val:
            logger.error(f"Database operation failed: {exc_val}", exc_info=(exc_type, exc_val, exc_tb))

    def _execute_query(self, sql_query, params=(), commit=False):
        """Internal method to execute an SQL query."""
        if not self._connection:
            raise sqlite3.OperationalError("No active database connection.")
        cursor = self._connection.cursor()
        logger.debug(f"Executing SQL: {sql_query} with params: {params}")
        cursor.execute(sql_query, params)
        if commit:
            self._connection.commit()
            logger.info("Transaction committed.")
        return cursor

    def fetch_all(self, sql_query, params=()):
        """Fetches all rows from a SELECT query."""
        cursor = self._execute_query(sql_query, params)
        return cursor.fetchall()

    def fetch_one(self, sql_query, params=()):
        """Fetches a single row from a SELECT query."""
        cursor = self._execute_query(sql_query, params)
        return cursor.fetchone()

    def execute_and_commit(self, sql_query, params=()):
        """Executes a DML query (INSERT, UPDATE, DELETE) and commits."""
        cursor = self._execute_query(sql_query, params, commit=True)
        return cursor.rowcount # Returns the number of rows affected

    def get_table_names(self):
        """Retrieves a list of all table names in the database."""
        # For SQLite, use sqlite_master table to get table names
        sql = "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';"
        cursor = self._execute_query(sql)
        tables = [row[0] for row in cursor.fetchall()]
        logger.info(f"Discovered tables: {tables}")
        return tables

    def get_table_schema(self, table_name):
        """
        Retrieves the schema (column names and types) for a given table.
        Returns a list of dictionaries, each representing a column.
        Each dictionary contains: {'name': str, 'type': str, 'pk': bool}
        """
        sql = f"PRAGMA table_info({table_name});"
        cursor = self._execute_query(sql)
        # cid, name, type, notnull, dflt_value, pk
        schema_info = []
        for row in cursor.fetchall():
            schema_info.append({
                'name': row['name'],
                'type': row['type'],
                'pk': bool(row['pk'])
            })
        logger.debug(f"Schema for '{table_name}': {schema_info}")
        return schema_info

# --- Schema Caching and Inspection ---
# To optimize performance, schema information is cached.
# This avoids repeatedly querying the database for table and column details.
class SchemaInspector:
    """
    Inspects and caches database schema information.
    This avoids repetitive database queries for schema details.
    """
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self._schema_cache = {} # Stores {table_name: {'columns': [...], 'pk_column': str}, 'timestamp': float}
        self._table_list_cache = None
        self._last_table_list_update = 0

    def _is_cache_valid(self, timestamp):
        """Checks if a cached item is still valid based on its timestamp."""
        return (os.time() - timestamp) < Config.SCHEMA_CACHE_TTL_SECONDS if Config.SCHEMA_CACHE_TTL_SECONDS > 0 else False

    def get_all_table_names(self):
        """
        Retrieves all table names, utilizing a cache.
        """
        if self._table_list_cache and self._is_cache_valid(self._last_table_list_update):
            logger.debug("Retrieving table names from cache.")
            return self._table_list_cache

        logger.info("Fetching table names from database (cache expired or not set).")
        with self.db_manager as db:
            table_names = db.get_table_names()
        self._table_list_cache = table_names
        self._last_table_list_update = os.time()
        return table_names

    def get_table_schema(self, table_name):
        """
        Retrieves the schema for a specific table, utilizing a cache.
        Returns a dictionary with 'columns' (list of dicts) and 'pk_column' (str).
        """
        if table_name not in self._schema_cache or not self._is_cache_valid(self._schema_cache[table_name]['timestamp']):
            logger.info(f"Fetching schema for table '{table_name}' from database (cache expired or not set).")
            with self.db_manager as db:
                schema_data = db.get_table_schema(table_name)
            
            pk_column = None
            for col in schema_data:
                if col['pk']:
                    pk_column = col['name']
                    break
            # Fallback for SQLite if no explicit PK is found
            if not pk_column:
                pk_column = Config.PRIMARY_KEY_IDENTIFIER 
                logger.warning(f"No explicit primary key found for table '{table_name}'. Using '{pk_column}' as fallback.")

            self._schema_cache[table_name] = {
                'columns': schema_data,
                'pk_column': pk_column,
                'timestamp': os.time()
            }
        logger.debug(f"Retrieving schema for table '{table_name}' from cache.")
        return self._schema_cache[table_name]

# Global instances of our managers
db_manager_instance = DatabaseManager(Config.DATABASE_FILE)
schema_inspector_instance = SchemaInspector(db_manager_instance)

# --- Dynamic API Endpoint Generation ---

def _build_select_query(table_name, schema_info, query_params, single_row_id=None):
    """
    Constructs a SQL SELECT query dynamically based on parsed query parameters.
    This function handles field selection, filtering, sorting, limiting, and offsetting.
    """
    columns = [col['name'] for col in schema_info['columns']]
    pk_column = schema_info['pk_column']

    # 1. SELECT clause: specific fields or all
    selected_fields = query_params.get(Config.QUERY_PARAM_FIELDS, '*')
    if selected_fields != '*':
        # Validate requested fields against actual columns
        requested_fields_list = [f.strip() for f in selected_fields.split(',')]
        valid_fields = [f for f in requested_fields_list if f in columns]
        if not valid_fields:
            raise ValueError(f"No valid fields specified in '{Config.QUERY_PARAM_FIELDS}' parameter.")
        select_clause = ", ".join(valid_fields)
    else:
        select_clause = "*"

    sql_parts = [f"SELECT {select_clause} FROM {table_name}"]
    where_clauses = []
    sql_params = []

    # 2. WHERE clause for single row by ID
    if single_row_id is not None:
        where_clauses.append(f"{pk_column} = ?")
        sql_params.append(single_row_id)
        logger.debug(f"Adding single row ID filter: {pk_column}={single_row_id}")
    else:
        # 3. WHERE clause for filtering (from query parameters)
        for param, value in query_params.items():
            if param in columns: # Direct column name filter
                where_clauses.append(f"{param} = ?")
                sql_params.append(value)
                logger.debug(f"Adding direct column filter: {param}={value}")
            elif param.startswith(Config.QUERY_PARAM_FILTER_PREFIX): # Advanced filter prefix
                column_name = param[len(Config.QUERY_PARAM_FILTER_PREFIX):]
                if column_name in columns:
                    where_clauses.append(f"{column_name} = ?")
                    sql_params.append(value)
                    logger.debug(f"Adding prefixed column filter: {column_name}={value}")
                else:
                    logger.warning(f"Ignoring invalid filter parameter: {param}")

    if where_clauses:
        sql_parts.append("WHERE " + " AND ".join(where_clauses))

    # 4. ORDER BY clause
    sort_by = query_params.get(Config.QUERY_PARAM_SORT)
    if sort_by:
        sort_columns = []
        for s_col in sort_by.split(','):
            s_col = s_col.strip()
            direction = 'ASC'
            if s_col.startswith('-'):
                direction = 'DESC'
                s_col = s_col[1:]
            
            if s_col in columns:
                sort_columns.append(f"{s_col} {direction}")
            else:
                logger.warning(f"Ignoring invalid sort column: {s_col}")
        if sort_columns:
            sql_parts.append("ORDER BY " + ", ".join(sort_columns))
            logger.debug(f"Adding sort order: {sort_by}")

    # 5. LIMIT and OFFSET clauses
    limit = int(query_params.get(Config.QUERY_PARAM_LIMIT, Config.DEFAULT_LIMIT))
    limit = min(limit, Config.MAX_LIMIT) # Enforce max limit
    offset = int(query_params.get(Config.QUERY_PARAM_OFFSET, 0))

    if limit > 0:
        sql_parts.append(f"LIMIT ?")
        sql_params.append(limit)
        logger.debug(f"Adding limit: {limit}")
    if offset > 0:
        sql_parts.append(f"OFFSET ?")
        sql_params.append(offset)
        logger.debug(f"Adding offset: {offset}")

    final_sql = " ".join(sql_parts) + ";"
    return final_sql, sql_params, limit, offset


def _get_total_records(table_name, schema_info, query_params):
    """
    Counts the total number of records in a table, considering filters but not limit/offset.
    This is used for pagination metadata.
    """
    columns = [col['name'] for col in schema_info['columns']]
    sql_parts = [f"SELECT COUNT(*) FROM {table_name}"]
    where_clauses = []
    sql_params = []

    for param, value in query_params.items():
        if param in columns:
            where_clauses.append(f"{param} = ?")
            sql_params.append(value)
        elif param.startswith(Config.QUERY_PARAM_FILTER_PREFIX):
            column_name = param[len(Config.QUERY_PARAM_FILTER_PREFIX):]
            if column_name in columns:
                where_clauses.append(f"{column_name} = ?")
                sql_params.append(value)

    if where_clauses:
        sql_parts.append("WHERE " + " AND ".join(where_clauses))

    final_sql = " ".join(sql_parts) + ";"
    logger.debug(f"Counting total records with SQL: {final_sql} and params: {sql_params}")

    with db_manager_instance as db:
        cursor = db._execute_query(final_sql, sql_params)
        total = cursor.fetchone()[0]
    return total

def _register_table_endpoints(app_instance, table_name):
    """
    Dynamically registers Flask routes for a given table.
    Creates endpoints for fetching all records and a single record by ID.
    """
    table_base_path = f"{Config.API_BASE_PATH}/{table_name}"
    schema_info = schema_inspector_instance.get_table_schema(table_name)
    pk_column = schema_info['pk_column']

    logger.info(f"Registering API endpoints for table: '{table_name}'")
    logger.debug(f"Primary key for '{table_name}': {pk_column}")

    # Endpoint to get all records from the table
    @app_instance.route(table_base_path, methods=['GET'])
    @database_connection_required
    def get_all_records():
        logger.info(f"Received GET request for all records in table '{table_name}'")
        query_params = {k: v for k, v in request.args.items()}
        logger.debug(f"Request query parameters: {query_params}")

        try:
            sql_query, sql_params, current_limit, current_offset = _build_select_query(
                table_name, schema_info, query_params
            )
            with db_manager_instance as db:
                rows = db.fetch_all(sql_query, sql_params)
            
            total_records = _get_total_records(table_name, schema_info, query_params)
            
            response_data = [row_to_dict(db._connection.cursor(), r) for r in rows]
            response = make_response(jsonify(response_data))

            # Add pagination headers
            pagination_links = generate_pagination_links(
                request.full_path, total_records, current_limit, current_offset
            )
            pagination_metadata = {
                "total": total_records,
                "count": len(response_data),
                "limit": current_limit,
                "offset": current_offset,
                "links": pagination_links
            }
            response.headers[Config.PAGINATION_HEADER] = json.dumps(pagination_metadata)
            
            logger.info(f"Returning {len(response_data)} records for '{table_name}'. Total: {total_records}")
            return response

        except ValueError as ve:
            logger.warning(f"Bad request for '{table_name}': {ve}")
            abort(400, description=str(ve))
        except Exception as e:
            logger.exception(f"Error fetching all records for table '{table_name}': {e}")
            abort(500, description=f"Internal server error: {e}")

    # Endpoint to get a single record by its primary key
    @app_instance.route(f"{table_base_path}/<pk_value>", methods=['GET'])
    @database_connection_required
    def get_single_record(pk_value):
        logger.info(f"Received GET request for record '{pk_value}' in table '{table_name}'")
        
        # We need a dummy query_params for _build_select_query, but without limit/offset
        # as a single row query should not be limited/offsetted.
        # However, _fields parameter might still be relevant.
        query_params = {k: v for k, v in request.args.items() if k == Config.QUERY_PARAM_FIELDS}

        try:
            sql_query, sql_params, _, _ = _build_select_query(
                table_name, schema_info, query_params, single_row_id=pk_value
            )
            with db_manager_instance as db:
                row = db.fetch_one(sql_query, sql_params)

            if row:
                response_data = row_to_dict(db._connection.cursor(), row)
                logger.info(f"Returning single record for '{table_name}' with ID '{pk_value}'")
                return jsonify(response_data)
            else:
                logger.warning(f"Record with ID '{pk_value}' not found in table '{table_name}'")
                abort(404, description=f"Record with ID '{pk_value}' not found in table '{table_name}'.")

        except ValueError as ve:
            logger.warning(f"Bad request for single record '{pk_value}' in '{table_name}': {ve}")
            abort(400, description=str(ve))
        except Exception as e:
            logger.exception(f"Error fetching single record '{pk_value}' for table '{table_name}': {e}")
            abort(500, description=f"Internal server error: {e}")

# --- Flask Error Handlers ---
# These functions provide consistent JSON error responses for common HTTP status codes.
@app.errorhandler(400)
def bad_request(error):
    logger.error(f"HTTP 400 Bad Request: {error.description}")
    return jsonify({"error": "Bad Request", "message": error.description}), 400

@app.errorhandler(404)
def not_found(error):
    logger.error(f"HTTP 404 Not Found: {error.description}")
    return jsonify({"error": "Not Found", "message": error.description}), 404

@app.errorhandler(405)
def method_not_allowed(error):
    logger.error(f"HTTP 405 Method Not Allowed: {error.description}")
    return jsonify({"error": "Method Not Allowed", "message": "The method is not allowed for the requested URL."}), 405

@app.errorhandler(500)
def internal_server_error(error):
    logger.critical(f"HTTP 500 Internal Server Error: {error.description}", exc_info=True)
    return jsonify({"error": "Internal Server Error", "message": error.description}), 500

# --- Root and API Base Endpoints ---
# These provide basic information about the API and available tables.
@app.route("/", methods=['GET'])
def root_info():
    """Provides basic information about the API and links to documentation/status."""
    logger.info("Received GET request for root endpoint.")
    return jsonify({
        "service": "Database to JSON API",
        "version": "1.0.0",
        "status": "online",
        "documentation": f"http://{Config.API_HOST}:{Config.API_PORT}/api",
        "message": "Access /api to see available tables."
    })

@app.route(Config.API_BASE_PATH, methods=['GET'])
@database_connection_required
def list_available_tables():
    """Lists all tables for which API endpoints are available."""
    logger.info("Received GET request for API base path, listing available tables.")
    try:
        table_names = schema_inspector_instance.get_all_table_names()
        table_links = {
            table: f"{request.url}/{table}" for table in table_names
        }
        return jsonify({
            "message": "Available database tables (endpoints)",
            "tables": table_links
        })
    except Exception as e:
        logger.exception("Failed to list available tables.")
        abort(500, description=f"Failed to retrieve table list: {e}")


# --- Database Initialization (for demonstration purposes) ---
def _create_dummy_database(db_file):
    """
    Creates a simple SQLite database with a few tables and sample data.
    This function ensures the script is runnable out-of-the-box for demonstration.
    """
    if os.path.exists(db_file):
        logger.info(f"Database file '{db_file}' already exists. Skipping dummy data creation.")
        return

    logger.info(f"Creating dummy database '{db_file}' with sample data.")
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        # Create 'users' table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                age INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cursor.execute("INSERT INTO users (name, email, age) VALUES ('Alice Smith', 'alice@example.com', 30);")
        cursor.execute("INSERT INTO users (name, email, age) VALUES ('Bob Johnson', 'bob@example.com', 24);")
        cursor.execute("INSERT INTO users (name, email, age) VALUES ('Charlie Brown', 'charlie@example.com', 35);")
        cursor.execute("INSERT INTO users (name, email, age) VALUES ('Diana Prince', 'diana@example.com', 40);")
        cursor.execute("INSERT INTO users (name, email, age) VALUES ('Eve Adams', 'eve@example.com', 28);")
        cursor.execute("INSERT INTO users (name, email, age) VALUES ('Frank White', 'frank@example.com', 50);")
        cursor.execute("INSERT INTO users (name, email, age) VALUES ('Grace Kelly', 'grace@example.com', 22);")
        cursor.execute("INSERT INTO users (name, email, age) VALUES ('Heidi Klum', 'heidi@example.com', 48);")
        cursor.execute("INSERT INTO users (name, email, age) VALUES ('Ivan Drago', 'ivan@example.com', 33);")
        cursor.execute("INSERT INTO users (name, email, age) VALUES ('Julia Roberts', 'julia@example.com', 56);")
        cursor.execute("INSERT INTO users (name, email, age) VALUES ('Karen Millen', 'karen@example.com', 45);")
        cursor.execute("INSERT INTO users (name, email, age) VALUES ('Leo Messi', 'leo@example.com', 37);")
        cursor.execute("INSERT INTO users (name, email, age) VALUES ('Mia Farrow', 'mia@example.com', 79);")
        cursor.execute("INSERT INTO users (name, email, age) VALUES ('Noah Wyle', 'noah@example.com', 53);")
        cursor.execute("INSERT INTO users (name, email, age) VALUES ('Olivia Newton', 'olivia@example.com', 75);")


        # Create 'products' table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS products (
                product_id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                price REAL NOT NULL,
                stock INTEGER DEFAULT 0,
                category TEXT
            );
        """)
        cursor.execute("INSERT INTO products (name, price, stock, category) VALUES ('Laptop', 1200.00, 50, 'Electronics');")
        cursor.execute("INSERT INTO products (name, price, stock, category) VALUES ('Mouse', 25.50, 200, 'Electronics');")
        cursor.execute("INSERT INTO products (name, price, stock, category) VALUES ('Keyboard', 75.00, 150, 'Electronics');")
        cursor.execute("INSERT INTO products (name, price, stock, category) VALUES ('Desk Chair', 150.00, 30, 'Furniture');")
        cursor.execute("INSERT INTO products (name, price, stock, category) VALUES ('Monitor', 300.00, 75, 'Electronics');")
        cursor.execute("INSERT INTO products (name, price, stock, category) VALUES ('Coffee Mug', 12.99, 500, 'Kitchen');")
        cursor.execute("INSERT INTO products (name, price, stock, category) VALUES ('Notebook', 5.99, 1000, 'Stationery');")
        cursor.execute("INSERT INTO products (name, price, stock, category) VALUES ('Pen Set', 10.00, 300, 'Stationery');")
        cursor.execute("INSERT INTO products (name, price, stock, category) VALUES ('Webcam', 49.99, 80, 'Electronics');")
        cursor.execute("INSERT INTO products (name, price, stock, category) VALUES ('Speakers', 99.00, 120, 'Electronics');")
        cursor.execute("INSERT INTO products (name, price, stock, category) VALUES ('Headphones', 199.00, 90, 'Electronics');")
        cursor.execute("INSERT INTO products (name, price, stock, category) VALUES ('Water Bottle', 15.00, 250, 'Sporting Goods');")
        cursor.execute("INSERT INTO products (name, price, stock, category) VALUES ('Backpack', 60.00, 180, 'Bags');")
        cursor.execute("INSERT INTO products (name, price, stock, category) VALUES ('Tablet', 450.00, 60, 'Electronics');")
        cursor.execute("INSERT INTO products (name, price, stock, category) VALUES ('Smartwatch', 220.00, 40, 'Wearables');")


        # Create 'orders' table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS orders (
                order_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                total_amount REAL NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
        """)
        cursor.execute("INSERT INTO orders (user_id, total_amount, status) VALUES (1, 1225.50, 'completed');")
        cursor.execute("INSERT INTO orders (user_id, total_amount, status) VALUES (2, 75.00, 'pending');")
        cursor.execute("INSERT INTO orders (user_id, total_amount, status) VALUES (1, 15.00, 'completed');")
        cursor.execute("INSERT INTO orders (user_id, total_amount, status) VALUES (3, 300.00, 'shipped');")
        cursor.execute("INSERT INTO orders (user_id, total_amount, status) VALUES (5, 49.99, 'pending');")
        cursor.execute("INSERT INTO orders (user_id, total_amount, status) VALUES (2, 5.99, 'completed');")
        cursor.execute("INSERT INTO orders (user_id, total_amount, status) VALUES (1, 199.00, 'shipped');")
        cursor.execute("INSERT INTO orders (user_id, total_amount, status) VALUES (4, 150.00, 'completed');")
        cursor.execute("INSERT INTO orders (user_id, total_amount, status) VALUES (3, 10.00, 'pending');")
        cursor.execute("INSERT INTO orders (user_id, total_amount, status) VALUES (6, 99.00, 'completed');")
        cursor.execute("INSERT INTO orders (user_id, total_amount, status) VALUES (7, 60.00, 'shipped');")
        cursor.execute("INSERT INTO orders (user_id, total_amount, status) VALUES (8, 220.00, 'pending');")
        cursor.execute("INSERT INTO orders (user_id, total_amount, status) VALUES (9, 450.00, 'completed');")
        cursor.execute("INSERT INTO orders (user_id, total_amount, status) VALUES (10, 12.99, 'shipped');")
        cursor.execute("INSERT INTO orders (user_id, total_amount, status) VALUES (11, 1200.00, 'pending');")

        conn.commit()
        logger.info("Dummy database and data created successfully.")
    except sqlite3.Error as e:
        logger.critical(f"Error creating dummy database: {e}")
        if conn:
            conn.rollback() # Rollback any changes on error
    finally:
        if conn:
            conn.close()

# --- Main Application Execution Block ---
# This block runs when the script is executed directly.
if __name__ == "__main__":
    # Ensure the dummy database exists for the application to run immediately.
    _create_dummy_database(Config.DATABASE_FILE)

    # Discover tables and register API endpoints for each.
    logger.info("Starting schema discovery and endpoint registration process...")
    try:
        # We perform initial schema discovery outside the request context
        # to set up routes before the server starts accepting requests.
        all_tables = schema_inspector_instance.get_all_table_names()
        if not all_tables:
            logger.warning("No tables found in the database. API will serve no data endpoints.")
        else:
            logger.info(f"Discovered {len(all_tables)} tables: {', '.join(all_tables)}")
            for table in all_tables:
                _register_table_endpoints(app, table)
                logger.debug(f"Endpoints for '{table}' registered.")

    except sqlite3.OperationalError as e:
        logger.critical(f"Failed to connect to database or inspect schema during startup: {e}")
        sys.exit(1) # Exit if database cannot be accessed at startup
    except Exception as e:
        logger.critical(f"An unexpected error occurred during startup: {e}", exc_info=True)
        sys.exit(1)

    # Start the Flask development server.
    # In a production environment, this would typically be served by a WSGI server
    # like Gunicorn or uWSGI, behind a reverse proxy like Nginx.
    logger.info(f"Starting Flask API server on http://{Config.API_HOST}:{Config.API_PORT}")
    logger.info("Press Ctrl+C to stop the server.")
    app.run(host=Config.API_HOST, port=Config.API_PORT, debug=Config.DEBUG_MODE)