# Required 3rd party libraries:
# To install, run: pip install Flask Flask-SocketIO psutil eventlet

import os
import sys
import json
import time
import threading
from datetime import datetime

# Standard library imports first for consistency
from pprint import pformat
import logging

# Third-party imports for web framework, websockets, and system monitoring
from flask import Flask, render_template_string, request, Response
from flask_socketio import SocketIO, emit, disconnect
import psutil
import eventlet # Used by Flask-SocketIO for asynchronous capabilities

# It's crucial to monkey patch standard library functions for eventlet
# to manage concurrency effectively, especially for blocking I/O operations.
eventlet.monkey_patch()

# --- Application Configuration ---
# Define constants and configuration variables for easy modification.
# The network port on which the Flask application will listen for incoming requests.
APP_PORT = 5000
# The IP address on which the Flask application will be accessible.
# '0.0.0.0' makes it accessible from any external IP, which is suitable for a dashboard.
APP_HOST = '0.0.0.0'
# The interval (in seconds) at which system statistics will be gathered and
# streamed to connected web browsers via WebSockets.
STREAM_INTERVAL_SECONDS = 2
# A timeout in seconds for `psutil` operations. This helps prevent the monitoring
# thread from hanging indefinitely if a process is unresponsive or causes issues.
PSUTIL_TIMEOUT_SECONDS = 0.1
# Maximum number of processes to send to the frontend. This prevents overwhelming
# the browser with an excessively large list of processes on busy systems.
MAX_PROCESSES_TO_DISPLAY = 100
# Enable or disable Flask's debug mode. Debug mode provides more verbose logging
# and an interactive debugger in the browser, but should be False in production.
FLASK_DEBUG_MODE = False
# Secret key for Flask sessions. This is essential for security features like
# protecting cookies and CSRF tokens. It should be a strong, random value.
# os.urandom(24) generates a suitable random byte string.
FLASK_SECRET_KEY = os.urandom(24)

# --- Flask and SocketIO Initialization ---
# Create the Flask application instance.
app = Flask(__name__)

# Apply configuration settings to the Flask app.
app.config['SECRET_KEY'] = FLASK_SECRET_KEY
app.config['DEBUG'] = FLASK_DEBUG_MODE

# Configure logging for the Flask application.
# This ensures that messages from Flask and psutil are visible in the console.
logging.basicConfig(level=logging.INFO,
                    format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
app.logger.setLevel(logging.INFO) # Set default logging level for app.logger

# Initialize Flask-SocketIO. This integrates WebSocket capabilities into Flask.
# `async_mode='eventlet'` tells SocketIO to use eventlet for its asynchronous
# operations, which is efficient for handling many concurrent connections.
# `cors_allowed_origins="*"` allows connections from any origin, useful for local
# development or if the dashboard is served from a different domain than the API.
# In production, this should be restricted to specific allowed origins for security.
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins="*")

# A threading.Event object used as a signal to gracefully stop the background
# data monitoring thread when the application is shutting down.
thread_stop_event = threading.Event()
# A global variable to hold a reference to the background monitoring thread.
# This allows us to start and manage it from different parts of the application.
background_thread = None

# --- Helper Functions for Data Collection using psutil ---
def get_cpu_info():
    """
    Collects detailed CPU usage statistics using the psutil library.
    It includes total and per-CPU core usage percentages, as well as
    various CPU time statistics (user, system, idle, iowait).

    Returns:
        dict: A dictionary containing various CPU-related statistics.
    """
    try:
        # psutil.cpu_percent(interval=None) calculates usage since the last call.
        # Calling it twice with None interval gives accurate current usage.
        psutil.cpu_percent(interval=None)
        eventlet.sleep(0.05) # Small pause to allow for a meaningful interval measurement
        total_cpu_percent = psutil.cpu_percent(interval=None) # Overall CPU usage percentage
        per_cpu_percent = psutil.cpu_percent(interval=None, percpu=True) # Percentage per CPU core

        cpu_times = psutil.cpu_times() # Get cumulative CPU times

        cpu_stats = {
            "total_percent": total_cpu_percent,
            "per_cpu_percent": per_cpu_percent,
            "cores_logical": psutil.cpu_count(logical=True), # Total logical cores (threads)
            "cores_physical": psutil.cpu_count(logical=False), # Total physical cores
            "user_time": cpu_times.user,
            "system_time": cpu_times.system,
            "idle_time": cpu_times.idle,
            # 'iowait' might not be available on all OSes (e.g., macOS, some Windows versions)
            "iowait_time": getattr(cpu_times, 'iowait', 0.0),
        }
        app.logger.debug(f"Collected CPU info: {json.dumps(cpu_stats, indent=2)}")
        return cpu_stats
    except Exception as e:
        app.logger.error(f"Error collecting CPU info: {e}", exc_info=True)
        return {"error": str(e)}

def get_memory_info():
    """
    Collects detailed memory (RAM) and swap space usage statistics using psutil.
    Provides total, used, available, and percentage usage for both virtual memory
    and swap memory, formatted in gigabytes.

    Returns:
        dict: A dictionary containing virtual and swap memory statistics.
    """
    try:
        virtual_memory = psutil.virtual_memory() # Main RAM statistics
        swap_memory = psutil.swap_memory()       # Swap space statistics

        mem_stats = {
            "total_gb": round(virtual_memory.total / (1024**3), 2),
            "available_gb": round(virtual_memory.available / (1024**3), 2),
            "used_gb": round(virtual_memory.used / (1024**3), 2),
            "percent": virtual_memory.percent,
            "swap_total_gb": round(swap_memory.total / (1024**3), 2),
            "swap_used_gb": round(swap_memory.used / (1024**3), 2),
            "swap_percent": swap_memory.percent,
        }
        app.logger.debug(f"Collected Memory info: {json.dumps(mem_stats, indent=2)}")
        return mem_stats
    except Exception as e:
        app.logger.error(f"Error collecting Memory info: {e}", exc_info=True)
        return {"error": str(e)}

def get_disk_info():
    """
    Collects disk usage statistics for the root partition ('/') using psutil.
    It reports total, used, free space, and usage percentage in gigabytes.

    Returns:
        dict: A dictionary containing disk usage statistics for the root partition.
    """
    try:
        # Get disk usage for the root partition. On Windows, this might be 'C:\'
        # psutil intelligently handles OS differences for root partition.
        disk_usage = psutil.disk_usage('/')
        disk_stats = {
            "total_gb": round(disk_usage.total / (1024**3), 2),
            "used_gb": round(disk_usage.used / (1024**3), 2),
            "free_gb": round(disk_usage.free / (1024**3), 2),
            "percent": disk_usage.percent,
        }
        app.logger.debug(f"Collected Disk info: {json.dumps(disk_stats, indent=2)}")
        return disk_stats
    except Exception as e:
        app.logger.error(f"Error collecting Disk info: {e}", exc_info=True)
        return {"error": str(e)}

def get_network_info():
    """
    Collects cumulative network I/O statistics (bytes and packets sent/received)
    for all network interfaces using psutil.

    Returns:
        dict: A dictionary containing network I/O statistics.
    """
    try:
        net_io = psutil.net_io_counters() # Cumulative network I/O counters
        net_stats = {
            "bytes_sent_mb": round(net_io.bytes_sent / (1024**2), 2),
            "bytes_recv_mb": round(net_io.bytes_recv / (1024**2), 2),
            "packets_sent": net_io.packets_sent,
            "packets_recv": net_io.packets_recv,
            "err_in": net_io.errin,   # Total number of errors while receiving
            "err_out": net_io.errout, # Total number of errors while sending
            "drop_in": net_io.dropin, # Total number of incoming packets which were dropped
            "drop_out": net_io.dropout, # Total number of outgoing packets which were dropped
        }
        app.logger.debug(f"Collected Network info: {json.dumps(net_stats, indent=2)}")
        return net_stats
    except Exception as e:
        app.logger.error(f"Error collecting Network info: {e}", exc_info=True)
        return {"error": str(e)}

def get_system_load():
    """
    Collects system load averages for 1, 5, and 15 minutes.
    This function is primarily available on Unix-like systems.

    Returns:
        dict: A dictionary with load averages, or an error message if not available.
    """
    try:
        # os.getloadavg() is a standard Python function, but only available on Unix.
        load_avg = os.getloadavg()
        load_stats = {
            "load1": round(load_avg[0], 2),
            "load5": round(load_avg[1], 2),
            "load15": round(load_avg[2], 2),
        }
        app.logger.debug(f"Collected System Load: {json.dumps(load_stats, indent=2)}")
        return load_stats
    except AttributeError:
        # os.getloadavg is not available on Windows, for example.
        app.logger.warning("System load averages not available on this operating system.")
        return {"error": "Load averages not available on this OS."}
    except Exception as e:
        app.logger.error(f"Error collecting system load: {e}", exc_info=True)
        return {"error": str(e)}

def get_process_data():
    """
    Collects a list of currently running processes with key details (PID, name, CPU, memory, etc.).
    It uses psutil.process_iter() for efficiency and includes error handling for processes
    that might terminate during iteration or deny access. Processes are sorted by CPU usage.

    Returns:
        list: A list of dictionaries, each representing a process with selected attributes.
              The list is truncated to `MAX_PROCESSES_TO_DISPLAY`.
    """
    processes_list = []
    # Define the attributes to retrieve for each process. This reduces overhead
    # compared to fetching all attributes for every process.
    attrs_to_get = [
        "pid", "name", "username", "status", "cpu_percent",
        "memory_percent", "num_threads", "create_time", "cmdline"
    ]

    # Iterate over all running processes
    for p in psutil.process_iter(attrs=attrs_to_get):
        try:
            # Get process info as a dictionary for easier access
            process_info = p.info

            # Calculate resident set size (RSS) memory usage in megabytes
            memory_info = p.memory_info()
            memory_rss_mb = round(memory_info.rss / (1024 * 1024), 2) if memory_info else 0

            # Format the process creation time into a human-readable string
            create_time_dt = datetime.fromtimestamp(process_info['create_time'])
            create_time_formatted = create_time_dt.strftime('%Y-%m-%d %H:%M:%S')

            # Ensure 'cmdline' is a string; it can be a list of arguments. Join them if so.
            cmdline = ' '.join(process_info['cmdline']) if isinstance(process_info['cmdline'], list) else process_info['cmdline']
            # If cmdline is empty (e.g., for system processes), use the process name.
            if not cmdline:
                cmdline = process_info['name']

            processes_list.append({
                "pid": process_info['pid'],
                "name": process_info['name'],
                "user": process_info['username'],
                "status": process_info['status'],
                "cpu_percent": round(process_info['cpu_percent'], 2),
                "memory_percent": round(process_info['memory_percent'], 2),
                "memory_rss_mb": memory_rss_mb,
                "threads": process_info['num_threads'],
                "start_time": create_time_formatted,
                "command": cmdline,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # These exceptions can occur if a process terminates between checks,
            # if we lack permissions, or if it's a zombie process. We silently skip them.
            continue
        except Exception as e:
            # Catch any other unexpected errors during process info retrieval.
            app.logger.warning(f"Error getting info for process {p.pid}: {e}", exc_info=True)
            continue

    # Sort the processes by CPU usage in descending order to show the most active ones first.
    sorted_processes = sorted(processes_list, key=lambda x: x['cpu_percent'], reverse=True)
    app.logger.debug(f"Collected {len(sorted_processes)} processes. Displaying top {MAX_PROCESSES_TO_DISPLAY}.")
    # Return only the top N processes to manage frontend performance.
    return sorted_processes[:MAX_PROCESSES_TO_DISPLAY]

def fetch_all_system_data():
    """
    Aggregates all system and process data collected by the helper functions
    into a single structured dictionary. This function acts as a single point
    for collecting all dashboard data.

    Returns:
        dict: A comprehensive dictionary containing system metrics and process list.
    """
    app.logger.info("Attempting to fetch all system data...")
    data = {
        "timestamp": datetime.now().isoformat(), # ISO formatted timestamp of data collection
        "cpu": get_cpu_info(),
        "memory": get_memory_info(),
        "disk": get_disk_info(),
        "network": get_network_info(),
        "load_averages": get_system_load(),
        "processes": get_process_data(),
    }
    app.logger.info("Finished fetching all system data.")
    return data

# --- Background Thread for Data Monitoring and Emitting ---
def background_monitor_thread():
    """
    This function runs continuously in a separate eventlet-managed thread.
    It periodically collects the latest system data and broadcasts it to all
    currently connected WebSocket clients. It uses `thread_stop_event` to
    allow for graceful shutdown.
    """
    app.logger.info("Starting background monitor thread for real-time data streaming.")
    iteration_count = 0
    while not thread_stop_event.is_set(): # Loop until a stop signal is received
        # Using eventlet.sleep is vital here instead of time.sleep.
        # It yields control, allowing other greenlets (like WebSocket connections)
        # to execute, ensuring the application remains responsive.
        eventlet.sleep(STREAM_INTERVAL_SECONDS)
        iteration_count += 1
        app.logger.debug(f"Background thread iteration: {iteration_count}. Fetching new data.")

        try:
            # Fetch all system data. This can be time-consuming, hence running in a background thread.
            system_data = fetch_all_system_data()
            # Emit the collected data to all connected clients under the 'system_update' event.
            # The `namespace='/'` specifies the default SocketIO namespace.
            socketio.emit('system_update', system_data, namespace='/')
            app.logger.info(f"Emitted system_update data to {len(socketio.server.manager.rooms['/']['/'])} clients.")
        except Exception as e:
            app.logger.error(f"Unhandled error in background monitor thread: {e}", exc_info=True)
            # Emit an error event to clients if data fetching fails.
            socketio.emit('error', {'message': f"Server error fetching data: {e}"}, namespace='/')

    app.logger.info("Background monitor thread received stop signal and is terminating.")

# --- Flask Routes ---
@app.route('/')
def index():
    """
    Serves the main HTML page for the SysAdmin dashboard.
    The HTML includes embedded CSS and JavaScript to create a single, self-contained
    Python script, as per the requirements. In a production environment,
    these assets would typically be served from separate template and static files.
    """
    # The HTML template string below defines the structure, styling, and client-side
    # JavaScript logic for the real-time dashboard.
    # It dynamically inserts the MAX_PROCESSES_TO_DISPLAY configuration value.
    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SysAdmin Dashboard - Real-time Monitor</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>📈</text></svg>">
    <style>
        /* General Body and Container Styling */
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; background-color: #f4f7f6; color: #333; line-height: 1.6; }}
        .header {{ background-color: #2c3e50; color: #ecf0f1; padding: 15px 20px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .header h1 {{ margin: 0; font-size: 1.8em; }}
        .header p {{ font-size: 0.9em; margin-top: 5px; opacity: 0.8; }}
        .container {{ max-width: 1400px; margin: 20px auto; padding: 0 20px; display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }}

        /* Card Styling for Individual Metric Sections */
        .card {{ background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.05); padding: 20px; transition: transform 0.2s ease, box-shadow 0.2s ease; }}
        .card:hover {{ transform: translateY(-3px); box-shadow: 0 4px 12px rgba(0,0,0,0.1); }}
        .card h2 {{ color: #34495e; margin-top: 0; border-bottom: 2px solid #eee; padding-bottom: 10px; margin-bottom: 15px; font-size: 1.4em; }}

        /* Stat Grid for arranging key-value pairs within cards */
        .stat-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }}
        .stat-item {{ padding: 5px 0; }}
        .stat-item strong {{ color: #555; display: block; margin-bottom: 3px; font-size: 0.9em; }}
        .stat-item span {{ font-size: 1.1em; font-weight: bold; color: #2980b9; }}

        /* Progress Bar Styling */
        .progress-bar-container {{ background-color: #e0e0e0; border-radius: 5px; height: 12px; margin-top: 5px; overflow: hidden; }}
        .progress-bar {{ height: 100%; background-color: #2ecc71; width: 0%; border-radius: 5px; transition: width 0.5s ease-out, background-color 0.5s ease; }}
        .progress-bar.red {{ background-color: #e74c3c; }} /* High usage */
        .progress-bar.orange {{ background-color: #f39c12; }} /* Medium usage */
        .progress-bar.green {{ background-color: #2ecc71; }} /* Low usage (default) */

        /* Table Styling for Process List */
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 0.9em; }}
        th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #eee; }}
        th {{ background-color: #e9ecef; color: #333; font-weight: bold; cursor: pointer; user-select: none; }}
        th:hover {{ background-color: #dee2e6; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
        tr:hover {{ background-color: #f0f8ff; }}

        /* Process Status Indicators */
        .status-indicator {{ display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 5px; border: 1px solid rgba(0,0,0,0.1); }}
        .status-running {{ background-color: #2ecc71; }} /* Green */
        .status-sleeping {{ background-color: #3498db; }} /* Blue */
        .status-disk-sleep {{ background-color: #f39c12; }} /* Orange */
        .status-stopped {{ background-color: #e74c3c; }} /* Red */
        .status-zombie {{ background-color: #9b59b6; }} /* Purple */
        .status-dead, .status-unknown {{ background-color: #7f8c8d; }} /* Grey */

        /* Layout adjustments for specific cards */
        #process-list {{ grid-column: 1 / -1; }} /* Make process list span full width */

        /* Responsive Design Adjustments */
        @media (max-width: 768px) {{
            .container {{ grid-template-columns: 1fr; }}
            .stat-grid {{ grid-template-columns: 1fr; }}
            .header h1 {{ font-size: 1.5em; }}
            th, td {{ padding: 8px; }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>SysAdmin Dashboard</h1>
        <p>Real-time Server Monitoring - Last Update: <span id="last-update">N/A</span></p>
    </div>

    <div class="container">
        <!-- CPU Usage Card -->
        <div class="card" id="cpu-card">
            <h2>CPU Usage</h2>
            <div class="stat-grid">
                <div class="stat-item">
                    <strong>Total Usage:</strong>
                    <span id="cpu-total-percent">0.00%</span>
                    <div class="progress-bar-container"><div class="progress-bar" id="cpu-total-bar"></div></div>
                </div>
                <div class="stat-item">
                    <strong>Logical Cores:</strong>
                    <span id="cpu-cores-logical">0</span>
                </div>
                <div class="stat-item">
                    <strong>Physical Cores:</strong>
                    <span id="cpu-cores-physical">0</span>
                </div>
                <div class="stat-item">
                    <strong>User Time:</strong>
                    <span id="cpu-user-time">0s</span>
                </div>
                <div class="stat-item">
                    <strong>System Time:</strong>
                    <span id="cpu-system-time">0s</span>
                </div>
                <div class="stat-item">
                    <strong>Idle Time:</strong>
                    <span id="cpu-idle-time">0s</span>
                </div>
                <div class="stat-item">
                    <strong>I/O Wait:</strong>
                    <span id="cpu-iowait-time">0s</span>
                </div>
            </div>
            <!-- Dynamic CPU core bars could be added here for even more detail -->
        </div>

        <!-- Memory Usage Card -->
        <div class="card" id="memory-card">
            <h2>Memory Usage</h2>
            <div class="stat-grid">
                <div class="stat-item">
                    <strong>Used:</strong>
                    <span id="mem-used">0.00 GB</span>
                </div>
                <div class="stat-item">
                    <strong>Total:</strong>
                    <span id="mem-total">0.00 GB</span>
                </div>
                <div class="stat-item">
                    <strong>Available:</strong>
                    <span id="mem-available">0.00 GB</span>
                </div>
                <div class="stat-item">
                    <strong>Usage %:</strong>
                    <span id="mem-percent">0.00%</span>
                    <div class="progress-bar-container"><div class="progress-bar" id="mem-percent-bar"></div></div>
                </div>
                <div class="stat-item">
                    <strong>Swap Used:</strong>
                    <span id="swap-used">0.00 GB</span>
                </div>
                <div class="stat-item">
                    <strong>Swap Total:</strong>
                    <span id="swap-total">0.00 GB</span>
                </div>
                <div class="stat-item">
                    <strong>Swap Usage %:</strong>
                    <span id="swap-percent">0.00%</span>
                    <div class="progress-bar-container"><div class="progress-bar" id="swap-percent-bar"></div></div>
                </div>
            </div>
        </div>

        <!-- Disk Usage Card -->
        <div class="card" id="disk-card">
            <h2>Disk Usage (Root)</h2>
            <div class="stat-grid">
                <div class="stat-item">
                    <strong>Used:</strong>
                    <span id="disk-used">0.00 GB</span>
                </div>
                <div class="stat-item">
                    <strong>Total:</strong>
                    <span id="disk-total">0.00 GB</span>
                </div>
                <div class="stat-item">
                    <strong>Free:</strong>
                    <span id="disk-free">0.00 GB</span>
                </div>
                <div class="stat-item">
                    <strong>Usage %:</strong>
                    <span id="disk-percent">0.00%</span>
                    <div class="progress-bar-container"><div class="progress-bar" id="disk-percent-bar"></div></div>
                </div>
            </div>
        </div>

        <!-- Network Usage Card -->
        <div class="card" id="network-card">
            <h2>Network I/O</h2>
            <div class="stat-grid">
                <div class="stat-item">
                    <strong>Bytes Sent:</strong>
                    <span id="net-sent">0.00 MB</span>
                </div>
                <div class="stat-item">
                    <strong>Bytes Recv:</strong>
                    <span id="net-recv">0.00 MB</span>
                </div>
                <div class="stat-item">
                    <strong>Packets Sent:</strong>
                    <span id="net-packets-sent">0</span>
                </div>
                <div class="stat-item">
                    <strong>Packets Recv:</strong>
                    <span id="net-packets-recv">0</span>
                </div>
                <div class="stat-item">
                    <strong>Errors In:</strong>
                    <span id="net-err-in">0</span>
                </div>
                <div class="stat-item">
                    <strong>Errors Out:</strong>
                    <span id="net-err-out">0</span>
                </div>
            </div>
        </div>

        <!-- System Load Averages Card -->
        <div class="card" id="load-card">
            <h2>System Load Average</h2>
            <div class="stat-grid">
                <div class="stat-item">
                    <strong>1 min:</strong>
                    <span id="load-1min">0.00</span>
                </div>
                <div class="stat-item">
                    <strong>5 min:</strong>
                    <span id="load-5min">0.00</span>
                </div>
                <div class="stat-item">
                    <strong>15 min:</strong>
                    <span id="load-15min">0.00</span>
                </div>
            </div>
        </div>

        <!-- Process List Card -->
        <div class="card" id="process-list">
            <h2>Process List</h2>
            <div style="overflow-x: auto;">
                <table id="processes-table">
                    <thead>
                        <tr>
                            <th data-sort="pid">PID</th>
                            <th data-sort="name">Name</th>
                            <th data-sort="user">User</th>
                            <th data-sort="status">Status</th>
                            <th data-sort="cpu_percent">CPU %</th>
                            <th data-sort="memory_percent">MEM %</th>
                            <th data-sort="memory_rss_mb">MEM (MB)</th>
                            <th data-sort="threads">Threads</th>
                            <th data-sort="start_time">Start Time</th>
                            <th data-sort="command">Command</th>
                        </tr>
                    </thead>
                    <tbody>
                        <!-- Process rows will be dynamically inserted here by JavaScript -->
                    </tbody>
                </table>
            </div>
            <p style="font-size: 0.85em; color: #666; margin-top: 15px;">
                Displaying top {MAX_PROCESSES_TO_DISPLAY} processes by CPU usage. Click column headers to sort.
            </p>
        </div>
    </div>

    <!-- External Socket.IO client library from CDN -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.0/socket.io.min.js"></script>
    <script>
        // Client-side JavaScript for handling WebSocket data and updating the UI

        // Establish a WebSocket connection to the server.
        // By default, it connects to the same host and port the HTML was served from.
        const socket = io();

        // --- Utility Functions for UI Updates ---

        /**
         * Updates a progress bar element's width and color based on a percentage value.
         * @param {string} elementId The ID of the progress bar div.
         * @param {number} percentage The usage percentage (0-100).
         */
        function updateProgressBar(elementId, percentage) {{
            const bar = document.getElementById(elementId);
            if (bar) {{
                bar.style.width = percentage + '%';
                // Apply color coding based on usage thresholds
                if (percentage > 90) {{
                    bar.className = 'progress-bar red';
                } else if (percentage > 70) {{
                    bar.className = 'progress-bar orange';
                } else {{
                    bar.className = 'progress-bar green'; // Default green for lower usage
                }}
            }}
        }}

        /**
         * Returns a CSS class name for a process status indicator based on the status string.
         * @param {string} status The process status string (e.g., "running", "sleeping").
         * @returns {string} The corresponding CSS class name.
         */
        function getStatusIndicatorClass(status) {{
            if (!status) return 'status-unknown';
            status = status.toLowerCase();
            if (status === 'running') return 'status-running';
            if (status === 'sleeping') return 'status-sleeping';
            if (status === 'disk_sleep' || status === 'waiting') return 'status-disk-sleep';
            if (status === 'stopped' || status === 'tracing_stop') return 'status-stopped';
            if (status === 'zombie') return 'status-zombie';
            if (status === 'dead' || status === 'parked') return 'status-dead';
            return 'status-unknown'; // Fallback for unknown statuses
        }}

        // --- Socket.IO Event Handlers ---

        socket.on('connect', function() {{
            console.log('Connected to WebSocket server.');
            // Acknowledge connection. Could send an initial request if needed.
            socket.emit('client_ready', {{data: 'Client is ready to receive data!'}});
        }});

        socket.on('disconnect', function() {{
            console.log('Disconnected from WebSocket server.');
        }});

        socket.on('error', function(data) {{
            console.error('Server error:', data.message);
            // Display a user-friendly error message, perhaps in a toast notification.
            alert('Server error: ' + data.message + '\\nPlease check server logs.');
        }});

        socket.on('system_update', function(data) {{
            // console.log('Received system update:', data); // Uncomment for debugging

            // Update the 'Last Update' timestamp in the header
            const updateTime = new Date(data.timestamp).toLocaleTimeString();
            document.getElementById('last-update').innerText = updateTime;

            // Update CPU Info Card
            if (data.cpu) {{
                document.getElementById('cpu-total-percent').innerText = data.cpu.total_percent.toFixed(2) + '%';
                updateProgressBar('cpu-total-bar', data.cpu.total_percent);
                document.getElementById('cpu-cores-logical').innerText = data.cpu.cores_logical;
                document.getElementById('cpu-cores-physical').innerText = data.cpu.cores_physical;
                document.getElementById('cpu-user-time').innerText = data.cpu.user_time.toFixed(1) + 's';
                document.getElementById('cpu-system-time').innerText = data.cpu.system_time.toFixed(1) + 's';
                document.getElementById('cpu-idle-time').innerText = data.cpu.idle_time.toFixed(1) + 's';
                document.getElementById('cpu-iowait-time').innerText = data.cpu.iowait_time.toFixed(1) + 's';
            }}

            // Update Memory Info Card
            if (data.memory) {{
                document.getElementById('mem-used').innerText = data.memory.used_gb.toFixed(2) + ' GB';
                document.getElementById('mem-total').innerText = data.memory.total_gb.toFixed(2) + ' GB';
                document.getElementById('mem-available').innerText = data.memory.available_gb.toFixed(2) + ' GB';
                document.getElementById('mem-percent').innerText = data.memory.percent.toFixed(2) + '%';
                updateProgressBar('mem-percent-bar', data.memory.percent);

                document.getElementById('swap-used').innerText = data.memory.swap_used_gb.toFixed(2) + ' GB';
                document.getElementById('swap-total').innerText = data.memory.swap_total_gb.toFixed(2) + ' GB';
                document.getElementById('swap-percent').innerText = data.memory.swap_percent.toFixed(2) + '%';
                updateProgressBar('swap-percent-bar', data.memory.swap_percent);
            }}

            // Update Disk Info Card
            if (data.disk && !data.disk.error) {{
                document.getElementById('disk-used').innerText = data.disk.used_gb.toFixed(2) + ' GB';
                document.getElementById('disk-total').innerText = data.disk.total_gb.toFixed(2) + ' GB';
                document.getElementById('disk-free').innerText = data.disk.free_gb.toFixed(2) + ' GB';
                document.getElementById('disk-percent').innerText = data.disk.percent.toFixed(2) + '%';
                updateProgressBar('disk-percent-bar', data.disk.percent);
            }} else if (data.disk && data.disk.error) {{
                // Handle disk error display
                document.getElementById('disk-used').innerText = 'Error';
                document.getElementById('disk-total').innerText = data.disk.error;
                document.getElementById('disk-free').innerText = '';
                document.getElementById('disk-percent').innerText = '';
                updateProgressBar('disk-percent-bar', 0); // Reset bar
            }}

            // Update Network Info Card
            if (data.network) {{
                document.getElementById('net-sent').innerText = data.network.bytes_sent_mb.toFixed(2) + ' MB';
                document.getElementById('net-recv').innerText = data.network.bytes_recv_mb.toFixed(2) + ' MB';
                document.getElementById('net-packets-sent').innerText = data.network.packets_sent;
                document.getElementById('net-packets-recv').innerText = data.network.packets_recv;
                document.getElementById('net-err-in').innerText = data.network.err_in;
                document.getElementById('net-err-out').innerText = data.network.err_out;
            }}

            // Update System Load Averages Card
            if (data.load_averages && !data.load_averages.error) {{
                document.getElementById('load-1min').innerText = data.load_averages.load1.toFixed(2);
                document.getElementById('load-5min').innerText = data.load_averages.load5.toFixed(2);
                document.getElementById('load-15min').innerText = data.load_averages.load15.toFixed(2);
            }} else if (data.load_averages && data.load_averages.error) {{
                 document.getElementById('load-1min').innerText = data.load_averages.error;
                 document.getElementById('load-5min').innerText = ''; // Clear other values
                 document.getElementById('load-15min').innerText = '';
            }}

            // Update Process List Table
            if (data.processes) {{
                const tbody = document.getElementById('processes-table').getElementsByTagName('tbody')[0];
                tbody.innerHTML = ''; // Clear existing rows

                data.processes.forEach(p => {{
                    const row = tbody.insertRow();
                    row.insertCell().innerText = p.pid;
                    row.insertCell().innerText = p.name;
                    row.insertCell().innerText = p.user;
                    const statusCell = row.insertCell();
                    statusCell.innerHTML = `<span class="status-indicator ${getStatusIndicatorClass(p.status)}"></span>${p.status}`;
                    row.insertCell().innerText = p.cpu_percent.toFixed(2) + '%';
                    row.insertCell().innerText = p.memory_percent.toFixed(2) + '%';
                    row.insertCell().innerText = p.memory_rss_mb.toFixed(2) + ' MB';
                    row.insertCell().innerText = p.threads;
                    row.insertCell().innerText = p.start_time;
                    // Truncate long commands for better table readability
                    row.insertCell().innerText = p.command.length > 80 ? p.command.substring(0, 77) + '...' : p.command;
                }});
                // Re-apply current sort after updating processes
                if (currentSortColumn) {{
                    sortTable(currentSortColumn, currentSortDirection);
                }}
            }}
        });

        // --- Table Sorting Logic (Client-Side) ---
        // This allows users to sort the process list by clicking on table headers.
        document.addEventListener('DOMContentLoaded', () => {{
            const table = document.getElementById('processes-table');
            const headers = table.querySelectorAll('th[data-sort]');
            const tbody = table.querySelector('tbody');

            let currentSortColumn = 'cpu_percent'; // Default sort by CPU %
            let currentSortDirection = 'desc'; // Default descending

            headers.forEach(header => {{
                header.addEventListener('click', () => {{
                    const column = header.dataset.sort;
                    // If clicking the same column, toggle sort direction
                    if (currentSortColumn === column) {{
                        currentSortDirection = currentSortDirection === 'asc' ? 'desc' : 'asc';
                    }} else {{
                        // If new column, set it as current and default to ascending (or descending for numerical)
                        currentSortColumn = column;
                        currentSortDirection = ['cpu_percent', 'memory_percent', 'memory_rss_mb', 'pid', 'threads'].includes(column) ? 'desc' : 'asc';
                    }}
                    sortTable(currentSortColumn, currentSortDirection);
                }});
            }});

            /**
             * Sorts the process table rows based on the specified column and direction.
             * @param {string} column The data-sort attribute of the column to sort by.
             * @param {string} direction 'asc' for ascending, 'desc' for descending.
             */
            function sortTable(column, direction) {{
                const rows = Array.from(tbody.rows);
                // Determine if the column contains numeric values for proper comparison
                const isNumeric = ['pid', 'cpu_percent', 'memory_percent', 'memory_rss_mb', 'threads'].includes(column);

                rows.sort((a, b) => {{
                    const colIndex = getColumnIndex(column);
                    const aValue = a.cells[colIndex].innerText.replace('%', '').replace(' MB', '');
                    const bValue = b.cells[colIndex].innerText.replace('%', '').replace(' MB', '');

                    let comparison = 0;
                    if (isNumeric) {{
                        comparison = parseFloat(aValue) - parseFloat(bValue);
                    }} else {{
                        comparison = aValue.localeCompare(bValue);
                    }}

                    return direction === 'asc' ? comparison : -comparison;
                }});

                // Clear the table body and re-append the sorted rows
                tbody.innerHTML = '';
                rows.forEach(row => tbody.appendChild(row));
            }}

            /**
             * Finds the column index for a given column name (data-sort attribute).
             * @param {string} columnName The name of the column as defined in data-sort.
             * @returns {number} The 0-based index of the column, or -1 if not found.
             */
            function getColumnIndex(columnName) {{
                const headerRow = table.querySelector('thead tr');
                const headers = Array.from(headerRow.querySelectorAll('th'));
                for (let i = 0; i < headers.length; i++) {{
                    if (headers[i].dataset.sort === columnName) {{
                        return i;
                    }}
                }}
                return -1;
            }}

            // Initial sort when the page loads
            sortTable(currentSortColumn, currentSortDirection);
        }});

    </script>
</body>
</html>
    """
    return render_template_string(html_content)

# --- SocketIO Event Handlers ---
@socketio.on('connect')
def handle_connect():
    """
    Handles new client connections to the WebSocket.
    When a client connects, this function ensures the background data
    monitoring thread is running. If it's not, it starts a new one.
    It also sends an initial snapshot of system data to the newly connected client.
    """
    global background_thread
    app.logger.info(f"Client {request.sid} connected to WebSocket.")

    # Check if the background thread is not running or has stopped.
    # If so, start a new one to begin streaming data.
    if background_thread is None or not background_thread.is_alive():
        app.logger.info("Background data monitoring thread is not active. Starting a new one.")
        thread_stop_event.clear() # Clear the stop event to allow the thread to run
        background_thread = socketio.start_background_task(target=background_monitor_thread)
        app.logger.info("Background thread initiated and set to stream data.")
    else:
        app.logger.debug("Background data monitoring thread is already running.")

    # Send an immediate snapshot of the current system data to the connecting client.
    # This provides instant feedback without waiting for the next stream interval.
    try:
        initial_data = fetch_all_system_data()
        emit('system_update', initial_data)
        app.logger.info(f"Sent initial system data snapshot to new client {request.sid}.")
    except Exception as e:
        app.logger.error(f"Error sending initial data to client {request.sid}: {e}", exc_info=True)
        emit('error', {'message': f"Server error occurred while sending initial data: {e}"})

@socketio.on('disconnect')
def handle_disconnect():
    """
    Handles client disconnections from the WebSocket.
    Logs the disconnection. In this implementation, the background data
    monitoring thread continues to run even if all clients disconnect.
    A more advanced setup might include logic to stop the thread after a
    period of no active connections to conserve resources.
    """
    app.logger.info(f"Client {request.sid} disconnected from WebSocket.")
    # Optional: Logic to stop the background thread if no clients are connected.
    # This example keeps the thread running to be immediately available for new connections.
    # If len(socketio.server.manager.rooms['/']['/']) == 0:
    #     app.logger.info("No more clients connected. Signalling background thread to stop.")
    #     thread_stop_event.set()
    #     global background_thread
    #     background_thread = None

# --- Main Application Entry Point ---
if __name__ == '__main__':
    app.logger.info("--- Starting SysAdmin Dashboard Application ---")
    app.logger.info(f"Access the dashboard at: http://127.0.0.1:{APP_PORT}")
    app.logger.info(f"Server is listening on: {APP_HOST}:{APP_PORT}")
    app.logger.info(f"Data stream interval set to: {STREAM_INTERVAL_SECONDS} seconds.")
    app.logger.info(f"Max processes displayed: {MAX_PROCESSES_TO_DISPLAY}")
    app.logger.info(f"Flask debug mode: {FLASK_DEBUG_MODE}")

    try:
        # Run the Flask application with SocketIO integration.
        # `socketio.run()` is used instead of `app.run()` when SocketIO is active.
        # `host='0.0.0.0'` makes the server accessible externally.
        # `allow_unsafe_werkzeug=True` might be needed if running in non-debug mode
        # but without a dedicated production WSGI server (like Gunicorn).
        # For production deployments, a proper WSGI server should be used.
        socketio.run(app, host=APP_HOST, port=APP_PORT, debug=FLASK_DEBUG_MODE, allow_unsafe_werkzeug=True)
    except KeyboardInterrupt:
        app.logger.info("Server is shutting down due to KeyboardInterrupt (Ctrl+C).")
    except Exception as e:
        app.logger.critical(f"An unexpected error occurred during server startup or execution: {e}", exc_info=True)
    finally:
        # Ensure the background thread is signaled to stop gracefully
        app.logger.info("Sending stop signal to background monitor thread...")
        thread_stop_event.set()
        # Give the eventlet-managed thread a moment to process the stop event and exit.
        # While eventlet handles greenlet stopping, a small sleep here ensures logs are
        # flushed or any final cleanup in the thread has a chance to occur.
        eventlet.sleep(STREAM_INTERVAL_SECONDS + 0.5)
        app.logger.info("Background thread termination signal sent and awaited.")

    app.logger.info("--- SysAdmin Dashboard Application Terminated ---")