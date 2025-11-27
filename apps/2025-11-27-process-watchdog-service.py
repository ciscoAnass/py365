import os
import sys
import time
import logging
import psutil
import signal
import subprocess
from datetime import datetime

# Set up logging
logging.basicConfig(filename='process_watchdog.log', level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

# List of critical processes to monitor
CRITICAL_PROCESSES = [
    {'name': 'nginx', 'pid': None},
    {'name': 'redis-server', 'pid': None},
    {'name': 'postgresql', 'pid': None},
    {'name': 'apache2', 'pid': None},
    {'name': 'mysql', 'pid': None},
]

def get_process_by_name(process_name):
    """
    Finds a process by its name and returns the process object.
    """
    for proc in psutil.process_iter(['name']):
        try:
            if proc.info['name'] == process_name:
                return proc
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return None

def get_process_by_pid(pid):
    """
    Finds a process by its PID and returns the process object.
    """
    try:
        return psutil.Process(pid)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None

def is_process_running(process):
    """
    Checks if a process is running.
    """
    try:
        return process.is_running()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return False

def restart_process(process):
    """
    Attempts to restart a process.
    """
    try:
        process.terminate()
        process.wait(timeout=5)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        logging.error(f"Failed to terminate process: {process.info['name']}")
        return False

    try:
        subprocess.Popen([sys.executable, os.path.abspath(sys.argv[0])])
        logging.info(f"Restarted process: {process.info['name']}")
        return True
    except Exception as e:
        logging.error(f"Failed to restart process: {process.info['name']} - {e}")
        return False

def monitor_processes():
    """
    Monitors the list of critical processes and restarts them if they are not running.
    """
    while True:
        for process_info in CRITICAL_PROCESSES:
            process_name = process_info['name']
            process_pid = process_info['pid']

            if process_pid is None:
                process = get_process_by_name(process_name)
                if process:
                    process_info['pid'] = process.pid
            else:
                process = get_process_by_pid(process_pid)

            if not process or not is_process_running(process):
                logging.error(f"Process '{process_name}' is not running. Attempting to restart.")
                if not restart_process(process):
                    logging.error(f"Failed to restart process: {process_name}")

        time.sleep(60)  # Check processes every minute

def signal_handler(sig, frame):
    """
    Handles the SIGINT (Ctrl+C) signal to gracefully stop the service.
    """
    logging.info("Received SIGINT, stopping process watchdog service...")
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    logging.info("Starting process watchdog service...")
    monitor_processes()