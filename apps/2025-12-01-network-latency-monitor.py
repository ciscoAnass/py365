import os
import time
import logging
import subprocess
import threading
import smtplib
from email.mime.text import MIMEText
from datetime import datetime

# Third-party libraries:
# - 'ping3' library for cross-platform ping functionality
# - 'tabulate' library for formatting output tables
import ping3
from tabulate import tabulate

# Set up logging
logging.basicConfig(filename='network_latency_monitor.log', level=logging.INFO,
                    format='%(asctime)s %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

# Configuration
CRITICAL_ENDPOINTS = ['8.8.8.8', '1.1.1.1', 'example.com', '192.168.1.1']
LATENCY_THRESHOLD = 100  # milliseconds
ALERT_INTERVAL = 60  # seconds
PING_INTERVAL = 10  # seconds
ALERT_EMAIL_RECIPIENTS = ['admin@example.com']
ALERT_EMAIL_SENDER = 'network-monitor@example.com'
ALERT_EMAIL_SUBJECT = 'Network Latency Alert'

# Global variables
latency_data = {}
packet_loss_data = {}
alert_triggered = False

def ping_endpoint(endpoint):
    """
    Ping an endpoint and return the latency (RTT) and packet loss.
    """
    try:
        latency = ping3.ping(endpoint, unit='ms')
        if latency is None:
            packet_loss = 100.0
        else:
            packet_loss = 0.0
        return latency, packet_loss
    except Exception as e:
        logging.error(f"Error pinging {endpoint}: {e}")
        return None, 100.0

def monitor_endpoints():
    """
    Continuously monitor the critical endpoints and update the latency and packet loss data.
    """
    while True:
        for endpoint in CRITICAL_ENDPOINTS:
            latency, packet_loss = ping_endpoint(endpoint)
            if latency is not None:
                latency_data[endpoint] = latency
                packet_loss_data[endpoint] = packet_loss
        time.sleep(PING_INTERVAL)

def check_for_alerts():
    """
    Check the latency data and trigger an alert if the latency exceeds the threshold.
    """
    global alert_triggered
    while True:
        for endpoint, latency in latency_data.items():
            if latency > LATENCY_THRESHOLD and not alert_triggered:
                send_alert(endpoint, latency)
                alert_triggered = True
        if alert_triggered:
            time.sleep(ALERT_INTERVAL)
            alert_triggered = False

def send_alert(endpoint, latency):
    """
    Send an alert email to the specified recipients.
    """
    message = f"Alert: Latency for {endpoint} exceeded {LATENCY_THRESHOLD}ms. Current latency: {latency}ms."
    msg = MIMEText(message)
    msg['Subject'] = ALERT_EMAIL_SUBJECT
    msg['From'] = ALERT_EMAIL_SENDER
    msg['To'] = ', '.join(ALERT_EMAIL_RECIPIENTS)

    with smtplib.SMTP('localhost') as smtp:
        smtp.send_message(msg)

    logging.info(f"Alert sent: {message}")

def print_status():
    """
    Print the current latency and packet loss data in a formatted table.
    """
    headers = ['Endpoint', 'Latency (ms)', 'Packet Loss (%)']
    data = []
    for endpoint, latency in latency_data.items():
        packet_loss = packet_loss_data[endpoint]
        data.append([endpoint, latency, packet_loss])
    print(tabulate(data, headers=headers))

def main():
    """
    Main function to run the network latency monitor.
    """
    logging.info("Network Latency Monitor started.")

    # Start the monitoring threads
    monitor_thread = threading.Thread(target=monitor_endpoints)
    alert_thread = threading.Thread(target=check_for_alerts)
    monitor_thread.start()
    alert_thread.start()

    try:
        while True:
            print_status()
            time.sleep(10)
    except KeyboardInterrupt:
        logging.info("Network Latency Monitor stopped.")

if __name__ == "__main__":
    main()