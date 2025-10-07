import docker
import time
import logging
import threading
import socket
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import json
import os
import sys
import signal
import queue
import sqlite3
import datetime
import uuid
import base64
import http.server
import socketserver
import urllib.parse

class DockerHealthMonitor:
    def __init__(self, poll_interval=30, smtp_config=None, alert_threshold=3):
        self.client = docker.from_env()
        self.poll_interval = poll_interval
        self.smtp_config = smtp_config or {}
        self.alert_threshold = alert_threshold
        self.health_log = {}
        self.alert_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.setup_logging()
        self.setup_database()

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s: %(message)s',
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler('docker_health_monitor.log')
            ]
        )
        self.logger = logging.getLogger(__name__)

    def setup_database(self):
        self.conn = sqlite3.connect('health_monitor.db', check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS container_health (
                id TEXT PRIMARY KEY,
                name TEXT,
                status TEXT,
                health_status TEXT,
                failure_count INTEGER,
                last_checked DATETIME
            )
        ''')
        self.conn.commit()

    def monitor_containers(self):
        while not self.stop_event.is_set():
            try:
                containers = self.client.containers.list()
                for container in containers:
                    self.check_container_health(container)
                time.sleep(self.poll_interval)
            except Exception as e:
                self.logger.error(f"Monitoring error: {e}")
                time.sleep(self.poll_interval)

    def check_container_health(self, container):
        try:
            container.reload()
            health_status = container.attrs.get('State', {}).get('Health', {}).get('Status', 'N/A')
            
            record = self.cursor.execute(
                'SELECT * FROM container_health WHERE id = ?', 
                (container.id,)
            ).fetchone()

            if not record:
                self.cursor.execute('''
                    INSERT INTO container_health 
                    (id, name, status, health_status, failure_count, last_checked)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    container.id, 
                    container.name, 
                    container.status, 
                    health_status, 
                    0, 
                    datetime.datetime.now()
                ))
                self.conn.commit()
                record = (container.id, container.name, container.status, health_status, 0, datetime.datetime.now())

            if health_status == 'unhealthy':
                failure_count = record[4] + 1
                self.cursor.execute('''
                    UPDATE container_health 
                    SET health_status = ?, failure_count = ?, last_checked = ?
                    WHERE id = ?
                ''', (health_status, failure_count, datetime.datetime.now(), container.id))
                self.conn.commit()

                if failure_count >= self.alert_threshold:
                    self.alert_queue.put({
                        'container_id': container.id,
                        'container_name': container.name,
                        'health_status': health_status,
                        'failure_count': failure_count
                    })

        except Exception as e:
            self.logger.error(f"Health check error for {container.name}: {e}")

    def send_email_alert(self, alert_data):
        try:
            msg = MIMEMultipart()
            msg['From'] = self.smtp_config.get('sender_email', 'monitor@example.com')
            msg['To'] = self.smtp_config.get('recipient_email', 'admin@example.com')
            msg['Subject'] = f"Docker Container Health Alert: {alert_data['container_name']}"
            
            body = f"""
            Container Health Alert:
            - Container ID: {alert_data['container_id']}
            - Container Name: {alert_data['container_name']}
            - Health Status: {alert_data['health_status']}
            - Failure Count: {alert_data['failure_count']}
            """
            msg.attach(MIMEText(body, 'plain'))

            server = smtplib.SMTP(
                self.smtp_config.get('smtp_server', 'localhost'), 
                self.smtp_config.get('smtp_port', 25)
            )
            server.starttls()
            server.login(
                self.smtp_config.get('username', ''), 
                self.smtp_config.get('password', '')
            )
            server.send_message(msg)
            server.quit()
        except Exception as e:
            self.logger.error(f"Email alert error: {e}")

    def alert_processor(self):
        while not self.stop_event.is_set():
            try:
                alert = self.alert_queue.get(timeout=5)
                self.send_email_alert(alert)
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Alert processing error: {e}")

    def start(self):
        monitor_thread = threading.Thread(target=self.monitor_containers)
        alert_thread = threading.Thread(target=self.alert_processor)
        
        monitor_thread.start()
        alert_thread.start()

        def signal_handler(signum, frame):
            self.stop_event.set()
            monitor_thread.join()
            alert_thread.join()
            self.conn.close()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        monitor_thread.join()
        alert_thread.join()

def main():
    smtp_config = {
        'smtp_server': 'smtp.gmail.com',
        'smtp_port': 587,
        'sender_email': 'your_email@gmail.com',
        'recipient_email': 'admin@example.com',
        'username': 'your_email@gmail.com',
        'password': 'your_app_password'
    }
    
    monitor = DockerHealthMonitor(
        poll_interval=30, 
        smtp_config=smtp_config, 
        alert_threshold=3
    )
    monitor.start()

if __name__ == "__main__":
    main()