import psutil
import time
import smtplib
import platform
import threading
import subprocess
import socket
import logging
import json
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any
from dataclasses import dataclass, asdict
import tkinter as tk
from tkinter import messagebox, ttk

@dataclass
class ResourceThresholds:
    cpu_threshold: float = 80.0
    memory_threshold: float = 85.0
    disk_threshold: float = 90.0
    network_threshold: float = 50.0
    duration_seconds: int = 300

class SystemResourceMonitor:
    def __init__(self, config_path: str = 'resource_monitor_config.json'):
        self.config_path = config_path
        self.thresholds = self._load_config()
        self.logger = self._setup_logging()
        self.alert_history = []
        self.stop_event = threading.Event()

    def _setup_logging(self) -> logging.Logger:
        logger = logging.getLogger('ResourceMonitor')
        logger.setLevel(logging.INFO)
        handler = logging.FileHandler('resource_monitor.log')
        formatter = logging.Formatter('%(asctime)s - %(levelname)s: %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

    def _load_config(self) -> ResourceThresholds:
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    config_data = json.load(f)
                    return ResourceThresholds(**config_data)
        except Exception as e:
            self.logger.warning(f"Config load failed: {e}")
        return ResourceThresholds()

    def _save_config(self):
        try:
            with open(self.config_path, 'w') as f:
                json.dump(asdict(self.thresholds), f, indent=4)
        except Exception as e:
            self.logger.error(f"Config save failed: {e}")

    def _send_email_alert(self, subject: str, body: str):
        try:
            msg = MIMEMultipart()
            msg['From'] = 'systemmonitor@localhost'
            msg['To'] = 'admin@localhost'
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))

            server = smtplib.SMTP('localhost', 25)
            server.send_message(msg)
            server.quit()
        except Exception as e:
            self.logger.error(f"Email alert failed: {e}")

    def _desktop_notification(self, title: str, message: str):
        system = platform.system()
        try:
            if system == "Darwin":
                subprocess.run(["osascript", "-e", f'display notification "{message}" with title "{title}"'])
            elif system == "Linux":
                subprocess.run(["notify-send", title, message])
            elif system == "Windows":
                subprocess.run(["powershell", "-Command", f'Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show("{message}", "{title}")'])
        except Exception as e:
            self.logger.error(f"Desktop notification failed: {e}")

    def monitor_resources(self):
        while not self.stop_event.is_set():
            metrics = {
                'cpu_usage': psutil.cpu_percent(),
                'memory_usage': psutil.virtual_memory().percent,
                'disk_usage': psutil.disk_usage('/').percent,
                'network_usage': self._get_network_usage()
            }

            self._check_and_alert(metrics)
            time.sleep(60)

    def _get_network_usage(self) -> float:
        try:
            net_io = psutil.net_io_counters()
            return (net_io.bytes_sent + net_io.bytes_recv) / 1024 / 1024  # MB
        except Exception:
            return 0.0

    def _check_and_alert(self, metrics: Dict[str, float]):
        alerts = []
        if metrics['cpu_usage'] > self.thresholds.cpu_threshold:
            alerts.append(f"High CPU Usage: {metrics['cpu_usage']}%")
        if metrics['memory_usage'] > self.thresholds.memory_threshold:
            alerts.append(f"High Memory Usage: {metrics['memory_usage']}%")
        if metrics['disk_usage'] > self.thresholds.disk_threshold:
            alerts.append(f"High Disk Usage: {metrics['disk_usage']}%")

        if alerts:
            alert_message = "\n".join(alerts)
            self.logger.warning(alert_message)
            self._send_email_alert("System Resource Alert", alert_message)
            self._desktop_notification("Resource Monitor", alert_message)
            self.alert_history.append({
                'timestamp': time.time(),
                'metrics': metrics,
                'alerts': alerts
            })

    def start_monitoring(self):
        monitor_thread = threading.Thread(target=self.monitor_resources)
        monitor_thread.start()
        return monitor_thread

    def stop_monitoring(self):
        self.stop_event.set()

class ResourceMonitorGUI:
    def __init__(self, monitor: SystemResourceMonitor):
        self.monitor = monitor
        self.root = tk.Tk()
        self.root.title("System Resource Monitor")
        self.root.geometry("600x500")
        self._create_widgets()

    def _create_widgets(self):
        notebook = ttk.Notebook(self.root)
        notebook.pack(expand=True, fill='both', padx=10, pady=10)

        monitor_frame = ttk.Frame(notebook)
        config_frame = ttk.Frame(notebook)
        history_frame = ttk.Frame(notebook)

        notebook.add(monitor_frame, text="Monitor")
        notebook.add(config_frame, text="Configuration")
        notebook.add(history_frame, text="Alert History")

        self._setup_monitor_frame(monitor_frame)
        self._setup_config_frame(config_frame)
        self._setup_history_frame(history_frame)

    def _setup_monitor_frame(self, frame):
        # Real-time metrics display logic here
        pass

    def _setup_config_frame(self, frame):
        # Configuration update widgets
        pass

    def _setup_history_frame(self, frame):
        # Alert history display logic
        pass

def main():
    monitor = SystemResourceMonitor()
    monitor_thread = monitor.start_monitoring()
    
    gui = ResourceMonitorGUI(monitor)
    gui.root.mainloop()

    monitor.stop_monitoring()
    monitor_thread.join()

if __name__ == "__main__":
    main()