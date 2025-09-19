import os
import re
import sys
import json
import smtplib
import socket
import logging
import hashlib
import datetime
import statistics
import email.mime.text
import email.mime.multipart
from typing import List, Dict, Any
from collections import defaultdict
from email.mime.text import MIMEText

class LogAnomalyDetector:
    def __init__(self, log_path: str, config_path: str = None):
        self.log_path = log_path
        self.config = self._load_config(config_path)
        self.logger = self._setup_logging()
        self.anomalies = []

    def _load_config(self, config_path: str = None) -> Dict[str, Any]:
        default_config = {
            "log_type": "syslog",
            "anomaly_threshold": 2.5,
            "alert_email": "admin@example.com",
            "smtp_server": "localhost",
            "smtp_port": 25,
            "ip_whitelist": ["127.0.0.1", "::1"],
            "error_patterns": [
                r"error",
                r"critical",
                r"fatal",
                r"warning"
            ]
        }

        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
            except Exception as e:
                print(f"Error loading config: {e}")

        return default_config

    def _setup_logging(self) -> logging.Logger:
        logger = logging.getLogger('LogAnomalyDetector')
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

    def _parse_log_line(self, line: str) -> Dict[str, Any]:
        try:
            if self.config['log_type'] == 'syslog':
                match = re.match(r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\w+):\s+(.+)', line)
                if match:
                    return {
                        'timestamp': match.group(1),
                        'host': match.group(2),
                        'severity': match.group(3),
                        'message': match.group(4)
                    }
            elif self.config['log_type'] == 'apache':
                match = re.match(r'(\S+) (\S+) (\S+) \[([^\]]+)\] "(\w+) (\S+) \S+" (\d+) (\d+)', line)
                if match:
                    return {
                        'ip': match.group(1),
                        'identity': match.group(2),
                        'user': match.group(3),
                        'timestamp': match.group(4),
                        'method': match.group(5),
                        'path': match.group(6),
                        'status': int(match.group(7)),
                        'size': int(match.group(8))
                    }
        except Exception as e:
            self.logger.error(f"Error parsing log line: {e}")
        return {}

    def detect_anomalies(self) -> List[Dict[str, Any]]:
        log_entries = defaultdict(list)
        ip_counts = defaultdict(int)
        error_counts = defaultdict(int)

        with open(self.log_path, 'r') as log_file:
            for line in log_file:
                entry = self._parse_log_line(line)
                if not entry:
                    continue

                if 'ip' in entry and entry['ip'] not in self.config['ip_whitelist']:
                    ip_counts[entry['ip']] += 1

                if 'message' in entry:
                    for pattern in self.config['error_patterns']:
                        if re.search(pattern, entry['message'], re.IGNORECASE):
                            error_counts[pattern] += 1

        # Statistical anomaly detection
        ip_mean = statistics.mean(ip_counts.values()) if ip_counts else 0
        ip_stdev = statistics.stdev(ip_counts.values()) if len(ip_counts) > 1 else 0
        error_mean = statistics.mean(error_counts.values()) if error_counts else 0
        error_stdev = statistics.stdev(error_counts.values()) if len(error_counts) > 1 else 0

        for ip, count in ip_counts.items():
            if ip_stdev > 0 and abs(count - ip_mean) > self.config['anomaly_threshold'] * ip_stdev:
                self.anomalies.append({
                    'type': 'ip_anomaly',
                    'ip': ip,
                    'count': count,
                    'mean': ip_mean,
                    'stdev': ip_stdev
                })

        for pattern, count in error_counts.items():
            if error_stdev > 0 and abs(count - error_mean) > self.config['anomaly_threshold'] * error_stdev:
                self.anomalies.append({
                    'type': 'error_anomaly',
                    'pattern': pattern,
                    'count': count,
                    'mean': error_mean,
                    'stdev': error_stdev
                })

        return self.anomalies

    def send_alert_email(self):
        if not self.anomalies:
            return

        try:
            msg = email.mime.multipart.MIMEMultipart()
            msg['From'] = f"LogAnomalyDetector <{socket.gethostname()}>"
            msg['To'] = self.config['alert_email']
            msg['Subject'] = f"Log Anomaly Alert - {datetime.datetime.now()}"

            body = "Anomalies Detected:\n\n"
            for anomaly in self.anomalies:
                body += json.dumps(anomaly, indent=2) + "\n\n"

            msg.attach(MIMEText(body, 'plain'))

            with smtplib.SMTP(self.config['smtp_server'], self.config['smtp_port']) as server:
                server.sendmail(msg['From'], msg['To'], msg.as_string())
                self.logger.info("Alert email sent successfully")

        except Exception as e:
            self.logger.error(f"Failed to send alert email: {e}")

def main():
    log_path = sys.argv[1] if len(sys.argv) > 1 else '/var/log/syslog'
    detector = LogAnomalyDetector(log_path)
    anomalies = detector.detect_anomalies()
    
    if anomalies:
        print(json.dumps(anomalies, indent=2))
        detector.send_alert_email()

if __name__ == "__main__":
    main()