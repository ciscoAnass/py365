import ssl
import socket
import datetime
import smtplib
import json
import os
import sys
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Dict, Optional
import requests
import OpenSSL
import cryptography
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

class CertificateChecker:
    def __init__(self, config_path: str = 'config.json'):
        self.config = self._load_config(config_path)
        self.logger = self._setup_logging()

    def _load_config(self, config_path: str) -> Dict:
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {
                'domains': ['example.com', 'google.com'],
                'expiry_threshold_days': 30,
                'notification_method': 'email',
                'email_config': {
                    'smtp_server': 'smtp.gmail.com',
                    'smtp_port': 587,
                    'sender_email': 'your_email@gmail.com',
                    'sender_password': 'your_app_password',
                    'recipient_email': 'recipient@example.com'
                },
                'slack_webhook_url': 'https://hooks.slack.com/services/your_webhook_url'
            }

    def _setup_logging(self) -> logging.Logger:
        logger = logging.getLogger('CertificateChecker')
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

    def check_certificate(self, domain: str) -> Optional[datetime.datetime]:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                    cert = secure_sock.getpeercert(binary_form=True)
                    x509_cert = x509.load_der_x509_certificate(cert)
                    return x509_cert.not_valid_after
        except Exception as e:
            self.logger.error(f"Error checking certificate for {domain}: {e}")
            return None

    def _days_until_expiry(self, expiry_date: datetime.datetime) -> int:
        return (expiry_date - datetime.datetime.now(expiry_date.tzinfo)).days

    def _send_email_notification(self, domain: str, days_left: int):
        config = self.config['email_config']
        msg = MIMEMultipart()
        msg['From'] = config['sender_email']
        msg['To'] = config['recipient_email']
        msg['Subject'] = f"SSL Certificate Expiring: {domain}"
        
        body = f"The SSL certificate for {domain} will expire in {days_left} days."
        msg.attach(MIMEText(body, 'plain'))

        try:
            server = smtplib.SMTP(config['smtp_server'], config['smtp_port'])
            server.starttls()
            server.login(config['sender_email'], config['sender_password'])
            server.send_message(msg)
            server.quit()
            self.logger.info(f"Email notification sent for {domain}")
        except Exception as e:
            self.logger.error(f"Failed to send email: {e}")

    def _send_slack_notification(self, domain: str, days_left: int):
        webhook_url = self.config.get('slack_webhook_url')
        if not webhook_url:
            self.logger.warning("No Slack webhook URL configured")
            return

        payload = {
            'text': f"⚠️ SSL Certificate Alert: {domain} expires in {days_left} days"
        }

        try:
            response = requests.post(webhook_url, json=payload)
            if response.status_code == 200:
                self.logger.info(f"Slack notification sent for {domain}")
            else:
                self.logger.error(f"Failed to send Slack notification: {response.text}")
        except Exception as e:
            self.logger.error(f"Slack notification error: {e}")

    def run_check(self):
        domains = self.config.get('domains', [])
        threshold = self.config.get('expiry_threshold_days', 30)
        notification_method = self.config.get('notification_method', 'email')

        for domain in domains:
            expiry_date = self.check_certificate(domain)
            if expiry_date:
                days_left = self._days_until_expiry(expiry_date)
                self.logger.info(f"{domain} certificate expires on {expiry_date}, {days_left} days remaining")

                if days_left <= threshold:
                    if notification_method == 'email':
                        self._send_email_notification(domain, days_left)
                    elif notification_method == 'slack':
                        self._send_slack_notification(domain, days_left)
                    else:
                        self.logger.warning(f"Unsupported notification method: {notification_method}")

def main():
    checker = CertificateChecker()
    checker.run_check()

if __name__ == "__main__":
    main()