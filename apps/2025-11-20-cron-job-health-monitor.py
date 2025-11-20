import os
import sys
import smtplib
import time
import logging
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from functools import wraps

# Optional 3rd party library: pagerduty-api-python-client
# https://github.com/PagerDuty/pagerduty-api-python-client
try:
    import pypd
except ImportError:
    pypd = None

# Configure logging
logging.basicConfig(
    filename='cron_job_health_monitor.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Email configuration
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
SMTP_USERNAME = 'your_email@gmail.com'
SMTP_PASSWORD = 'your_password'
RECIPIENT_EMAIL = 'sysadmin@company.com'
SENDER_EMAIL = 'cron_job_monitor@company.com'
SUBJECT = 'Cron Job Failure Alert'

# PagerDuty configuration (optional)
PAGERDUTY_API_KEY = 'your_pagerduty_api_key'
PAGERDUTY_SERVICE_ID = 'your_pagerduty_service_id'

def send_email(subject, body):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = SENDER_EMAIL
    msg['To'] = RECIPIENT_EMAIL

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as smtp:
        smtp.starttls()
        smtp.login(SMTP_USERNAME, SMTP_PASSWORD)
        smtp.send_message(msg)

def send_pagerduty_alert(subject, body):
    if pypd:
        incident = pypd.Incident.create(
            type='trigger',
            title=subject,
            body=body,
            service_id=PAGERDUTY_SERVICE_ID
        )
        logging.info(f'PagerDuty alert created: {incident.id}')
    else:
        logging.error('PagerDuty library not installed. Unable to send alert.')

def cron_job_wrapper(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logging.error(f'Cron job failed: {e}')
            send_email(SUBJECT, f'Cron job failed: {e}')
            if pypd:
                send_pagerduty_alert(SUBJECT, f'Cron job failed: {e}')
            return 1
    return wrapper

@cron_job_wrapper
def run_cron_job():
    # Your cron job code goes here
    # Example:
    print('Cron job running...')
    time.sleep(5)  # Simulating job execution
    print('Cron job completed successfully.')
    return 0

def check_job_history():
    log_file = 'cron_job_health_monitor.log'
    if not os.path.exists(log_file):
        logging.info('No log file found. Skipping job history check.')
        return

    with open(log_file, 'r') as f:
        lines = f.readlines()

    failures = 0
    last_success = None
    for line in lines[::-1]:
        if 'INFO: Cron job running...' in line:
            last_success = datetime.strptime(line.split()[0], '%Y-%m-%d')
            break
        elif 'ERROR: Cron job failed:' in line:
            failures += 1

    if failures > 0:
        logging.warning(f'Cron job has failed {failures} times in the last 24 hours.')
        if last_success and last_success < datetime.now() - timedelta(days=1):
            logging.error('Cron job has not run successfully in the last 24 hours.')
            send_email(SUBJECT, 'Cron job has not run successfully in the last 24 hours.')
            if pypd:
                send_pagerduty_alert(SUBJECT, 'Cron job has not run successfully in the last 24 hours.')

def main():
    run_cron_job()
    check_job_history()

if __name__ == '__main__':
    main()