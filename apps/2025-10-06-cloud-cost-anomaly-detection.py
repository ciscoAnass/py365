import os
import sys
import json
import time
import boto3
import logging
import requests
import datetime
import statistics
from typing import Dict, List, Optional
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor

class CloudCostAnomalyDetector:
    def __init__(self, slack_webhook_url: str, aws_access_key: str, aws_secret_key: str):
        self.slack_webhook_url = slack_webhook_url
        self.aws_session = boto3.Session(
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name='us-east-1'
        )
        self.cost_explorer = self.aws_session.client('ce')
        self.logger = self._setup_logging()

    def _setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s: %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler('cloud_cost_anomaly.log')
            ]
        )
        return logging.getLogger(__name__)

    def fetch_daily_costs(self, days: int = 30) -> List[float]:
        end_date = datetime.date.today()
        start_date = end_date - datetime.timedelta(days=days)

        response = self.cost_explorer.get_cost_and_usage(
            TimePeriod={
                'Start': start_date.isoformat(),
                'End': end_date.isoformat()
            },
            Granularity='DAILY',
            Metrics=['UnblendedCost']
        )

        costs = [
            float(result['Total']['UnblendedCost']['Amount'])
            for result in response['ResultsByTime']
        ]
        return costs

    def detect_anomalies(self, costs: List[float], threshold_multiplier: float = 2.0) -> List[float]:
        if len(costs) < 7:
            return []

        mean_cost = statistics.mean(costs)
        std_dev = statistics.stdev(costs)
        anomaly_threshold = mean_cost + (std_dev * threshold_multiplier)

        anomalies = [
            cost for cost in costs 
            if cost > anomaly_threshold
        ]
        return anomalies

    def send_slack_alert(self, anomalies: List[float]):
        if not anomalies:
            return

        message = {
            "text": f"🚨 Cloud Cost Anomaly Detected! 🚨\n" +
                    f"Anomalous Costs: {[f'${cost:,.2f}' for cost in anomalies]}\n" +
                    f"Detected at: {datetime.datetime.now().isoformat()}"
        }

        try:
            response = requests.post(
                self.slack_webhook_url, 
                json=message,
                timeout=10
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Slack alert failed: {e}")

    def run_anomaly_detection(self):
        try:
            daily_costs = self.fetch_daily_costs()
            anomalies = self.detect_anomalies(daily_costs)
            
            if anomalies:
                self.logger.warning(f"Anomalies detected: {anomalies}")
                self.send_slack_alert(anomalies)
            else:
                self.logger.info("No cost anomalies detected.")
        
        except Exception as e:
            self.logger.error(f"Anomaly detection failed: {e}")

def main():
    slack_webhook = os.environ.get('SLACK_WEBHOOK_URL')
    aws_access_key = os.environ.get('AWS_ACCESS_KEY')
    aws_secret_key = os.environ.get('AWS_SECRET_KEY')

    if not all([slack_webhook, aws_access_key, aws_secret_key]):
        print("Missing environment variables. Set SLACK_WEBHOOK_URL, AWS_ACCESS_KEY, AWS_SECRET_KEY")
        sys.exit(1)

    detector = CloudCostAnomalyDetector(slack_webhook, aws_access_key, aws_secret_key)
    
    while True:
        detector.run_anomaly_detection()
        time.sleep(24 * 60 * 60)  # Run daily

if __name__ == "__main__":
    main()