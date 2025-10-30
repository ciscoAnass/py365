import os
import sys
import json
import requests
import argparse
import logging
from typing import Dict, List, Optional
from urllib.parse import urljoin

class GrafanaProvisioner:
    def __init__(self, grafana_url: str, api_key: str, log_level: str = 'INFO'):
        self.grafana_url = grafana_url.rstrip('/')
        self.headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
        logging.basicConfig(
            level=getattr(logging, log_level.upper()),
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def _api_request(self, method: str, endpoint: str, data: Optional[Dict] = None) -> requests.Response:
        url = urljoin(self.grafana_url, f'/api/{endpoint}')
        try:
            response = requests.request(method, url, headers=self.headers, json=data)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            self.logger.error(f"API Request Error: {e}")
            raise

    def create_datasource(self, datasource_config: Dict) -> Dict:
        try:
            response = self._api_request('POST', 'datasources', datasource_config)
            self.logger.info(f"Created datasource: {datasource_config.get('name', 'Unknown')}")
            return response.json()
        except Exception as e:
            self.logger.error(f"Datasource creation failed: {e}")
            raise

    def create_dashboard(self, dashboard_config: Dict) -> Dict:
        payload = {
            'dashboard': dashboard_config,
            'overwrite': True,
            'message': 'Dashboard provisioned via code'
        }
        try:
            response = self._api_request('POST', 'dashboards/db', payload)
            self.logger.info(f"Created/Updated dashboard: {dashboard_config.get('title', 'Unknown')}")
            return response.json()
        except Exception as e:
            self.logger.error(f"Dashboard creation failed: {e}")
            raise

    def list_datasources(self) -> List[Dict]:
        try:
            response = self._api_request('GET', 'datasources')
            return response.json()
        except Exception as e:
            self.logger.error(f"Failed to list datasources: {e}")
            raise

    def list_dashboards(self) -> List[Dict]:
        try:
            response = self._api_request('GET', 'search')
            return response.json()
        except Exception as e:
            self.logger.error(f"Failed to list dashboards: {e}")
            raise

def load_json_config(config_path: str) -> Dict:
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        logging.error(f"Configuration load error: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Grafana Dashboard Provisioner')
    parser.add_argument('--grafana-url', required=True, help='Grafana server URL')
    parser.add_argument('--api-key', required=True, help='Grafana API Key')
    parser.add_argument('--config', required=True, help='Path to JSON configuration file')
    parser.add_argument('--log-level', default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'])
    
    args = parser.parse_args()

    try:
        config = load_json_config(args.config)
        provisioner = GrafanaProvisioner(args.grafana_url, args.api_key, args.log_level)

        # Provision Datasources
        if 'datasources' in config:
            for datasource in config['datasources']:
                provisioner.create_datasource(datasource)

        # Provision Dashboards
        if 'dashboards' in config:
            for dashboard in config['dashboards']:
                provisioner.create_dashboard(dashboard)

        # Optional: List current state
        print("Current Datasources:")
        for ds in provisioner.list_datasources():
            print(f" - {ds['name']} ({ds['type']})")

        print("\nCurrent Dashboards:")
        for dash in provisioner.list_dashboards():
            print(f" - {dash['title']}")

    except Exception as e:
        logging.error(f"Provisioning failed: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()