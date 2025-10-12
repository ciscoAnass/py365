import os
import sys
import json
import argparse
import requests
from typing import Dict, Optional, Any

class GitLabPipelineTrigger:
    def __init__(self, gitlab_url: str, project_id: int, token: str):
        self.gitlab_url = gitlab_url.rstrip('/')
        self.project_id = project_id
        self.token = token
        self.headers = {
            'Private-Token': self.token,
            'Content-Type': 'application/json'
        }

    def trigger_pipeline(self, ref: str, variables: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        Trigger a new pipeline for a specific branch/ref with optional variables
        """
        endpoint = f'{self.gitlab_url}/api/v4/projects/{self.project_id}/pipelines'
        payload = {
            'ref': ref,
            'variables': variables or []
        }

        try:
            response = requests.post(endpoint, headers=self.headers, json=payload)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error triggering pipeline: {e}")
            return {}

    def get_pipeline_status(self, pipeline_id: int) -> Dict[str, Any]:
        """
        Retrieve the status of a specific pipeline
        """
        endpoint = f'{self.gitlab_url}/api/v4/projects/{self.project_id}/pipelines/{pipeline_id}'
        
        try:
            response = requests.get(endpoint, headers=self.headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error retrieving pipeline status: {e}")
            return {}

    def wait_for_pipeline_completion(self, pipeline_id: int, timeout: int = 3600) -> bool:
        """
        Wait for a pipeline to complete with optional timeout
        """
        import time

        start_time = time.time()
        while time.time() - start_time < timeout:
            status = self.get_pipeline_status(pipeline_id)
            pipeline_state = status.get('status', '')

            if pipeline_state in ['success', 'failed', 'canceled']:
                return pipeline_state == 'success'
            
            time.sleep(10)  # Poll every 10 seconds
        
        return False

def main():
    parser = argparse.ArgumentParser(description='GitLab CI Pipeline Trigger')
    parser.add_argument('--url', required=True, help='GitLab instance URL')
    parser.add_argument('--project-id', type=int, required=True, help='GitLab Project ID')
    parser.add_argument('--token', required=True, help='GitLab Access Token')
    parser.add_argument('--ref', default='main', help='Branch or ref to trigger (default: main)')
    parser.add_argument('--wait', action='store_true', help='Wait for pipeline completion')
    parser.add_argument('--timeout', type=int, default=3600, help='Timeout for pipeline wait (seconds)')
    parser.add_argument('--var', nargs='+', help='Pipeline variables in KEY=VALUE format')

    args = parser.parse_args()

    # Process variables
    variables = {}
    if args.var:
        for var in args.var:
            key, value = var.split('=', 1)
            variables[key] = value

    # Initialize trigger
    trigger = GitLabPipelineTrigger(args.url, args.project_id, args.token)

    # Trigger pipeline
    result = trigger.trigger_pipeline(args.ref, variables)
    
    if not result:
        print("Failed to trigger pipeline")
        sys.exit(1)

    pipeline_id = result.get('id')
    print(f"Pipeline triggered: ID {pipeline_id}")

    # Optional wait for completion
    if args.wait:
        success = trigger.wait_for_pipeline_completion(pipeline_id, args.timeout)
        
        if success:
            print("Pipeline completed successfully")
            sys.exit(0)
        else:
            print("Pipeline did not complete successfully")
            sys.exit(1)

if __name__ == '__main__':
    main()