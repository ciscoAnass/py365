import os
import sys
import json
import base64
import datetime
import argparse
import threading
import subprocess
import http.server
import socketserver
from typing import List, Dict, Optional
from dataclasses import dataclass
from urllib.request import urlopen, Request
from urllib.error import URLError

@dataclass
class WorkflowRun:
    id: int
    name: str
    status: str
    conclusion: str
    created_at: str
    updated_at: str
    branch: str
    duration: float
    html_url: str

class GitHubActionMonitor:
    def __init__(self, token: str, repo: str):
        self.token = token
        self.repo = repo
        self.base_url = f"https://api.github.com/repos/{repo}"
        self.headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json"
        }

    def _make_request(self, endpoint: str) -> Dict:
        try:
            req = Request(f"{self.base_url}{endpoint}", headers=self.headers)
            with urlopen(req) as response:
                return json.loads(response.read().decode())
        except URLError as e:
            print(f"Error fetching data: {e}")
            return {}

    def get_workflow_runs(self, branch: Optional[str] = None, workflow_name: Optional[str] = None) -> List[WorkflowRun]:
        endpoint = "/actions/runs"
        if branch:
            endpoint += f"?branch={branch}"

        runs_data = self._make_request(endpoint)
        workflow_runs = []

        for run in runs_data.get('workflow_runs', []):
            if workflow_name and workflow_name.lower() not in run['name'].lower():
                continue

            created = datetime.datetime.fromisoformat(run['created_at'].replace('Z', '+00:00'))
            updated = datetime.datetime.fromisoformat(run['updated_at'].replace('Z', '+00:00'))
            duration = (updated - created).total_seconds()

            workflow_run = WorkflowRun(
                id=run['id'],
                name=run['name'],
                status=run['status'],
                conclusion=run['conclusion'] or 'N/A',
                created_at=run['created_at'],
                updated_at=run['updated_at'],
                branch=run['head_branch'],
                duration=duration,
                html_url=run['html_url']
            )
            workflow_runs.append(workflow_run)

        return workflow_runs

    def render_html(self, workflow_runs: List[WorkflowRun]) -> str:
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>GitHub Actions Monitor</title>
            <style>
                body { font-family: Arial, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }
                table { width: 100%; border-collapse: collapse; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                .success { background-color: #d4edda; }
                .failure { background-color: #f8d7da; }
                .pending { background-color: #fff3cd; }
            </style>
        </head>
        <body>
            <h1>GitHub Actions Workflow Runs</h1>
            <table>
                <thead>
                    <tr>
                        <th>Workflow Name</th>
                        <th>Branch</th>
                        <th>Status</th>
                        <th>Conclusion</th>
                        <th>Duration (s)</th>
                        <th>Created At</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </body>
        </html>
        """

        rows = []
        for run in workflow_runs:
            status_class = 'success' if run.conclusion == 'success' else \
                           'failure' if run.conclusion == 'failure' else 'pending'
            row = f"""
            <tr class="{status_class}">
                <td>{run.name}</td>
                <td>{run.branch}</td>
                <td>{run.status}</td>
                <td>{run.conclusion}</td>
                <td>{run.duration:.2f}</td>
                <td>{run.created_at}</td>
                <td><a href="{run.html_url}" target="_blank">View</a></td>
            </tr>
            """
            rows.append(row)

        return html_template.format(rows=''.join(rows))

    def start_web_server(self, workflow_runs: List[WorkflowRun], port: int = 8080):
        class RequestHandler(http.server.SimpleHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                html_content = self.server.workflow_runs_html
                self.wfile.write(html_content.encode())

        class CustomServer(socketserver.TCPServer):
            def __init__(self, *args, **kwargs):
                self.workflow_runs_html = kwargs.pop('workflow_runs_html')
                super().__init__(*args, **kwargs)

        html_content = self.render_html(workflow_runs)
        server = CustomServer(("", port), RequestHandler, workflow_runs_html=html_content.encode())
        print(f"Serving workflow runs at http://localhost:{port}")
        server.serve_forever()

def main():
    parser = argparse.ArgumentParser(description="GitHub Actions Workflow Monitor")
    parser.add_argument("--token", required=True, help="GitHub Personal Access Token")
    parser.add_argument("--repo", required=True, help="Repository in format owner/repo")
    parser.add_argument("--branch", help="Filter by branch name")
    parser.add_argument("--workflow", help="Filter by workflow name")
    parser.add_argument("--web", action="store_true", help="Start web server")
    parser.add_argument("--port", type=int, default=8080, help="Web server port")
    args = parser.parse_args()

    monitor = GitHubActionMonitor(args.token, args.repo)
    workflow_runs = monitor.get_workflow_runs(branch=args.branch, workflow_name=args.workflow)

    if args.web:
        monitor.start_web_server(workflow_runs, port=args.port)
    else:
        for run in workflow_runs:
            print(f"{run.name} | {run.branch} | {run.status} | {run.conclusion} | {run.duration:.2f}s")

if __name__ == "__main__":
    main()