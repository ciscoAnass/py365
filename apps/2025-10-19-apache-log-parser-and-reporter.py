import re
import sys
from collections import Counter
from datetime import datetime
from typing import List, Dict, Any
from http.server import HTTPServer, SimpleHTTPRequestHandler
import socket
import threading
import json

class ApacheLogParser:
    def __init__(self, log_file_path: str):
        self.log_file_path = log_file_path
        self.log_entries = []
        self.log_pattern = re.compile(
            r'(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d+) (\d+) "([^"]*)" "([^"]*)"'
        )

    def parse_log(self) -> None:
        try:
            with open(self.log_file_path, 'r') as log_file:
                for line in log_file:
                    match = self.log_pattern.match(line)
                    if match:
                        entry = {
                            'ip': match.group(1),
                            'timestamp': datetime.strptime(match.group(2), '%d/%b/%Y:%H:%M:%S %z'),
                            'method': match.group(3),
                            'path': match.group(4),
                            'status': int(match.group(5)),
                            'bytes': int(match.group(6)),
                            'referrer': match.group(7),
                            'user_agent': match.group(8)
                        }
                        self.log_entries.append(entry)
        except FileNotFoundError:
            print(f"Error: Log file {self.log_file_path} not found.")
            sys.exit(1)

    def get_top_pages(self, top_n: int = 10) -> List[Dict[str, Any]]:
        page_counts = Counter(entry['path'] for entry in self.log_entries)
        return [{'page': page, 'count': count} for page, count in page_counts.most_common(top_n)]

    def get_ip_request_counts(self, top_n: int = 10) -> List[Dict[str, Any]]:
        ip_counts = Counter(entry['ip'] for entry in self.log_entries)
        return [{'ip': ip, 'count': count} for ip, count in ip_counts.most_common(top_n)]

    def get_status_code_distribution(self) -> Dict[str, int]:
        status_groups = {
            '2xx': len([e for e in self.log_entries if 200 <= e['status'] < 300]),
            '4xx': len([e for e in self.log_entries if 400 <= e['status'] < 500]),
            '5xx': len([e for e in self.log_entries if 500 <= e['status'] < 600])
        }
        return status_groups

    def generate_report(self) -> Dict[str, Any]:
        return {
            'total_requests': len(self.log_entries),
            'top_pages': self.get_top_pages(),
            'top_ips': self.get_ip_request_counts(),
            'status_distribution': self.get_status_code_distribution()
        }

class LogReportHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(HTML_TEMPLATE.encode())
        elif self.path == '/report':
            parser = ApacheLogParser(LOG_FILE_PATH)
            parser.parse_log()
            report = parser.generate_report()
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(report, default=str).encode())

def start_server(port: int = 8000):
    server_address = ('', port)
    httpd = HTTPServer(server_address, LogReportHandler)
    print(f"Server running on http://localhost:{port}")
    httpd.serve_forever()

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Apache Log Report</title>
    <script>
        async function fetchReport() {
            const response = await fetch('/report');
            const data = await response.json();
            document.getElementById('report').innerHTML = `
                <h2>Log Report</h2>
                <p>Total Requests: ${data.total_requests}</p>
                
                <h3>Top 10 Pages</h3>
                <table>
                    ${data.top_pages.map(page => `
                        <tr>
                            <td>${page.page}</td>
                            <td>${page.count}</td>
                        </tr>
                    `).join('')}
                </table>
                
                <h3>Top 10 IPs</h3>
                <table>
                    ${data.top_ips.map(ip => `
                        <tr>
                            <td>${ip.ip}</td>
                            <td>${ip.count}</td>
                        </tr>
                    `).join('')}
                </table>
                
                <h3>Status Code Distribution</h3>
                <p>2xx: ${data.status_distribution['2xx']}</p>
                <p>4xx: ${data.status_distribution['4xx']}</p>
                <p>5xx: ${data.status_distribution['5xx']}</p>
            `;
        }
        fetchReport();
    </script>
</head>
<body>
    <div id="report">Loading...</div>
</body>
</html>
'''

LOG_FILE_PATH = '/var/log/apache2/access.log'  # Adjust path as needed

def main():
    start_server()

if __name__ == '__main__':
    main()