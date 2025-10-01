import os
import time
import random
import threading
import logging
from typing import Dict, Any
from http.server import HTTPServer, BaseHTTPRequestHandler
from prometheus_client import start_http_server, Gauge, Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

class ApplicationMetrics:
    def __init__(self):
        self.active_users = Gauge('app_active_users', 'Number of currently active users')
        self.user_logins = Counter('app_user_logins_total', 'Total number of user logins')
        self.request_duration = Histogram('app_request_duration_seconds', 'Request processing duration', 
                                          buckets=[0.1, 0.5, 1, 2, 5, 10])
        self.queue_size = Gauge('app_task_queue_size', 'Current number of tasks in processing queue')
        self.error_count = Counter('app_errors_total', 'Total number of application errors')
        
class MockApplicationSimulator:
    def __init__(self, metrics: ApplicationMetrics):
        self.metrics = metrics
        self.running = True
        
    def simulate_metrics(self):
        while self.running:
            # Simulate active users
            active_users = random.randint(10, 250)
            self.metrics.active_users.set(active_users)
            
            # Simulate user logins
            login_count = random.randint(1, 20)
            for _ in range(login_count):
                self.metrics.user_logins.inc()
            
            # Simulate request durations
            for _ in range(50):
                with self.metrics.request_duration.time():
                    time.sleep(random.uniform(0.01, 1.5))
            
            # Simulate queue size
            queue_size = random.randint(0, 100)
            self.metrics.queue_size.set(queue_size)
            
            # Simulate occasional errors
            if random.random() < 0.1:
                self.metrics.error_count.inc()
            
            time.sleep(5)
            
    def start(self):
        thread = threading.Thread(target=self.simulate_metrics)
        thread.daemon = True
        thread.start()
        
    def stop(self):
        self.running = False

class PrometheusExporterHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, metrics=None, **kwargs):
        self.metrics = metrics
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        if self.path == '/metrics':
            self.send_response(200)
            self.send_header('Content-Type', CONTENT_TYPE_LATEST)
            self.end_headers()
            self.wfile.write(generate_latest())
        elif self.path == '/':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(self._generate_dashboard().encode())
        else:
            self.send_error(404)
    
    def _generate_dashboard(self) -> str:
        return f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Custom Prometheus Exporter Dashboard</title>
            <style>
                body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }}
                h1 {{ color: #333; }}
                .metric {{ margin-bottom: 10px; padding: 10px; background-color: #f4f4f4; }}
            </style>
        </head>
        <body>
            <h1>Application Metrics Dashboard</h1>
            <div class="metric">
                <h2>Metrics Overview</h2>
                <p>Metrics are being exported to Prometheus at <code>/metrics</code> endpoint.</p>
                <p>Simulated metrics include: Active Users, User Logins, Request Durations, Task Queue Size, and Error Counts.</p>
            </div>
        </body>
        </html>
        '''

def create_metrics_server(metrics: ApplicationMetrics, port: int = 8000):
    def handler(*args, **kwargs):
        return PrometheusExporterHandler(*args, metrics=metrics, **kwargs)
    
    server = HTTPServer(('0.0.0.0', port), handler)
    print(f"Metrics server running on port {port}")
    server.serve_forever()

def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s')
    
    # Initialize metrics
    metrics = ApplicationMetrics()
    
    # Start mock application simulator
    simulator = MockApplicationSimulator(metrics)
    simulator.start()
    
    # Start Prometheus metrics endpoint
    start_http_server(9090)  # Default Prometheus metrics port
    
    # Start custom metrics web server
    create_metrics_server(metrics)

if __name__ == '__main__':
    main()