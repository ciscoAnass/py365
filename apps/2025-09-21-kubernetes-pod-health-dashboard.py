import os
import base64
from typing import List, Dict, Any
from kubernetes import client, config
from flask import Flask, render_template_string, jsonify
from threading import Thread
import time

app = Flask(__name__)

DASHBOARD_HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Kubernetes Pod Health Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; background-color: #f4f4f4; }
        h1 { color: #333; text-align: center; }
        table { width: 100%; border-collapse: collapse; background-color: white; box-shadow: 0 2px 3px rgba(0,0,0,0.1); }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #f8f8f8; font-weight: bold; }
        .pod-status { padding: 5px 10px; border-radius: 4px; font-weight: bold; }
        .running { background-color: #4CAF50; color: white; }
        .error { background-color: #F44336; color: white; }
        .pending { background-color: #FF9800; color: white; }
        #last-updated { text-align: right; color: #666; font-size: 0.8em; }
    </style>
</head>
<body>
    <h1>Kubernetes Pod Health Dashboard</h1>
    <div id="last-updated"></div>
    <table id="pods-table">
        <thead>
            <tr>
                <th>Namespace</th>
                <th>Pod Name</th>
                <th>Status</th>
                <th>Restart Count</th>
                <th>Age</th>
                <th>Node</th>
            </tr>
        </thead>
        <tbody id="pods-body">
        </tbody>
    </table>

    <script>
        function updatePods() {
            fetch('/pods')
                .then(response => response.json())
                .then(data => {
                    const podsBody = document.getElementById('pods-body');
                    const lastUpdated = document.getElementById('last-updated');
                    podsBody.innerHTML = '';
                    
                    data.pods.forEach(pod => {
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td>${pod.namespace}</td>
                            <td>${pod.name}</td>
                            <td>
                                <span class="pod-status ${pod.status.toLowerCase()}">${pod.status}</span>
                            </td>
                            <td>${pod.restart_count}</td>
                            <td>${pod.age}</td>
                            <td>${pod.node}</td>
                        `;
                        podsBody.appendChild(row);
                    });

                    lastUpdated.textContent = `Last Updated: ${new Date().toLocaleString()}`;
                });
        }

        updatePods();
        setInterval(updatePods, 5000);
    </script>
</body>
</html>
'''

def get_kubernetes_pods(namespace: str = 'default') -> List[Dict[str, Any]]:
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()

    v1 = client.CoreV1Api()
    pods = v1.list_namespaced_pod(namespace)
    
    pod_details = []
    for pod in pods.items:
        status = pod.status.phase
        restart_count = sum(container.restart_count for container in pod.status.container_statuses or [])
        
        pod_details.append({
            'namespace': pod.metadata.namespace,
            'name': pod.metadata.name,
            'status': status,
            'restart_count': restart_count,
            'age': str(time.time() - pod.metadata.creation_timestamp.timestamp())[:5] + 's',
            'node': pod.spec.node_name or 'Unknown'
        })
    
    return pod_details

@app.route('/')
def dashboard():
    return render_template_string(DASHBOARD_HTML)

@app.route('/pods')
def get_pods():
    pods = get_kubernetes_pods()
    return jsonify({'pods': pods})

def run_flask_app():
    app.run(host='0.0.0.0', port=8080)

if __name__ == '__main__':
    run_flask_app()