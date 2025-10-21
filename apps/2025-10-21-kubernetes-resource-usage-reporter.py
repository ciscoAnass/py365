import os
import sys
import csv
import json
import argparse
from datetime import datetime
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from tabulate import tabulate

class KubernetesResourceReporter:
    def __init__(self, namespace=None, output_format='table', output_file=None):
        self.namespace = namespace
        self.output_format = output_format
        self.output_file = output_file
        
        try:
            config.load_kube_config()
        except config.ConfigException:
            try:
                config.load_incluster_config()
            except config.ConfigException:
                print("Could not load Kubernetes configuration. Ensure you're in a cluster or have kubeconfig.")
                sys.exit(1)
        
        self.core_api = client.CoreV1Api()
        self.metrics_api = client.CustomObjectsApi()

    def get_node_metrics(self):
        try:
            node_metrics = self.metrics_api.list_cluster_custom_object(
                "metrics.k8s.io", "v1beta1", "nodes"
            )
            return {item['metadata']['name']: item['usage'] for item in node_metrics.get('items', [])}
        except ApiException as e:
            print(f"Error fetching node metrics: {e}")
            return {}

    def get_pod_metrics(self):
        try:
            pod_metrics = self.metrics_api.list_namespaced_custom_object(
                "metrics.k8s.io", "v1beta1", self.namespace or "default", "pods"
            )
            return {
                item['metadata']['name']: {
                    'namespace': item['metadata']['namespace'],
                    'cpu': item['containers'][0]['usage']['cpu'],
                    'memory': item['containers'][0]['usage']['memory']
                } for item in pod_metrics.get('items', [])
            }
        except ApiException as e:
            print(f"Error fetching pod metrics: {e}")
            return {}

    def generate_report(self):
        node_metrics = self.get_node_metrics()
        pod_metrics = self.get_pod_metrics()

        node_data = []
        for node in self.core_api.list_node().items:
            node_name = node.metadata.name
            node_usage = node_metrics.get(node_name, {})
            node_data.append([
                node_name,
                node.status.capacity.get('cpu', 'N/A'),
                node.status.capacity.get('memory', 'N/A'),
                node_usage.get('cpu', 'N/A'),
                node_usage.get('memory', 'N/A')
            ])

        pod_data = []
        for pod in self.core_api.list_namespaced_pod(namespace=self.namespace or "default").items:
            pod_name = pod.metadata.name
            pod_metrics_data = pod_metrics.get(pod_name, {})
            pod_data.append([
                pod_name,
                pod.metadata.namespace,
                pod.status.phase,
                pod_metrics_data.get('cpu', 'N/A'),
                pod_metrics_data.get('memory', 'N/A')
            ])

        return node_data, pod_data

    def output_report(self, node_data, pod_data):
        headers_nodes = ['Node', 'CPU Capacity', 'Memory Capacity', 'CPU Usage', 'Memory Usage']
        headers_pods = ['Pod', 'Namespace', 'Status', 'CPU Usage', 'Memory Usage']

        if self.output_format == 'table':
            print("\nNode Resource Usage:")
            print(tabulate(node_data, headers=headers_nodes, tablefmt='grid'))
            print("\nPod Resource Usage:")
            print(tabulate(pod_data, headers=headers_pods, tablefmt='grid'))
        
        elif self.output_format == 'csv':
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            node_filename = f"node_metrics_{timestamp}.csv"
            pod_filename = f"pod_metrics_{timestamp}.csv"

            with open(node_filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(headers_nodes)
                writer.writerows(node_data)

            with open(pod_filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(headers_pods)
                writer.writerows(pod_data)

            print(f"Node metrics saved to {node_filename}")
            print(f"Pod metrics saved to {pod_filename}")

def main():
    parser = argparse.ArgumentParser(description='Kubernetes Resource Usage Reporter')
    parser.add_argument('-n', '--namespace', help='Namespace to report on', default=None)
    parser.add_argument('-f', '--format', choices=['table', 'csv'], default='table', help='Output format')
    args = parser.parse_args()

    reporter = KubernetesResourceReporter(
        namespace=args.namespace,
        output_format=args.format
    )

    node_data, pod_data = reporter.generate_report()
    reporter.output_report(node_data, pod_data)

if __name__ == "__main__":
    main()