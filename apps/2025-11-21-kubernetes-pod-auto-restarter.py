import os
import time
import logging
import kubernetes
from kubernetes.client.rest import ApiException
from kubernetes.client import V1Pod, V1PodStatus, V1ContainerState, V1ContainerStateTerminated

logging.basicConfig(level=logging.INFO)

class KubernetesPodAutoRestarter:
    def __init__(self, namespace='default'):
        self.namespace = namespace
        self.api_client = kubernetes.config.load_incluster_config()
        self.core_api = kubernetes.client.CoreV1Api(self.api_client)

    def watch_pods(self):
        while True:
            try:
                ret = self.core_api.list_namespaced_pod(self.namespace)
                for pod in ret.items:
                    self.handle_pod(pod)
                time.sleep(10)
            except ApiException as e:
                logging.error(f"Exception when calling CoreV1Api->list_namespaced_pod: {e}")
            except Exception as e:
                logging.error(f"Unexpected error: {e}")

    def handle_pod(self, pod: V1Pod):
        pod_name = pod.metadata.name
        pod_status = pod.status
        if pod_status.phase == 'CrashLoopBackOff' or pod_status.phase == 'ImagePullBackOff':
            logging.info(f"Pod {pod_name} is in {pod_status.phase} state. Attempting to resolve issue.")
            self.analyze_pod_logs(pod)
            self.delete_pod(pod)

    def analyze_pod_logs(self, pod: V1Pod):
        pod_name = pod.metadata.name
        try:
            logs = self.core_api.read_namespaced_pod_log(pod_name, self.namespace)
            if 'ImagePullBackOff' in logs:
                logging.info(f"Pod {pod_name} is experiencing an ImagePullBackOff error. Checking image availability.")
                self.check_image_availability(pod)
            elif 'CrashLoopBackOff' in logs:
                logging.info(f"Pod {pod_name} is experiencing a CrashLoopBackOff error. Checking container state.")
                self.check_container_state(pod)
            else:
                logging.info(f"No known error patterns found in logs for pod {pod_name}.")
        except ApiException as e:
            logging.error(f"Exception when calling CoreV1Api->read_namespaced_pod_log: {e}")
        except Exception as e:
            logging.error(f"Unexpected error while analyzing pod logs: {e}")

    def check_image_availability(self, pod: V1Pod):
        pod_name = pod.metadata.name
        for container in pod.spec.containers:
            image = container.image
            try:
                self.core_api.read_namespaced_pod_log(pod_name, self.namespace, container=container.name)
                logging.info(f"Image {image} is available. Proceeding to delete pod {pod_name}.")
            except ApiException as e:
                if e.status == 404:
                    logging.error(f"Image {image} is not available. Unable to resolve ImagePullBackOff error for pod {pod_name}.")
                else:
                    logging.error(f"Exception when calling CoreV1Api->read_namespaced_pod_log: {e}")
            except Exception as e:
                logging.error(f"Unexpected error while checking image availability: {e}")

    def check_container_state(self, pod: V1Pod):
        pod_name = pod.metadata.name
        for container_status in pod.status.container_statuses:
            container_state = container_status.state
            if container_state.waiting:
                logging.info(f"Container {container_status.name} in pod {pod_name} is in a waiting state.")
                self.analyze_container_waiting_state(container_state.waiting)
            elif container_state.terminated:
                logging.info(f"Container {container_status.name} in pod {pod_name} is in a terminated state.")
                self.analyze_container_terminated_state(container_state.terminated)
            else:
                logging.info(f"Container {container_status.name} in pod {pod_name} is in an unknown state.")

    def analyze_container_waiting_state(self, waiting_state: V1ContainerState):
        if waiting_state.reason == 'ImagePullBackOff':
            logging.info(f"Container is in ImagePullBackOff state. Checking image availability.")
            self.check_image_availability(pod)
        elif waiting_state.reason == 'CrashLoopBackOff':
            logging.info(f"Container is in CrashLoopBackOff state. Checking container logs.")
            self.analyze_pod_logs(pod)
        else:
            logging.info(f"Container is in a waiting state with reason: {waiting_state.reason}")

    def analyze_container_terminated_state(self, terminated_state: V1ContainerStateTerminated):
        logging.info(f"Container terminated with exit code: {terminated_state.exit_code}")
        if terminated_state.exit_code != 0:
            logging.info(f"Non-zero exit code. Checking container logs.")
            self.analyze_pod_logs(pod)

    def delete_pod(self, pod: V1Pod):
        pod_name = pod.metadata.name
        try:
            self.core_api.delete_namespaced_pod(pod_name, self.namespace)
            logging.info(f"Pod {pod_name} has been deleted. Waiting for it to be rescheduled.")
        except ApiException as e:
            logging.error(f"Exception when calling CoreV1Api->delete_namespaced_pod: {e}")
        except Exception as e:
            logging.error(f"Unexpected error while deleting pod: {e}")

if __name__ == '__main__':
    restarter = KubernetesPodAutoRestarter()
    restarter.watch_pods()