import os
import sys
import time
import json
import logging
import subprocess
import docker
from typing import List, Tuple, Dict

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

class DockerContainerHealthChecker:
    def __init__(self, docker_socket_path: str = '/var/run/docker.sock'):
        self.docker_client = docker.DockerClient(base_url=f'unix://{docker_socket_path}')
        self.container_health_checks: Dict[str, List[Tuple[str, callable]]] = {}

    def register_health_check(self, container_name: str, check_name: str, check_function: callable):
        """
        Register a health check function for a specific container.
        
        Args:
            container_name (str): The name of the container to register the health check for.
            check_name (str): The name of the health check.
            check_function (callable): The function that performs the health check.
        """
        if container_name not in self.container_health_checks:
            self.container_health_checks[container_name] = []
        self.container_health_checks[container_name].append((check_name, check_function))

    def check_container_health(self, container_name: str) -> bool:
        """
        Perform health checks for the specified container.
        
        Args:
            container_name (str): The name of the container to check.
        
        Returns:
            bool: True if the container passes all health checks, False otherwise.
        """
        container = self.docker_client.containers.get(container_name)
        health_checks = self.container_health_checks.get(container_name, [])
        
        for check_name, check_function in health_checks:
            logging.info(f"Running health check '{check_name}' for container '{container_name}'")
            if not check_function(container):
                logging.error(f"Health check '{check_name}' failed for container '{container_name}'")
                return False
        
        return True

    def check_all_containers_health(self) -> Dict[str, bool]:
        """
        Perform health checks for all running containers.
        
        Returns:
            Dict[str, bool]: A dictionary mapping container names to their health check results.
        """
        container_health_status = {}
        for container in self.docker_client.containers.list():
            container_name = container.name
            container_health_status[container_name] = self.check_container_health(container_name)
        return container_health_status

    def restart_unhealthy_containers(self):
        """
        Restart all containers that fail the health checks.
        """
        container_health_status = self.check_all_containers_health()
        for container_name, is_healthy in container_health_status.items():
            if not is_healthy:
                logging.info(f"Restarting unhealthy container '{container_name}'")
                container = self.docker_client.containers.get(container_name)
                container.restart()

def check_container_port_listener(container: docker.models.containers.Container, port: int) -> bool:
    """
    Check if the specified port is being listened on by the container.
    
    Args:
        container (docker.models.containers.Container): The container to check.
        port (int): The port number to check.
    
    Returns:
        bool: True if the port is being listened on, False otherwise.
    """
    try:
        container.exec_run(f'nc -z 0.0.0.0 {port}', detach=True)
        return True
    except Exception as e:
        logging.error(f"Port listener check failed for container '{container.name}' on port {port}: {e}")
        return False

def check_container_log_output(container: docker.models.containers.Container, expected_output: str) -> bool:
    """
    Check if the container's log output contains the expected output.
    
    Args:
        container (docker.models.containers.Container): The container to check.
        expected_output (str): The expected output to look for in the logs.
    
    Returns:
        bool: True if the expected output is found in the logs, False otherwise.
    """
    try:
        logs = container.logs().decode('utf-8')
        if expected_output in logs:
            return True
        else:
            logging.error(f"Log output check failed for container '{container.name}'. Expected output not found.")
            return False
    except Exception as e:
        logging.error(f"Log output check failed for container '{container.name}': {e}")
        return False

def check_container_environment_variable(container: docker.models.containers.Container, variable_name: str, expected_value: str) -> bool:
    """
    Check if the container's environment variable has the expected value.
    
    Args:
        container (docker.models.containers.Container): The container to check.
        variable_name (str): The name of the environment variable to check.
        expected_value (str): The expected value of the environment variable.
    
    Returns:
        bool: True if the environment variable has the expected value, False otherwise.
    """
    try:
        env_vars = container.attrs['Config']['Env']
        for env_var in env_vars:
            if env_var.startswith(f"{variable_name}="):
                value = env_var.split("=")[1]
                if value == expected_value:
                    return True
                else:
                    logging.error(f"Environment variable check failed for container '{container.name}'. Expected '{variable_name}={expected_value}', got '{variable_name}={value}'.")
                    return False
        logging.error(f"Environment variable '{variable_name}' not found in container '{container.name}'.")
        return False
    except Exception as e:
        logging.error(f"Environment variable check failed for container '{container.name}': {e}")
        return False

def check_container_cpu_usage(container: docker.models.containers.Container, max_cpu_usage_percent: float) -> bool:
    """
    Check if the container's CPU usage is below the specified maximum.
    
    Args:
        container (docker.models.containers.Container): The container to check.
        max_cpu_usage_percent (float): The maximum allowed CPU usage percentage.
    
    Returns:
        bool: True if the CPU usage is below the maximum, False otherwise.
    """
    try:
        stats = container.stats(stream=False)
        cpu_usage = stats['cpu_stats']['cpu_usage']['total_usage']
        system_cpu_usage = stats['cpu_stats']['system_cpu_usage']
        num_cpus = len(stats['cpu_stats']['cpu_usage']['percpu_usage'])
        cpu_usage_percent = (cpu_usage - stats['precpu_stats']['cpu_usage']['total_usage']) / (system_cpu_usage - stats['precpu_stats']['system_cpu_usage']) * num_cpus * 100
        if cpu_usage_percent <= max_cpu_usage_percent:
            return True
        else:
            logging.error(f"CPU usage check failed for container '{container.name}'. CPU usage: {cpu_usage_percent:.2f}%, maximum allowed: {max_cpu_usage_percent:.2f}%.")
            return False
    except Exception as e:
        logging.error(f"CPU usage check failed for container '{container.name}': {e}")
        return False

def check_container_memory_usage(container: docker.models.containers.Container, max_memory_usage_bytes: int) -> bool:
    """
    Check if the container's memory usage is below the specified maximum.
    
    Args:
        container (docker.models.containers.Container): The container to check.
        max_memory_usage_bytes (int): The maximum allowed memory usage in bytes.
    
    Returns:
        bool: True if the memory usage is below the maximum, False otherwise.
    """
    try:
        stats = container.stats(stream=False)
        memory_usage = stats['memory_stats']['usage']
        if memory_usage <= max_memory_usage_bytes:
            return True
        else:
            logging.error(f"Memory usage check failed for container '{container.name}'. Memory usage: {memory_usage} bytes, maximum allowed: {max_memory_usage_bytes} bytes.")
            return False
    except Exception as e:
        logging.error(f"Memory usage check failed for container '{container.name}': {e}")
        return False

def check_container_network_connectivity(container: docker.models.containers.Container, target_host: str, target_port: int) -> bool:
    """
    Check if the container can connect to the specified target host and port.
    
    Args:
        container (docker.models.containers.Container): The container to check.
        target_host (str): The target host to connect to.
        target_port (int): The target port to connect to.
    
    Returns:
        bool: True if the container can connect to the target, False otherwise.
    """
    try:
        container.exec_run(f'nc -z {target_host} {target_port}', detach=True)
        return True
    except Exception as e:
        logging.error(f"Network connectivity check failed for container '{container.name}' to {target_host}:{target_port}: {e}")
        return False

def main():
    health_checker = DockerContainerHealthChecker()

    # Register health checks for specific containers
    health_checker.register_health_check('my-app', 'port-listener', lambda c: check_container_port_listener(c, 8080))
    health_checker.register_health_check('my-app', 'log-output', lambda c: check_container_log_output(c, 'Application started'))
    health_checker.register_health_check('my-app', 'env-variable', lambda c: check_container_environment_variable(c, 'APP_ENV', 'production'))
    health_checker.register_health_check('my-db', 'port-listener', lambda c: check_container_port_listener(c, 5432))
    health_checker.register_health_check('my-db', 'cpu-usage', lambda c: check_container_cpu_usage(c, 80.0))
    health_checker.register_health_check('my-db', 'memory-usage', lambda c: check_container_memory_usage(c, 1024 * 1024 * 1024))  # 1 GB
    health_checker.register_health_check('my-web', 'network-connectivity', lambda c: check_container_network_connectivity(c, 'external-service.com', 80))

    # Check the health of all running containers
    container_health_status = health_checker.check_all_containers_health()

    # Print the health status of each container
    for container_name, is_healthy in container_health_status.items():
        if is_healthy:
            logging.info(f"Container '{container_name}' is healthy.")
        else:
            logging.error(f"Container '{container_name}' is unhealthy.")

    # Restart any unhealthy containers
    health_checker.restart_unhealthy_containers()

if __name__ == "__main__":
    main()