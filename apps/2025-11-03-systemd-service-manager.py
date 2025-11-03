import os
import subprocess
import sys
import argparse
import json
import logging
from typing import List, Dict, Optional, Union

class SystemdServiceManager:
    def __init__(self, log_level: str = 'INFO'):
        """
        Initialize the SystemdServiceManager with configurable logging.
        
        Args:
            log_level (str): Logging level for the application
        """
        logging.basicConfig(
            level=getattr(logging, log_level.upper()),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def _run_systemctl_command(self, command: List[str]) -> Dict[str, Union[bool, str]]:
        """
        Execute a systemctl command with error handling and logging.
        
        Args:
            command (List[str]): Systemctl command to execute
        
        Returns:
            Dict containing command execution result
        """
        try:
            result = subprocess.run(
                command, 
                capture_output=True, 
                text=True, 
                check=True
            )
            return {
                'success': True,
                'output': result.stdout.strip(),
                'error': None
            }
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Command {' '.join(command)} failed: {e.stderr}")
            return {
                'success': False,
                'output': None,
                'error': e.stderr.strip()
            }

    def start_service(self, service_name: str) -> bool:
        """
        Start a systemd service.
        
        Args:
            service_name (str): Name of the service to start
        
        Returns:
            bool: True if service started successfully, False otherwise
        """
        result = self._run_systemctl_command(['sudo', 'systemctl', 'start', service_name])
        return result['success']

    def stop_service(self, service_name: str) -> bool:
        """
        Stop a systemd service.
        
        Args:
            service_name (str): Name of the service to stop
        
        Returns:
            bool: True if service stopped successfully, False otherwise
        """
        result = self._run_systemctl_command(['sudo', 'systemctl', 'stop', service_name])
        return result['success']

    def restart_service(self, service_name: str) -> bool:
        """
        Restart a systemd service.
        
        Args:
            service_name (str): Name of the service to restart
        
        Returns:
            bool: True if service restarted successfully, False otherwise
        """
        result = self._run_systemctl_command(['sudo', 'systemctl', 'restart', service_name])
        return result['success']

    def enable_service(self, service_name: str) -> bool:
        """
        Enable a systemd service to start on boot.
        
        Args:
            service_name (str): Name of the service to enable
        
        Returns:
            bool: True if service enabled successfully, False otherwise
        """
        result = self._run_systemctl_command(['sudo', 'systemctl', 'enable', service_name])
        return result['success']

    def disable_service(self, service_name: str) -> bool:
        """
        Disable a systemd service from starting on boot.
        
        Args:
            service_name (str): Name of the service to disable
        
        Returns:
            bool: True if service disabled successfully, False otherwise
        """
        result = self._run_systemctl_command(['sudo', 'systemctl', 'disable', service_name])
        return result['success']

    def get_service_status(self, service_name: str) -> Dict[str, Union[str, bool]]:
        """
        Get detailed status of a systemd service.
        
        Args:
            service_name (str): Name of the service to check
        
        Returns:
            Dict containing service status details
        """
        result = self._run_systemctl_command(['systemctl', 'status', service_name])
        
        if result['success']:
            return {
                'active': 'Active: active' in result['output'],
                'running': 'running' in result['output'],
                'full_status': result['output']
            }
        return {
            'active': False,
            'running': False,
            'full_status': result.get('error', 'Unknown error')
        }

    def list_services(self, filter_type: Optional[str] = None) -> List[str]:
        """
        List all systemd services with optional filtering.
        
        Args:
            filter_type (Optional[str]): Type of services to list (active, inactive)
        
        Returns:
            List of service names
        """
        cmd = ['systemctl', 'list-unit-files', '--type=service']
        if filter_type:
            cmd.append(f'--state={filter_type}')
        
        result = self._run_systemctl_command(cmd)
        
        if result['success']:
            services = [
                line.split()[0] 
                for line in result['output'].split('\n')[1:-2]  # Skip header and footer
                if line.strip() and not line.startswith('--')
            ]
            return services
        return []

def main():
    parser = argparse.ArgumentParser(description='Systemd Service Management Tool')
    parser.add_argument('action', choices=[
        'start', 'stop', 'restart', 'enable', 
        'disable', 'status', 'list'
    ])
    parser.add_argument('service', nargs='?', help='Service name')
    parser.add_argument('--filter', choices=['active', 'inactive'], 
                        help='Filter for list action')
    
    args = parser.parse_args()
    
    manager = SystemdServiceManager()
    
    try:
        if args.action == 'start':
            result = manager.start_service(args.service)
        elif args.action == 'stop':
            result = manager.stop_service(args.service)
        elif args.action == 'restart':
            result = manager.restart_service(args.service)
        elif args.action == 'enable':
            result = manager.enable_service(args.service)
        elif args.action == 'disable':
            result = manager.disable_service(args.service)
        elif args.action == 'status':
            result = manager.get_service_status(args.service)
            print(json.dumps(result, indent=2))
            sys.exit(0)
        elif args.action == 'list':
            result = manager.list_services(args.filter)
            print(json.dumps(result, indent=2))
            sys.exit(0)
        
        print(f"Action {args.action} on {args.service} {'succeeded' if result else 'failed'}")
        sys.exit(0 if result else 1)
    
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()