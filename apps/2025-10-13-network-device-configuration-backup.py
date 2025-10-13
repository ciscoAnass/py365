import os
import sys
import logging
from datetime import datetime
from netmiko import ConnectHandler
from typing import List, Dict, Optional

class NetworkDeviceBackup:
    def __init__(self, devices_config: List[Dict[str, str]], backup_dir: Optional[str] = None):
        self.devices_config = devices_config
        self.backup_dir = backup_dir or os.path.join(os.getcwd(), 'device_configs')
        self._setup_logging()
        self._create_backup_directory()

    def _setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s: %(message)s',
            handlers=[
                logging.FileHandler('network_backup.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)

    def _create_backup_directory(self):
        os.makedirs(self.backup_dir, exist_ok=True)
        self.logger.info(f"Backup directory created: {self.backup_dir}")

    def _generate_filename(self, device_name: str) -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{device_name}_{timestamp}_config.txt"

    def backup_device_config(self, device_config: Dict[str, str]) -> bool:
        try:
            connection = ConnectHandler(**device_config)
            self.logger.info(f"Connected to {device_config['host']}")

            config_output = connection.send_command("show running-config")
            filename = self._generate_filename(device_config['host'])
            filepath = os.path.join(self.backup_dir, filename)

            with open(filepath, 'w') as config_file:
                config_file.write(config_output)

            self.logger.info(f"Configuration backed up: {filepath}")
            connection.disconnect()
            return True

        except Exception as e:
            self.logger.error(f"Backup failed for {device_config['host']}: {str(e)}")
            return False

    def backup_all_devices(self) -> Dict[str, bool]:
        backup_results = {}
        for device in self.devices_config:
            result = self.backup_device_config(device)
            backup_results[device['host']] = result
        return backup_results

def load_device_configurations() -> List[Dict[str, str]]:
    return [
        {
            'device_type': 'cisco_ios',
            'host': '192.168.1.1',
            'username': 'admin',
            'password': 'secret123',
            'secret': 'enable_secret'
        },
        {
            'device_type': 'juniper_junos',
            'host': '192.168.1.2',
            'username': 'netadmin',
            'password': 'secure456'
        }
    ]

def main():
    try:
        devices = load_device_configurations()
        backup_tool = NetworkDeviceBackup(devices)
        results = backup_tool.backup_all_devices()

        print("\nBackup Summary:")
        for host, status in results.items():
            print(f"{host}: {'Success' if status else 'Failed'}")

    except Exception as e:
        print(f"Critical error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()