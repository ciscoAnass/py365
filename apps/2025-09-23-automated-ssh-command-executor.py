import os
import sys
import threading
import queue
import paramiko
import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

class SSHCommandExecutor:
    def __init__(self, servers_file, command, username=None, key_filename=None, password=None):
        self.servers_file = servers_file
        self.command = command
        self.username = username
        self.key_filename = key_filename
        self.password = password
        self.results_queue = queue.Queue()
        self.logger = self._setup_logging()

    def _setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s: %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler('ssh_executor.log')
            ]
        )
        return logging.getLogger(__name__)

    def _load_servers(self):
        try:
            with open(self.servers_file, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            self.logger.error(f"Servers file {self.servers_file} not found")
            return []
        except Exception as e:
            self.logger.error(f"Error reading servers file: {e}")
            return []

    def _ssh_connect(self, hostname):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            if self.key_filename:
                client.connect(
                    hostname, 
                    username=self.username, 
                    key_filename=self.key_filename
                )
            elif self.password:
                client.connect(
                    hostname, 
                    username=self.username, 
                    password=self.password
                )
            else:
                raise ValueError("No authentication method provided")

            stdin, stdout, stderr = client.exec_command(self.command)
            output = stdout.read().decode('utf-8').strip()
            error = stderr.read().decode('utf-8').strip()

            return {
                'hostname': hostname,
                'output': output,
                'error': error,
                'success': len(error) == 0
            }
        except Exception as e:
            return {
                'hostname': hostname,
                'output': '',
                'error': str(e),
                'success': False
            }
        finally:
            client.close()

    def execute_commands(self, max_workers=10):
        servers = self._load_servers()
        results = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self._ssh_connect, server): server for server in servers}
            
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                
                if result['success']:
                    self.logger.info(f"Command successful on {result['hostname']}")
                else:
                    self.logger.error(f"Command failed on {result['hostname']}: {result['error']}")

        return results

    def generate_report(self, results):
        report = {
            'total_servers': len(results),
            'successful_servers': sum(1 for r in results if r['success']),
            'failed_servers': sum(1 for r in results if not r['success']),
            'results': results
        }
        
        with open('ssh_execution_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        return report

def main():
    if len(sys.argv) < 4:
        print("Usage: python script.py <servers_file> <username> <command> [key_file]")
        sys.exit(1)

    servers_file = sys.argv[1]
    username = sys.argv[2]
    command = sys.argv[3]
    key_filename = sys.argv[4] if len(sys.argv) > 4 else None

    executor = SSHCommandExecutor(
        servers_file=servers_file, 
        command=command, 
        username=username, 
        key_filename=key_filename
    )

    results = executor.execute_commands()
    report = executor.generate_report(results)
    
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()