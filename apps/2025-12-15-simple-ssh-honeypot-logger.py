```python
#!/usr/bin/env python3
"""
Simple SSH Honeypot Logger
A cybersecurity script that opens a fake SSH port and logs all login attempts.
This honeypot is designed for gathering threat intelligence and monitoring unauthorized access attempts.

Requirements:
- paramiko (3rd party library for SSH protocol implementation)
- Python 3.6+

Usage:
    python3 ssh_honeypot.py [--port 2222] [--host 0.0.0.0] [--logfile honeypot.log]
"""

import os
import sys
import socket
import threading
import logging
import json
import argparse
import time
import traceback
from datetime import datetime
from pathlib import Path

try:
    import paramiko
except ImportError:
    print("Error: paramiko library is required. Install it with: pip install paramiko")
    sys.exit(1)


class SSHHoneypotServer:
    """
    A simple SSH honeypot server that logs all login attempts.
    
    This class implements a fake SSH server using paramiko that accepts
    any login attempt and immediately disconnects the client while logging
    all credentials and connection details for threat intelligence.
    """
    
    def __init__(self, host='0.0.0.0', port=2222, logfile='honeypot.log', 
                 json_logfile='honeypot.json', key_file='honeypot_key.pem'):
        """
        Initialize the SSH honeypot server.
        
        Args:
            host (str): The host address to bind to (default: 0.0.0.0)
            port (int): The port to listen on (default: 2222)
            logfile (str): Path to the text log file
            json_logfile (str): Path to the JSON log file
            key_file (str): Path to the RSA key file for the honeypot
        """
        self.host = host
        self.port = port
        self.logfile = logfile
        self.json_logfile = json_logfile
        self.key_file = key_file
        self.server_socket = None
        self.running = False
        self.attempt_count = 0
        self.unique_ips = set()
        
        # Configure logging
        self.setup_logging()
        
        # Generate or load SSH key
        self.generate_or_load_key()
        
        self.logger.info(f"SSH Honeypot initialized on {host}:{port}")
    
    def setup_logging(self):
        """
        Set up logging configuration for both file and console output.
        Creates a logger that writes to both text and JSON log files.
        """
        self.logger = logging.getLogger('SSHHoneypot')
        self.logger.setLevel(logging.DEBUG)
        
        # Create logs directory if it doesn't exist
        log_dir = Path('logs')
        log_dir.mkdir(exist_ok=True)
        
        # File handler for text logs
        file_handler = logging.FileHandler(log_dir / self.logfile)
        file_handler.setLevel(logging.DEBUG)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
    
    def generate_or_load_key(self):
        """
        Generate a new RSA key for the honeypot or load an existing one.
        This key is used for SSH protocol negotiation.
        """
        key_path = Path('logs') / self.key_file
        
        try:
            if key_path.exists():
                self.host_key = paramiko.RSAKey.from_private_key_file(str(key_path))
                self.logger.info(f"Loaded existing SSH key from {key_path}")
            else:
                self.logger.info("Generating new RSA key for honeypot...")
                self.host_key = paramiko.RSAKey.generate(2048)
                self.host_key.write_private_key_file(str(key_path))
                self.logger.info(f"Generated and saved new SSH key to {key_path}")
        except Exception as e:
            self.logger.error(f"Error handling SSH key: {e}")
            raise
    
    def start(self):
        """
        Start the honeypot server and begin listening for connections.
        This method runs in the main thread and accepts incoming connections.
        """
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(100)
            self.running = True
            
            self.logger.info(f"SSH Honeypot listening on {self.host}:{self.port}")
            print(f"\n[*] SSH Honeypot is running on {self.host}:{self.port}")
            print("[*] Press Ctrl+C to stop the honeypot\n")
            
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    self.logger.debug(f"New connection from {client_address}")
                    
                    # Handle each connection in a separate thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_address),
                        daemon=True
                    )
                    client_thread.start()
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        self.logger.error(f"Error accepting connection: {e}")
                    
        except OSError as e:
            self.logger.error(f"Failed to bind to {self.host}:{self.port}: {e}")
            raise
        except KeyboardInterrupt:
            self.logger.info("Honeypot interrupted by user")
        finally:
            self.stop()
    
    def handle_client(self, client_socket, client_address):
        """
        Handle an individual client connection.
        
        This method implements the SSH server protocol using paramiko,
        accepts any login attempt, logs the credentials, and disconnects.
        
        Args:
            client_socket: The socket object for the client connection
            client_address: Tuple of (host, port) for the client
        """
        remote_ip = client_address[0]
        remote_port = client_address[1]
        
        self.attempt_count += 1
        self.unique_ips.add(remote_ip)
        
        self.logger.info(f"[Attempt #{self.attempt_count}] Connection from {remote_ip}:{remote_port}")
        
        try:
            # Create SSH transport
            transport = paramiko.Transport(client_socket)
            transport.add_server_key(self.host_key)
            
            # Create server instance
            server = HoneypotSSHServer(
                remote_ip=remote_ip,
                remote_port=remote_port,
                logger=self.logger,
                json_logfile=self.json_logfile
            )
            
            # Start server
            transport.start_server(server=server)
            
            # Keep the connection open for a short time to allow authentication attempts
            channel = transport.accept(timeout=20)
            
            if channel is not None:
                self.logger.debug(f"Channel opened from {remote_ip}:{remote_port}")
                # Close the channel
                channel.close()
            
            transport.close()
            
        except paramiko.AuthenticationException as e:
            self.logger.warning(f"Authentication error from {remote_ip}: {e}")
        except paramiko.SSHException as e:
            self.logger.warning(f"SSH error from {remote_ip}: {e}")
        except Exception as e:
            self.logger.error(f"Error handling client {remote_ip}: {e}")
            self.logger.debug(traceback.format_exc())
        finally:
            try:
                client_socket.close()
            except:
                pass
            
            self.logger.info(f"Connection closed from {remote_ip}:{remote_port}")
    
    def stop(self):
        """
        Stop the honeypot server and clean up resources.
        """
        self.running = False
        
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        self.logger.info(f"Honeypot stopped. Total attempts: {self.attempt_count}, Unique IPs: {len(self.unique_ips)}")
        print(f"\n[*] Honeypot stopped")
        print(f"[*] Total login attempts: {self.attempt_count}")
        print(f"[*] Unique IP addresses: {len(self.unique_ips)}")
        print(f"[*] Logs saved to logs/{self.logfile} and logs/{self.json_logfile}")
    
    def get_statistics(self):
        """
        Get current statistics about the honeypot.
        
        Returns:
            dict: Dictionary containing statistics
        """
        return {
            'total_attempts': self.attempt_count,
            'unique_ips': len(self.unique_ips),
            'uptime': datetime.now().isoformat(),
            'running': self.running
        }


class HoneypotSSHServer(paramiko.ServerInterface):
    """
    SSH Server implementation for the honeypot.
    
    This class implements the paramiko ServerInterface to handle
    SSH protocol negotiations and authentication attempts.
    """
    
    def __init__(self, remote_ip, remote_port, logger, json_logfile):
        """
        Initialize the honeypot SSH server instance.
        
        Args:
            remote_ip (str): IP address of the connecting client
            remote_port (int): Port of the connecting client
            logger: Logger instance for logging attempts
            json_logfile (str): Path to JSON log file
        """
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.logger = logger
        self.json_logfile = json_logfile
        self.username = None
        self.password = None
        self.auth_method = None
        self.event = threading.Event()
    
    def check_auth_password(self, username, password):
        """
        Handle password authentication attempts.
        
        This method is called when a client attempts password authentication.
        We log the attempt and always reject it.
        
        Args:
            username (str): The username provided by the client
            password (str): The password provided by the client
            
        Returns:
            paramiko.AUTH_FAILED: Always reject the authentication
        """
        self.username = username
        self.password = password
        self.auth_method = 'password'
        
        self.log_attempt('password', username, password)
        
        self.logger.warning(
            f"Password auth attempt from {self.remote_ip}: "
            f"username='{username}', password='{password}'"
        )
        
        return paramiko.AUTH_FAILED
    
    def check_auth_publickey(self, username, key):
        """
        Handle public key authentication attempts.
        
        This method is called when a client attempts public key authentication.
        We log the attempt and always reject it.
        
        Args:
            username (str): The username provided by the client
            key: The public key object
            
        Returns:
            paramiko.AUTH_FAILED: Always reject the authentication
        """
        self.username = username
        self.auth_method = 'publickey'
        
        key_type = key.get_name()
        key_bits = key.get_bits()
        key_fingerprint = paramiko.py3compat.u(key.get_base64())[:50]
        
        self.log_attempt('publickey', username, f"{key_type} ({key_bits} bits)")
        
        self.logger.warning(
            f"Public key auth attempt from {self.remote_ip}: "
            f"username='{username}', key_type='{key_type}', bits={key_bits}"
        )
        
        return paramiko.AUTH_FAILED
    
    def check_auth_keyboard_interactive(self, username, submitter):
        """
        Handle keyboard-interactive authentication attempts.
        
        Args:
            username (str): The username provided by the client
            submitter: The submitter callback
            
        Returns:
            paramiko.AUTH_FAILED: Always reject the authentication
        """
        self.username = username
        self.auth_method = 'keyboard-interactive'
        
        self.log_attempt('keyboard-interactive', username, 'N/A')
        
        self.logger.warning(
            f"Keyboard-interactive auth attempt from {self.remote_ip}: "
            f"username='{username}'"
        )
        
        return paramiko.AUTH_FAILED
    
    def get_allowed_auths(self, username):
        """
        Return the list of allowed authentication methods.
        
        Args:
            username (str): The username
            
        Returns:
            str: Comma-separated list of allowed auth methods
        """
        return 'password,publickey,keyboard-interactive'
    
    def check_channel_request(self, kind, chanid):
        """
        Handle channel requests.
        
        Args:
            kind (str): The type of channel
            chanid (int): The channel ID
            
        Returns:
            paramiko.OPEN_SUCCEEDED: Accept the channel
        """
        self.logger.debug(f"Channel request from {self.remote_ip}: kind={kind}, chanid={chanid}")
        return paramiko.OPEN_SUCCEEDED
    
    def log_attempt(self, auth_method, username, credential):
        """
        Log an authentication attempt to both text and JSON files.
        
        Args:
            auth_method (str): The authentication method used
            username (str): The username attempted
            credential (str): The password or key information
        """
        timestamp = datetime.now().isoformat()
        
        # Create log entry
        log_entry = {
            'timestamp': timestamp,
            'remote_ip': self.remote_ip,
            'remote_port': self.remote_port,
            'auth_method': auth_method,
            'username': username,
            'credential': credential
        }
        
        # Log to JSON file
        try:
            log_path = Path('logs') / self.json_logfile
            
            # Read existing logs
            logs = []
            if log_path.exists():
                try:
                    with open(log_path, 'r') as f:
                        logs = json.load(f)
                except (json.JSONDecodeError, IOError):
                    logs = []
            
            # Append new entry
            logs.append(log_entry)
            
            # Write back to file
            with open(log_path, 'w') as f:
                json.dump(logs, f, indent=2)
        except Exception as e:
            self.logger.error(f"Error writing to JSON log: {e}")
        
        self.logger.info(
            f"[{auth_method.upper()}] {self.remote_ip}:{self.remote_port} - "
            f"user='{username}'"
        )


def parse_arguments():
    """
    Parse command-line arguments.
    
    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(