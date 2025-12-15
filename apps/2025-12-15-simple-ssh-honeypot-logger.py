#!/usr/bin/env python3
"""
Simple SSH Honeypot Logger
A cybersecurity script that opens a fake SSH port and logs all login attempts.

Requirements:
- paramiko
- Python 3.6+

Usage:
    python3 ssh_honeypot.py --port 2222 --host 0.0.0.0 --logfile honeypot.log --json-logfile honeypot.jsonl
"""

import sys
import socket
import threading
import logging
import json
import argparse
import traceback
from datetime import datetime
from pathlib import Path

try:
    import paramiko
except ImportError:
    print("Error: paramiko library is required. Install it with: pip install paramiko")
    sys.exit(1)


class SSHHoneypotServer:
    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 2222,
        logfile: str = "honeypot.log",
        json_logfile: str = "honeypot.jsonl",
        key_file: str = "honeypot_key.pem",
    ):
        self.host = host
        self.port = port
        self.logfile = logfile
        self.json_logfile = json_logfile
        self.key_file = key_file

        self.server_socket = None
        self.running = False

        # Shared stats (accessed by many threads)
        self.attempt_count = 0
        self.unique_ips = set()
        self.lock = threading.Lock()

        self.setup_logging()
        self.generate_or_load_key()

        self.logger.info(f"SSH Honeypot initialized on {host}:{port}")

    def setup_logging(self):
        self.logger = logging.getLogger("SSHHoneypot")
        self.logger.setLevel(logging.DEBUG)

        # Avoid duplicate handlers if the module is reloaded or instantiated twice
        if self.logger.handlers:
            self.logger.handlers.clear()

        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)

        file_handler = logging.FileHandler(log_dir / self.logfile)
        file_handler.setLevel(logging.DEBUG)

        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)

        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

    def generate_or_load_key(self):
        key_path = Path("logs") / self.key_file
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
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(100)

            # So we can check self.running periodically and stop cleanly
            self.server_socket.settimeout(1.0)

            self.running = True
            self.logger.info(f"SSH Honeypot listening on {self.host}:{self.port}")
            print(f"\n[*] SSH Honeypot is running on {self.host}:{self.port}")
            print("[*] Press Ctrl+C to stop the honeypot\n")

            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()

                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_address),
                        daemon=True,
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
        remote_ip, remote_port = client_address[0], client_address[1]

        # Thread-safe stats update
        with self.lock:
            self.attempt_count += 1
            self.unique_ips.add(remote_ip)
            attempt_no = self.attempt_count

        self.logger.info(f"[Attempt #{attempt_no}] Connection from {remote_ip}:{remote_port}")

        try:
            transport = paramiko.Transport(client_socket)
            transport.add_server_key(self.host_key)

            server = HoneypotSSHServer(
                remote_ip=remote_ip,
                remote_port=remote_port,
                logger=self.logger,
                json_logfile=self.json_logfile,
            )

            transport.start_server(server=server)

            channel = transport.accept(timeout=20)
            if channel is not None:
                self.logger.debug(f"Channel opened from {remote_ip}:{remote_port}")
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
            except Exception:
                pass
            self.logger.info(f"Connection closed from {remote_ip}:{remote_port}")

    def stop(self):
        self.running = False

        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass

        with self.lock:
            attempts = self.attempt_count
            uniq = len(self.unique_ips)

        self.logger.info(f"Honeypot stopped. Total attempts: {attempts}, Unique IPs: {uniq}")
        print(f"\n[*] Honeypot stopped")
        print(f"[*] Total login attempts: {attempts}")
        print(f"[*] Unique IP addresses: {uniq}")
        print(f"[*] Logs saved to logs/{self.logfile} and logs/{self.json_logfile}")

    def get_statistics(self):
        with self.lock:
            attempts = self.attempt_count
            uniq = len(self.unique_ips)

        return {
            "total_attempts": attempts,
            "unique_ips": uniq,
            "uptime": datetime.now().isoformat(),
            "running": self.running,
        }


class HoneypotSSHServer(paramiko.ServerInterface):
    def __init__(self, remote_ip, remote_port, logger, json_logfile):
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.logger = logger
        self.json_logfile = json_logfile

        self.username = None
        self.password = None
        self.auth_method = None

    def check_auth_password(self, username, password):
        self.username = username
        self.password = password
        self.auth_method = "password"

        self.log_attempt("password", username, password)

        self.logger.warning(
            f"Password auth attempt from {self.remote_ip}: username='{username}', password='{password}'"
        )
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        self.username = username
        self.auth_method = "publickey"

        key_type = key.get_name()
        key_bits = key.get_bits()

        self.log_attempt("publickey", username, f"{key_type} ({key_bits} bits)")

        self.logger.warning(
            f"Public key auth attempt from {self.remote_ip}: username='{username}', key_type='{key_type}', bits={key_bits}"
        )
        return paramiko.AUTH_FAILED

    def check_auth_keyboard_interactive(self, username, submitter):
        self.username = username
        self.auth_method = "keyboard-interactive"

        self.log_attempt("keyboard-interactive", username, "N/A")

        self.logger.warning(
            f"Keyboard-interactive auth attempt from {self.remote_ip}: username='{username}'"
        )
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password,publickey,keyboard-interactive"

    def check_channel_request(self, kind, chanid):
        self.logger.debug(f"Channel request from {self.remote_ip}: kind={kind}, chanid={chanid}")
        return paramiko.OPEN_SUCCEEDED

    def log_attempt(self, auth_method, username, credential):
        timestamp = datetime.now().isoformat()

        log_entry = {
            "timestamp": timestamp,
            "remote_ip": self.remote_ip,
            "remote_port": self.remote_port,
            "auth_method": auth_method,
            "username": username,
            "credential": credential,
        }

        # JSONL append-only (safe under threads and no read/modify/write)
        try:
            log_path = Path("logs") / self.json_logfile
            line = json.dumps(log_entry, ensure_ascii=False) + "\n"
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(line)
        except Exception as e:
            self.logger.error(f"Error writing to JSONL log: {e}")

        self.logger.info(
            f"[{auth_method.upper()}] {self.remote_ip}:{self.remote_port} - user='{username}'"
        )


def parse_arguments():
    parser = argparse.ArgumentParser(description="Simple SSH Honeypot Logger")
    parser.add_argument("--host", default="0.0.0.0", help="Host/IP to bind (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=2222, help="Port to listen on (default: 2222)")
    parser.add_argument("--logfile", default="honeypot.log", help="Text log filename (in ./logs)")
    parser.add_argument(
        "--json-logfile",
        default="honeypot.jsonl",
        help="JSON Lines log filename (in ./logs)",
    )
    parser.add_argument("--key-file", default="honeypot_key.pem", help="SSH host key filename (in ./logs)")
    return parser.parse_args()


def main():
    args = parse_arguments()
    server = SSHHoneypotServer(
        host=args.host,
        port=args.port,
        logfile=args.logfile,
        json_logfile=args.json_logfile,
        key_file=args.key_file,
    )
    server.start()


if __name__ == "__main__":
    main()
