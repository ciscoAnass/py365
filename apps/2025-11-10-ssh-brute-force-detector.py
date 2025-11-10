import os
import re
import time
import subprocess
from datetime import datetime

def monitor_auth_log():
    """
    Continuously monitors the system's authentication log (auth.log or secure) for failed SSH login attempts.
    """
    log_file = '/var/log/auth.log' if os.path.exists('/var/log/auth.log') else '/var/log/secure'
    
    failed_login_pattern = r'Failed password for .* from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    failed_login_ips = {}
    
    while True:
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    match = re.search(failed_login_pattern, line)
                    if match:
                        ip_address = match.group(1)
                        if ip_address in failed_login_ips:
                            failed_login_ips[ip_address] += 1
                            if failed_login_ips[ip_address] >= 5:
                                block_ip(ip_address)
                        else:
                            failed_login_ips[ip_address] = 1
        except FileNotFoundError:
            print(f"Error: {log_file} not found.")
            time.sleep(60)
        except Exception as e:
            print(f"Error: {e}")
            time.sleep(60)
        time.sleep(5)

def block_ip(ip_address):
    """
    Blocks the given IP address using either iptables or firewalld.
    """
    try:
        if os.path.exists('/usr/sbin/iptables'):
            subprocess.run(['iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'], check=True)
            print(f"Blocked IP address: {ip_address}")
        elif os.path.exists('/usr/bin/firewall-cmd'):
            subprocess.run(['firewall-cmd', '--permanent', '--add-rich-rule', f'rule family="ipv4" source address="{ip_address}" drop'], check=True)
            subprocess.run(['firewall-cmd', '--reload'], check=True)
            print(f"Blocked IP address: {ip_address}")
        else:
            print(f"Error: Neither iptables nor firewalld found on the system.")
    except subprocess.CalledProcessError as e:
        print(f"Error blocking IP address {ip_address}: {e}")

def main():
    """
    Main function that starts the SSH brute-force detection and blocking process.
    """
    print(f"SSH Brute-Force Detector started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    monitor_auth_log()

if __name__ == "__main__":
    main()