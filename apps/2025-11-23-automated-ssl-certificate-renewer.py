import os
import subprocess
import time
import logging
import sys
import shutil
import configparser

# Third-party libraries
# - certbot (pip install certbot)
# - requests (pip install requests)

# Configure logging
logging.basicConfig(
    filename='ssl_renewer.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Load configuration from file
config = configparser.ConfigParser()
config.read('ssl_renewer.conf')

# Constants
DOMAINS = config.get('domains', 'domains').split(',')
WEBSERVER = config.get('webserver', 'type')
WEBSERVER_RELOAD_COMMAND = config.get('webserver', 'reload_command')
CERTBOT_COMMAND = config.get('certbot', 'command')
CERTBOT_ARGS = config.get('certbot', 'args').split()
RENEWAL_DAYS = int(config.get('renewal', 'days'))

def check_domain_ownership(domain):
    """
    Verify domain ownership using the ACME protocol.
    Returns True if domain ownership is verified, False otherwise.
    """
    try:
        # Use certbot or other ACME client to verify domain ownership
        result = subprocess.run(['certbot', 'certonly', '--dry-run', '-d', domain], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.returncode == 0
    except subprocess.CalledProcessError as e:
        logging.error(f"Error verifying domain ownership for {domain}: {e}")
        return False

def renew_certificates():
    """
    Renew SSL/TLS certificates using certbot.
    """
    try:
        # Run the certbot command to renew certificates
        result = subprocess.run([CERTBOT_COMMAND] + CERTBOT_ARGS, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logging.info(f"SSL/TLS certificates renewed successfully: {result.stdout.decode().strip()}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error renewing SSL/TLS certificates: {e}")

def reload_webserver():
    """
    Reload the web server (Nginx or Apache) to apply the new SSL/TLS certificates.
    """
    try:
        # Run the web server reload command
        result = subprocess.run(WEBSERVER_RELOAD_COMMAND, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logging.info(f"Web server reloaded successfully: {result.stdout.decode().strip()}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error reloading web server: {e}")

def backup_certificates():
    """
    Backup the existing SSL/TLS certificates before renewing them.
    """
    try:
        # Create a backup directory
        backup_dir = 'ssl_certificate_backup'
        os.makedirs(backup_dir, exist_ok=True)

        # Copy the existing certificates to the backup directory
        for domain in DOMAINS:
            src_path = f'/etc/letsencrypt/live/{domain}'
            dst_path = os.path.join(backup_dir, domain)
            shutil.copytree(src_path, dst_path)
            logging.info(f"Backed up SSL/TLS certificates for {domain} to {dst_path}")
    except (OSError, shutil.Error) as e:
        logging.error(f"Error backing up SSL/TLS certificates: {e}")

def restore_certificates():
    """
    Restore the backed up SSL/TLS certificates if the renewal process fails.
    """
    try:
        # Restore the backed up certificates
        backup_dir = 'ssl_certificate_backup'
        for domain in DOMAINS:
            src_path = os.path.join(backup_dir, domain)
            dst_path = f'/etc/letsencrypt/live/{domain}'
            shutil.copytree(src_path, dst_path, dirs_exist_ok=True)
            logging.info(f"Restored SSL/TLS certificates for {domain} from {src_path}")
    except (OSError, shutil.Error) as e:
        logging.error(f"Error restoring SSL/TLS certificates: {e}")

def main():
    """
    Main function to orchestrate the SSL/TLS certificate renewal process.
    """
    try:
        # Backup the existing certificates
        backup_certificates()

        # Renew the certificates
        renew_certificates()

        # Verify domain ownership
        all_domains_verified = all(check_domain_ownership(domain) for domain in DOMAINS)
        if all_domains_verified:
            # Reload the web server to apply the new certificates
            reload_webserver()
            logging.info("SSL/TLS certificate renewal process completed successfully.")
        else:
            # Restore the backed up certificates
            restore_certificates()
            logging.error("SSL/TLS certificate renewal process failed. Restored the backed up certificates.")
    except Exception as e:
        # Restore the backed up certificates in case of any unexpected errors
        restore_certificates()
        logging.error(f"Unexpected error occurred during SSL/TLS certificate renewal: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()