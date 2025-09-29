import os
import sys
import subprocess
import datetime
import logging
import argparse
import gzip
import shutil
import boto3
from google.cloud import storage

class DatabaseBackupUtility:
    def __init__(self, config):
        self.config = config
        self.logger = self._setup_logging()
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    def _setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('database_backup.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        return logging.getLogger(__name__)

    def _validate_config(self):
        required_keys = [
            'database_type', 'database_name', 'host', 
            'username', 'backup_directory', 'cloud_provider'
        ]
        for key in required_keys:
            if key not in self.config:
                raise ValueError(f"Missing configuration key: {key}")

    def _generate_backup_filename(self):
        return f"{self.config['database_name']}_{self.timestamp}.sql.gz"

    def _execute_database_dump(self, output_file):
        database_type = self.config['database_type'].lower()
        
        if database_type == 'postgresql':
            dump_command = [
                'pg_dump',
                f'-h{self.config.get("host", "localhost")}',
                f'-U{self.config["username"]}',
                f'-d{self.config["database_name"]}',
                f'-f{output_file}'
            ]
            env = os.environ.copy()
            env['PGPASSWORD'] = self.config.get('password', '')
        
        elif database_type == 'mysql':
            dump_command = [
                'mysqldump',
                f'-h{self.config.get("host", "localhost")}',
                f'-u{self.config["username"]}',
                f'-p{self.config.get("password", "")}',
                self.config['database_name']
            ]
            if output_file:
                dump_command.extend([f'> {output_file}'])
        
        else:
            raise ValueError(f"Unsupported database type: {database_type}")

        try:
            result = subprocess.run(
                dump_command, 
                capture_output=True, 
                text=True, 
                env=env if database_type == 'postgresql' else None
            )
            
            if result.returncode != 0:
                self.logger.error(f"Backup failed: {result.stderr}")
                raise subprocess.CalledProcessError(result.returncode, dump_command, result.stderr)
            
            self.logger.info(f"Database dump completed successfully: {output_file}")
        
        except Exception as e:
            self.logger.error(f"Error during database dump: {e}")
            raise

    def _compress_backup(self, input_file, output_file):
        try:
            with open(input_file, 'rb') as f_in:
                with gzip.open(output_file, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            os.remove(input_file)
            self.logger.info(f"Backup compressed: {output_file}")
        
        except Exception as e:
            self.logger.error(f"Compression error: {e}")
            raise

    def _upload_to_cloud(self, backup_file):
        cloud_provider = self.config['cloud_provider'].lower()
        
        try:
            if cloud_provider == 'aws':
                s3_client = boto3.client('s3')
                bucket_name = self.config.get('bucket_name')
                s3_client.upload_file(
                    backup_file, 
                    bucket_name, 
                    os.path.basename(backup_file)
                )
                self.logger.info(f"Uploaded to AWS S3: {bucket_name}")
            
            elif cloud_provider == 'google':
                storage_client = storage.Client()
                bucket_name = self.config.get('bucket_name')
                bucket = storage_client.bucket(bucket_name)
                blob = bucket.blob(os.path.basename(backup_file))
                blob.upload_from_filename(backup_file)
                self.logger.info(f"Uploaded to Google Cloud Storage: {bucket_name}")
            
            else:
                raise ValueError(f"Unsupported cloud provider: {cloud_provider}")
        
        except Exception as e:
            self.logger.error(f"Cloud upload error: {e}")
            raise

    def perform_backup(self):
        self._validate_config()
        
        backup_dir = self.config.get('backup_directory', '/tmp/database_backups')
        os.makedirs(backup_dir, exist_ok=True)
        
        raw_backup_file = os.path.join(backup_dir, f"{self.config['database_name']}_{self.timestamp}.sql")
        compressed_backup_file = f"{raw_backup_file}.gz"
        
        try:
            self._execute_database_dump(raw_backup_file)
            self._compress_backup(raw_backup_file, compressed_backup_file)
            
            if self.config.get('cloud_upload', True):
                self._upload_to_cloud(compressed_backup_file)
        
        except Exception as e:
            self.logger.error(f"Backup process failed: {e}")
            sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Database Backup Utility')
    parser.add_argument('--config', type=str, help='Path to configuration file')
    args = parser.parse_args()

    default_config = {
        'database_type': 'postgresql',
        'database_name': 'mydb',
        'host': 'localhost',
        'username': 'dbuser',
        'password': '',
        'backup_directory': '/tmp/database_backups',
        'cloud_provider': 'aws',
        'bucket_name': 'my-database-backups',
        'cloud_upload': True
    }

    if args.config:
        try:
            with open(args.config, 'r') as f:
                import json
                user_config = json.load(f)
                default_config.update(user_config)
        except Exception as e:
            print(f"Error reading config file: {e}")
            sys.exit(1)

    backup_utility = DatabaseBackupUtility(default_config)
    backup_utility.perform_backup()

if __name__ == "__main__":
    main()