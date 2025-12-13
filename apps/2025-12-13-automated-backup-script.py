```python
#!/usr/bin/env python3
"""
Automated Backup Script for System Administrators
This script provides comprehensive backup functionality including:
- Directory archiving using tar
- Database dumping using mysqldump
- Secure file transfer using rsync or boto3 (S3)
- Logging and error handling
- Configuration file support
- Scheduling capabilities
"""

import os
import sys
import json
import logging
import subprocess
import argparse
import datetime
import shutil
import tempfile
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum
import time
import signal


class BackupType(Enum):
    """Enumeration for different backup types"""
    DIRECTORY = "directory"
    DATABASE = "database"
    COMBINED = "combined"


class TransferMethod(Enum):
    """Enumeration for transfer methods"""
    RSYNC = "rsync"
    S3 = "s3"
    LOCAL = "local"


@dataclass
class BackupConfig:
    """Configuration dataclass for backup operations"""
    backup_name: str
    backup_type: str
    source_path: Optional[str] = None
    database_name: Optional[str] = None
    database_user: Optional[str] = None
    database_password: Optional[str] = None
    database_host: str = "localhost"
    database_port: int = 3306
    destination_path: str = "/tmp/backups"
    transfer_method: str = "local"
    rsync_host: Optional[str] = None
    rsync_user: Optional[str] = None
    rsync_path: Optional[str] = None
    s3_bucket: Optional[str] = None
    s3_region: str = "us-east-1"
    s3_prefix: str = "backups/"
    compression: str = "gzip"
    retention_days: int = 30
    verify_checksum: bool = True
    exclude_patterns: List[str] = None
    include_patterns: List[str] = None
    pre_backup_script: Optional[str] = None
    post_backup_script: Optional[str] = None
    enable_logging: bool = True
    log_file: Optional[str] = None
    max_retries: int = 3
    retry_delay: int = 5


class BackupLogger:
    """Custom logger for backup operations"""
    
    def __init__(self, log_file: Optional[str] = None, enable_console: bool = True):
        """Initialize the backup logger"""
        self.logger = logging.getLogger("BackupScript")
        self.logger.setLevel(logging.DEBUG)
        
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        if enable_console:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(logging.INFO)
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)
        
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
    
    def info(self, message: str) -> None:
        """Log info message"""
        self.logger.info(message)
    
    def debug(self, message: str) -> None:
        """Log debug message"""
        self.logger.debug(message)
    
    def warning(self, message: str) -> None:
        """Log warning message"""
        self.logger.warning(message)
    
    def error(self, message: str) -> None:
        """Log error message"""
        self.logger.error(message)
    
    def critical(self, message: str) -> None:
        """Log critical message"""
        self.logger.critical(message)


class DirectoryBackup:
    """Handles directory backup operations"""
    
    def __init__(self, config: BackupConfig, logger: BackupLogger):
        """Initialize directory backup handler"""
        self.config = config
        self.logger = logger
        self.backup_file = None
    
    def validate_source(self) -> bool:
        """Validate that source directory exists"""
        if not self.config.source_path:
            self.logger.error("Source path not specified for directory backup")
            return False
        
        if not os.path.exists(self.config.source_path):
            self.logger.error(f"Source path does not exist: {self.config.source_path}")
            return False
        
        if not os.path.isdir(self.config.source_path):
            self.logger.error(f"Source path is not a directory: {self.config.source_path}")
            return False
        
        self.logger.info(f"Source directory validated: {self.config.source_path}")
        return True
    
    def build_tar_command(self) -> List[str]:
        """Build tar command with appropriate options"""
        command = ["tar"]
        
        if self.config.compression == "gzip":
            command.append("-czf")
            self.backup_file = os.path.join(
                self.config.destination_path,
                f"{self.config.backup_name}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.tar.gz"
            )
        elif self.config.compression == "bzip2":
            command.append("-cjf")
            self.backup_file = os.path.join(
                self.config.destination_path,
                f"{self.config.backup_name}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.tar.bz2"
            )
        else:
            command.append("-cf")
            self.backup_file = os.path.join(
                self.config.destination_path,
                f"{self.config.backup_name}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.tar"
            )
        
        command.append(self.backup_file)
        
        if self.config.exclude_patterns:
            for pattern in self.config.exclude_patterns:
                command.extend(["--exclude", pattern])
        
        command.append(self.config.source_path)
        
        return command
    
    def execute_backup(self) -> Tuple[bool, Optional[str]]:
        """Execute directory backup"""
        if not self.validate_source():
            return False, None
        
        os.makedirs(self.config.destination_path, exist_ok=True)
        
        command = self.build_tar_command()
        self.logger.info(f"Starting directory backup: {self.config.backup_name}")
        self.logger.debug(f"Tar command: {' '.join(command)}")
        
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=3600
            )
            
            if result.returncode != 0:
                self.logger.error(f"Tar command failed: {result.stderr}")
                return False, None
            
            if not os.path.exists(self.backup_file):
                self.logger.error(f"Backup file not created: {self.backup_file}")
                return False, None
            
            file_size = os.path.getsize(self.backup_file)
            self.logger.info(f"Directory backup completed: {self.backup_file} ({file_size} bytes)")
            
            return True, self.backup_file
        
        except subprocess.TimeoutExpired:
            self.logger.error("Tar command timed out")
            return False, None
        except Exception as e:
            self.logger.error(f"Error during directory backup: {str(e)}")
            return False, None


class DatabaseBackup:
    """Handles database backup operations"""
    
    def __init__(self, config: BackupConfig, logger: BackupLogger):
        """Initialize database backup handler"""
        self.config = config
        self.logger = logger
        self.backup_file = None
    
    def validate_database_config(self) -> bool:
        """Validate database configuration"""
        if not self.config.database_name:
            self.logger.error("Database name not specified")
            return False
        
        if not self.config.database_user:
            self.logger.error("Database user not specified")
            return False
        
        self.logger.info("Database configuration validated")
        return True
    
    def test_database_connection(self) -> bool:
        """Test connection to database"""
        command = [
            "mysql",
            "-h", self.config.database_host,
            "-P", str(self.config.database_port),
            "-u", self.config.database_user,
            "-e", "SELECT 1"
        ]
        
        if self.config.database_password:
            command.insert(4, f"-p{self.config.database_password}")
        
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                self.logger.info("Database connection test successful")
                return True
            else:
                self.logger.error(f"Database connection test failed: {result.stderr}")
                return False
        
        except FileNotFoundError:
            self.logger.error("mysql command not found. Please install MySQL client tools")
            return False
        except Exception as e:
            self.logger.error(f"Error testing database connection: {str(e)}")
            return False
    
    def execute_backup(self) -> Tuple[bool, Optional[str]]:
        """Execute database backup"""
        if not self.validate_database_config():
            return False, None
        
        if not self.test_database_connection():
            return False, None
        
        os.makedirs(self.config.destination_path, exist_ok=True)
        
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        self.backup_file = os.path.join(
            self.config.destination_path,
            f"{self.config.backup_name}_{timestamp}.sql"
        )
        
        if self.config.compression == "gzip":
            self.backup_file += ".gz"
        elif self.config.compression == "bzip2":
            self.backup_file += ".bz2"
        
        command = [
            "mysqldump",
            "-h", self.config.database_host,
            "-P", str(self.config.database_port),
            "-u", self.config.database_user,
            "--single-transaction",
            "--quick",
            "--lock-tables=false",
            self.config.database_name
        ]
        
        if self.config.database_password:
            command.insert(4, f"-p{self.config.database_password}")
        
        self.logger.info(f"Starting database backup: {self.config.backup_name}")
        self.logger.debug(f"Mysqldump command: {' '.join(command[:-1])} [database]")
        
        try:
            with open(self.backup_file, 'w') as backup_output:
                if self.config.compression == "gzip":
                    process = subprocess.Popen(
                        command,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    gzip_process = subprocess.Popen(
                        ["gzip"],
                        stdin=process.stdout,
                        stdout=backup_output,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    process.stdout.close()
                    _, gzip_err = gzip_process.communicate()
                    _, mysqldump_err = process.communicate()
                    
                    if gzip_process.returncode != 0:
                        self.logger.error(f"Gzip compression failed: {gzip_err}")
                        return False, None
                    if process.returncode != 0:
                        self.logger.error(f"Mysqldump failed: {mysqldump_err}")
                        return False, None
                
                elif self.config.compression == "bzip2":
                    process = subprocess.Popen(
                        command,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    bzip2_process = subprocess.Popen(
                        ["bzip2"],
                        stdin=process.stdout,
                        stdout=backup_output,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    process.stdout.close()
                    _, bzip2_err = bzip2_process.communicate()
                    _, mysqldump_err = process.communicate()
                    
                    if bzip2_process.returncode != 0:
                        self.logger.error(f"Bzip2 compression failed: {bzip2_err}")
                        return False, None
                    if process.returncode != 0:
                        self.logger.error(f"Mysqldump failed: {mysqldump_err}")
                        return False, None
                
                else:
                    result = subprocess.run(
                        command,
                        stdout=backup_output,
                        stderr=subprocess.PIPE,
                        text=True,
                        timeout=3600
                    )
                    
                    if result.returncode != 0:
                        self.logger.error(f"Mysqldump failed: {result.stderr}")
                        return False, None
            
            if not os.path.exists(self.backup_file):
                self.logger.error(f"Backup file not created: {self.backup_file}")
                return False, None
            
            file_size = os.path.getsize(self.backup_file)
            self.logger.info(f"Database backup completed: {self.backup_file} ({file_size} bytes)")
            
            return True, self.backup_file
        
        except subprocess.TimeoutExpired:
            self.logger.error("Mysqldump command timed out")
            return False, None
        except Exception as e:
            self.logger.error(f"Error during database backup: {str(e)}")
            return False, None


class FileTransfer:
    """Handles file transfer operations"""
    
    def __init__(self, config: BackupConfig, logger: BackupLogger):
        """Initialize file transfer handler"""
        self.config = config
        self.logger = logger
    
    def calculate_checksum(self, file_path: str) -> str:
        """Calculate SHA256 checksum of file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def transfer_via_rsync(self, source_file: str) -> bool:
        """Transfer file using rsync"""
        if not self.config.rsync_host or not self.config.rsync_user or not self.config.rsync_path:
            self.logger.error("Rsync configuration incomplete")
            return False
        
        destination = f"{self.config.rsync_user}@{self.config.rsync_host}:{self.config.rsync_path}"
        command = [
            "rsync",
            "-avz",
            "--progress",
            "--checksum",
            source_file,
            destination
        ]