import os
import hashlib
import time
import json
import threading
import logging
import sqlite3
import argparse
import platform
import socket
import uuid
import sys
from datetime import datetime, timedelta

class FileIntegrityMonitor:
    def __init__(self, config_path=None, log_path=None, db_path=None):
        self.hostname = socket.gethostname()
        self.machine_id = str(uuid.getnode())
        self.os_info = platform.platform()
        
        self.config_path = config_path or os.path.join(os.path.expanduser('~'), '.fim_config.json')
        self.log_path = log_path or os.path.join(os.path.expanduser('~'), 'fim_monitor.log')
        self.db_path = db_path or os.path.join(os.path.expanduser('~'), 'fim_database.sqlite')
        
        self.setup_logging()
        self.setup_database()
        self.load_config()
        
    def setup_logging(self):
        logging.basicConfig(
            filename=self.log_path,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s: %(message)s'
        )
        
    def setup_database(self):
        try:
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.cursor = self.conn.cursor()
            
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS file_hashes (
                    path TEXT PRIMARY KEY,
                    hash TEXT,
                    last_modified DATETIME,
                    size INTEGER,
                    permissions TEXT
                )
            ''')
            
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS integrity_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT,
                    event_type TEXT,
                    timestamp DATETIME,
                    details TEXT
                )
            ''')
            
            self.conn.commit()
        except Exception as e:
            logging.error(f"Database setup failed: {e}")
            sys.exit(1)
        
    def load_config(self):
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    self.config = json.load(f)
            else:
                self.config = {
                    'monitored_paths': [
                        '/etc/passwd',
                        '/etc/shadow',
                        '/etc/sudoers',
                        '/boot/grub/grub.cfg'
                    ],
                    'scan_interval_seconds': 300,
                    'hash_algorithm': 'sha256'
                }
                with open(self.config_path, 'w') as f:
                    json.dump(self.config, f, indent=4)
        except Exception as e:
            logging.error(f"Config loading failed: {e}")
            sys.exit(1)
        
    def calculate_file_hash(self, filepath):
        try:
            hasher = hashlib.new(self.config['hash_algorithm'])
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            logging.warning(f"Hash calculation failed for {filepath}: {e}")
            return None
        
    def record_file_hash(self, filepath):
        try:
            file_hash = self.calculate_file_hash(filepath)
            file_stat = os.stat(filepath)
            
            self.cursor.execute('''
                INSERT OR REPLACE INTO file_hashes 
                (path, hash, last_modified, size, permissions) 
                VALUES (?, ?, ?, ?, ?)
            ''', (
                filepath, 
                file_hash, 
                datetime.fromtimestamp(file_stat.st_mtime),
                file_stat.st_size,
                oct(file_stat.st_mode)[-3:]
            ))
            self.conn.commit()
        except Exception as e:
            logging.error(f"Recording hash failed for {filepath}: {e}")
        
    def check_file_integrity(self):
        for filepath in self.config['monitored_paths']:
            if not os.path.exists(filepath):
                self.log_integrity_event(filepath, 'FILE_DELETED')
                continue
            
            current_hash = self.calculate_file_hash(filepath)
            
            self.cursor.execute('SELECT hash FROM file_hashes WHERE path = ?', (filepath,))
            result = self.cursor.fetchone()
            
            if result is None:
                self.record_file_hash(filepath)
                self.log_integrity_event(filepath, 'FILE_ADDED')
            elif result[0] != current_hash:
                self.log_integrity_event(filepath, 'FILE_MODIFIED', 
                                         details=f"Old Hash: {result[0]}, New Hash: {current_hash}")
                self.record_file_hash(filepath)
        
    def log_integrity_event(self, filepath, event_type, details=''):
        try:
            self.cursor.execute('''
                INSERT INTO integrity_events 
                (file_path, event_type, timestamp, details) 
                VALUES (?, ?, ?, ?)
            ''', (filepath, event_type, datetime.now(), details))
            self.conn.commit()
            logging.warning(f"{event_type}: {filepath} - {details}")
        except Exception as e:
            logging.error(f"Event logging failed: {e}")
        
    def start_monitoring(self):
        def monitor_thread():
            while True:
                self.check_file_integrity()
                time.sleep(self.config['scan_interval_seconds'])
        
        thread = threading.Thread(target=monitor_thread, daemon=True)
        thread.start()
        
    def generate_report(self):
        self.cursor.execute('SELECT * FROM integrity_events ORDER BY timestamp DESC LIMIT 50')
        return self.cursor.fetchall()
    
def main():
    parser = argparse.ArgumentParser(description='File Integrity Monitor')
    parser.add_argument('--config', help='Custom config path')
    parser.add_argument('--log', help='Custom log path')
    parser.add_argument('--db', help='Custom database path')
    
    args = parser.parse_args()
    
    fim = FileIntegrityMonitor(
        config_path=args.config,
        log_path=args.log,
        db_path=args.db
    )
    
    fim.start_monitoring()
    
    try:
        while True:
            time.sleep(3600)  # Keep main thread alive
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")
        
if __name__ == '__main__':
    main()