import os
import sys
import time
import shutil
import hashlib
import logging
import subprocess
import threading
import argparse
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class ConfigVersionController:
    def __init__(self, watch_dir, repo_dir=None, log_level=logging.INFO):
        self.watch_dir = os.path.abspath(watch_dir)
        self.repo_dir = repo_dir or os.path.join(self.watch_dir, '.config_version_control')
        self.log_file = os.path.join(self.repo_dir, 'config_version.log')
        
        self.setup_logging(log_level)
        self.initialize_repository()
        
    def setup_logging(self, log_level):
        os.makedirs(self.repo_dir, exist_ok=True)
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s: %(message)s',
            handlers=[
                logging.FileHandler(self.log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def initialize_repository(self):
        try:
            if not os.path.exists(os.path.join(self.repo_dir, '.git')):
                subprocess.run(['git', 'init', self.repo_dir], check=True)
                self.logger.info(f"Initialized Git repository in {self.repo_dir}")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to initialize repository: {e}")
            sys.exit(1)
        
    def compute_file_hash(self, filepath):
        hasher = hashlib.sha256()
        with open(filepath, 'rb') as f:
            hasher.update(f.read())
        return hasher.hexdigest()
    
    def copy_to_repo(self, source_file):
        relative_path = os.path.relpath(source_file, self.watch_dir)
        dest_path = os.path.join(self.repo_dir, relative_path)
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        shutil.copy2(source_file, dest_path)
        return dest_path
    
    def git_commit(self, filepath, change_type):
        try:
            repo_filepath = self.copy_to_repo(filepath)
            
            subprocess.run(['git', '-C', self.repo_dir, 'add', repo_filepath], check=True)
            
            commit_message = f"{change_type.capitalize()} configuration: {os.path.basename(filepath)}"
            subprocess.run([
                'git', '-C', self.repo_dir, 
                'commit', 
                '-m', commit_message,
                '--author', '"Config Version Control <config@localhost>"'
            ], check=True)
            
            self.logger.info(f"Committed {change_type} for {filepath}")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Git commit failed: {e}")
        
class ConfigFileHandler(FileSystemEventHandler):
    def __init__(self, version_controller):
        self.version_controller = version_controller
        self.last_hashes = {}
        
    def on_modified(self, event):
        if not event.is_directory:
            self.process_file_change(event.src_path, 'modified')
            
    def on_created(self, event):
        if not event.is_directory:
            self.process_file_change(event.src_path, 'created')
            
    def on_deleted(self, event):
        if not event.is_directory:
            self.process_file_change(event.src_path, 'deleted')
            
    def process_file_change(self, filepath, change_type):
        try:
            current_hash = self.version_controller.compute_file_hash(filepath)
            last_hash = self.last_hashes.get(filepath)
            
            if current_hash != last_hash or change_type in ['created', 'deleted']:
                self.version_controller.git_commit(filepath, change_type)
                self.last_hashes[filepath] = current_hash
        except FileNotFoundError:
            self.version_controller.logger.warning(f"File not found: {filepath}")
        except Exception as e:
            self.version_controller.logger.error(f"Error processing {filepath}: {e}")

def main():
    parser = argparse.ArgumentParser(description='Configuration File Version Control')
    parser.add_argument('directory', help='Directory to watch for configuration changes')
    parser.add_argument('--repo', help='Optional repository directory', default=None)
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], default='INFO')
    args = parser.parse_args()
    
    log_level = getattr(logging, args.log_level.upper())
    
    version_controller = ConfigVersionController(
        watch_dir=args.directory, 
        repo_dir=args.repo, 
        log_level=log_level
    )
    
    event_handler = ConfigFileHandler(version_controller)
    observer = Observer()
    observer.schedule(event_handler, version_controller.watch_dir, recursive=True)
    
    try:
        observer.start()
        version_controller.logger.info(f"Watching directory: {version_controller.watch_dir}")
        
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    
    observer.join()

if __name__ == '__main__':
    main()