import os
import hashlib
import sqlite3
import time
import datetime
import logging
import argparse

def get_file_hash(filepath):
    """
    Calculate the SHA256 hash of a given file.
    
    Args:
        filepath (str): The path to the file.
    
    Returns:
        str: The SHA256 hash of the file.
    """
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while True:
            data = f.read(65536)
            if not data:
                break
            sha256.update(data)
    return sha256.hexdigest()

def scan_directory(directory, baseline_db):
    """
    Recursively scan a directory, calculate the SHA256 hash of each file, and store the results in a SQLite database.
    
    Args:
        directory (str): The path to the directory to scan.
        baseline_db (sqlite3.Connection): The connection to the SQLite database.
    """
    cursor = baseline_db.cursor()
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            try:
                file_hash = get_file_hash(filepath)
                cursor.execute("INSERT INTO baseline (filepath, hash) VALUES (?, ?)", (filepath, file_hash))
            except Exception as e:
                logging.error(f"Error processing file {filepath}: {e}")
    
    baseline_db.commit()

def check_integrity(directory, baseline_db):
    """
    Check the integrity of the files in a directory by comparing the current hashes to the baseline hashes stored in the database.
    
    Args:
        directory (str): The path to the directory to check.
        baseline_db (sqlite3.Connection): The connection to the SQLite database.
    
    Returns:
        dict: A dictionary containing the results of the integrity check, with keys for 'added', 'deleted', and 'modified' files.
    """
    cursor = baseline_db.cursor()
    
    added = []
    deleted = []
    modified = []
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            try:
                current_hash = get_file_hash(filepath)
                cursor.execute("SELECT hash FROM baseline WHERE filepath = ?", (filepath,))
                result = cursor.fetchone()
                if result is None:
                    added.append(filepath)
                elif current_hash != result[0]:
                    modified.append(filepath)
            except Exception as e:
                logging.error(f"Error processing file {filepath}: {e}")
    
    cursor.execute("SELECT filepath FROM baseline WHERE filepath NOT IN (SELECT filepath FROM baseline WHERE filepath IN (SELECT filepath FROM baseline WHERE filepath LIKE ?));", (f"{directory}%",))
    for row in cursor:
        deleted.append(row[0])
    
    return {'added': added, 'deleted': deleted, 'modified': modified}

def main():
    """
    The main function that sets up the script and runs the file integrity monitoring.
    """
    parser = argparse.ArgumentParser(description='File Integrity Monitor')
    parser.add_argument('--directory', '-d', type=str, required=True, help='The directory to monitor')
    parser.add_argument('--interval', '-i', type=int, default=60, help='The interval in seconds between scans')
    args = parser.parse_args()
    
    logging.basicConfig(filename='file_integrity_monitor.log', level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    
    baseline_db = sqlite3.connect('baseline.db')
    cursor = baseline_db.cursor()
    cursor.execute("""CREATE TABLE IF NOT EXISTS baseline (
                        filepath TEXT PRIMARY KEY,
                        hash TEXT NOT NULL
                    )""")
    
    logging.info(f"Starting file integrity monitoring for directory: {args.directory}")
    
    while True:
        try:
            scan_directory(args.directory, baseline_db)
            integrity_results = check_integrity(args.directory, baseline_db)
            
            if integrity_results['added']:
                logging.warning(f"Added files: {', '.join(integrity_results['added'])}")
            if integrity_results['deleted']:
                logging.warning(f"Deleted files: {', '.join(integrity_results['deleted'])}")
            if integrity_results['modified']:
                logging.warning(f"Modified files: {', '.join(integrity_results['modified'])}")
            
            time.sleep(args.interval)
        except KeyboardInterrupt:
            logging.info("Exiting file integrity monitor.")
            baseline_db.close()
            break
        except Exception as e:
            logging.error(f"Error occurred: {e}")
            baseline_db.close()
            break

if __name__ == "__main__":
    main()