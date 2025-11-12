import os
import shutil
import gzip
import boto3
from datetime import datetime
from pathlib import Path

def get_large_log_files(log_dir, min_size_mb=100):
    """
    Identifies large log files in the specified directory.
    
    Args:
        log_dir (str): The directory containing the log files.
        min_size_mb (int): The minimum file size in megabytes to consider a file "large".
        
    Returns:
        list: A list of file paths for large log files.
    """
    large_files = []
    for root, dirs, files in os.walk(log_dir):
        for file in files:
            file_path = os.path.join(root, file)
            file_size = os.path.getsize(file_path) / (1024 * 1024)
            if file_size >= min_size_mb:
                large_files.append(file_path)
    return large_files

def compress_log_file(log_file_path):
    """
    Compresses a log file using gzip.
    
    Args:
        log_file_path (str): The path of the log file to compress.
    """
    with open(log_file_path, 'rb') as f_in, gzip.open(f"{log_file_path}.gz", 'wb') as f_out:
        shutil.copyfileobj(f_in, f_out)

def upload_to_s3(log_file_path, s3_bucket, s3_key):
    """
    Uploads a compressed log file to an S3 bucket.
    
    Args:
        log_file_path (str): The path of the compressed log file.
        s3_bucket (str): The name of the S3 bucket to upload to.
        s3_key (str): The key (file path) to use for the uploaded file in S3.
    """
    s3 = boto3.client('s3')
    with open(log_file_path, 'rb') as f:
        s3.upload_fileobj(f, s3_bucket, s3_key)

def truncate_log_file(log_file_path):
    """
    Truncates a log file to free up disk space.
    
    Args:
        log_file_path (str): The path of the log file to truncate.
    """
    with open(log_file_path, 'w'):
        pass

def rotate_log_files(log_dir, s3_bucket, min_size_mb=100):
    """
    Rotates log files by compressing, archiving, and truncating large log files.
    
    Args:
        log_dir (str): The directory containing the log files.
        s3_bucket (str): The name of the S3 bucket to upload the archived log files to.
        min_size_mb (int): The minimum file size in megabytes to consider a file "large".
    """
    large_log_files = get_large_log_files(log_dir, min_size_mb)
    for log_file_path in large_log_files:
        # Compress the log file
        compress_log_file(log_file_path)
        
        # Upload the compressed log file to S3
        s3_key = f"log_archives/{os.path.basename(log_file_path)}.gz"
        upload_to_s3(f"{log_file_path}.gz", s3_bucket, s3_key)
        
        # Truncate the original log file
        truncate_log_file(log_file_path)

def main():
    """
    The main function that runs the log file rotation process.
    """
    log_dir = "/var/log"
    s3_bucket = "my-log-archive-bucket"
    rotate_log_files(log_dir, s3_bucket)

if __name__ == "__main__":
    main()