import os
import sys
import shutil
import time
import heapq
from collections import defaultdict

def get_directory_sizes(path):
    """
    Recursively scan the specified filesystem path and aggregate the file sizes by directory.
    
    Args:
        path (str): The filesystem path to scan.
    
    Returns:
        dict: A dictionary where the keys are directory paths and the values are the total file sizes in bytes.
    """
    directory_sizes = defaultdict(int)
    
    for root, dirs, files in os.walk(path):
        for file in files:
            file_path = os.path.join(root, file)
            directory_sizes[root] += os.path.getsize(file_path)
        
        for dir in dirs:
            dir_path = os.path.join(root, dir)
            directory_sizes.update(get_directory_sizes(dir_path))
    
    return directory_sizes

def format_size(size_in_bytes):
    """
    Convert a file size in bytes to a human-readable format.
    
    Args:
        size_in_bytes (int): The file size in bytes.
    
    Returns:
        str: The file size in a human-readable format (e.g., "1.2 GB").
    """
    size_units = ["B", "KB", "MB", "GB", "TB"]
    
    if size_in_bytes == 0:
        return "0 B"
    
    i = 0
    while size_in_bytes >= 1024 and i < len(size_units) - 1:
        size_in_bytes /= 1024
        i += 1
    
    return f"{size_in_bytes:.2f} {size_units[i]}"

def print_directory_sizes(directory_sizes, top_n=10):
    """
    Print the top N largest directories in the filesystem.
    
    Args:
        directory_sizes (dict): A dictionary where the keys are directory paths and the values are the total file sizes in bytes.
        top_n (int, optional): The number of largest directories to display. Defaults to 10.
    """
    sorted_sizes = heapq.nlargest(top_n, directory_sizes.items(), key=lambda x: x[1])
    
    print("Disk Usage Report:")
    print("------------------")
    
    for directory, size in sorted_sizes:
        print(f"{format_size(size)}\t{directory}")

def main():
    """
    The main entry point of the disk usage analyzer script.
    """
    if len(sys.argv) < 2:
        print("Usage: python disk_usage_analyzer.py <path>")
        sys.exit(1)
    
    path = sys.argv[1]
    
    if not os.path.exists(path):
        print(f"Error: {path} does not exist.")
        sys.exit(1)
    
    if not os.path.isdir(path):
        print(f"Error: {path} is not a directory.")
        sys.exit(1)
    
    start_time = time.time()
    directory_sizes = get_directory_sizes(path)
    end_time = time.time()
    
    print_directory_sizes(directory_sizes)
    
    print(f"\nScan completed in {end_time - start_time:.2f} seconds.")

if __name__ == "__main__":
    main()