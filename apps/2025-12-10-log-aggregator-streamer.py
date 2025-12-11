```python
#!/usr/bin/env python3
"""
Log Aggregator Streamer - A DevOps utility for tailing multiple log files
and streaming them to various backends (Kafka, ElasticSearch, TCP socket).

This script monitors multiple log files using glob patterns and streams
their contents to a central receiver in a unified format.
"""

import os
import sys
import glob
import time
import json
import socket
import threading
import argparse
import logging
import hashlib
from datetime import datetime
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, asdict
from enum import Enum
from queue import Queue, Empty
import re


class BackendType(Enum):
    """Enumeration of supported backend types."""
    TCP = "tcp"
    KAFKA = "kafka"
    ELASTICSEARCH = "elasticsearch"
    FILE = "file"


@dataclass
class LogEntry:
    """Data class representing a single log entry."""
    timestamp: str
    hostname: str
    source_file: str
    log_level: str
    message: str
    raw_line: str
    
    def to_json(self) -> str:
        """Convert log entry to JSON string."""
        return json.dumps(asdict(self))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert log entry to dictionary."""
        return asdict(self)


class LogLevelDetector:
    """Detects and extracts log levels from log lines."""
    
    LOG_LEVEL_PATTERNS = {
        'ERROR': re.compile(r'\bERROR\b|\bERR\b', re.IGNORECASE),
        'WARNING': re.compile(r'\bWARNING\b|\bWARN\b', re.IGNORECASE),
        'INFO': re.compile(r'\bINFO\b', re.IGNORECASE),
        'DEBUG': re.compile(r'\bDEBUG\b', re.IGNORECASE),
        'CRITICAL': re.compile(r'\bCRITICAL\b|\bFATAL\b', re.IGNORECASE),
    }
    
    @staticmethod
    def detect_level(line: str) -> str:
        """Detect log level from a log line."""
        for level, pattern in LogLevelDetector.LOG_LEVEL_PATTERNS.items():
            if pattern.search(line):
                return level
        return 'INFO'


class FileTracker:
    """Tracks file positions and metadata for tailing."""
    
    def __init__(self):
        """Initialize file tracker."""
        self.file_positions: Dict[str, int] = {}
        self.file_inodes: Dict[str, int] = {}
        self.file_handles: Dict[str, Any] = {}
        self.lock = threading.Lock()
    
    def get_position(self, filepath: str) -> int:
        """Get current position for a file."""
        with self.lock:
            return self.file_positions.get(filepath, 0)
    
    def set_position(self, filepath: str, position: int) -> None:
        """Set current position for a file."""
        with self.lock:
            self.file_positions[filepath] = position
    
    def get_inode(self, filepath: str) -> Optional[int]:
        """Get inode for a file."""
        with self.lock:
            return self.file_inodes.get(filepath)
    
    def set_inode(self, filepath: str, inode: int) -> None:
        """Set inode for a file."""
        with self.lock:
            self.file_inodes[filepath] = inode
    
    def get_file_handle(self, filepath: str) -> Optional[Any]:
        """Get file handle for a file."""
        with self.lock:
            return self.file_handles.get(filepath)
    
    def set_file_handle(self, filepath: str, handle: Any) -> None:
        """Set file handle for a file."""
        with self.lock:
            self.file_handles[filepath] = handle
    
    def close_file_handle(self, filepath: str) -> None:
        """Close file handle for a file."""
        with self.lock:
            if filepath in self.file_handles:
                try:
                    self.file_handles[filepath].close()
                except Exception:
                    pass
                del self.file_handles[filepath]
    
    def remove_file(self, filepath: str) -> None:
        """Remove file from tracking."""
        with self.lock:
            self.close_file_handle(filepath)
            self.file_positions.pop(filepath, None)
            self.file_inodes.pop(filepath, None)


class LogTailer:
    """Tails multiple log files and yields new lines."""
    
    def __init__(self, glob_patterns: List[str], poll_interval: float = 1.0):
        """
        Initialize log tailer.
        
        Args:
            glob_patterns: List of glob patterns to match log files
            poll_interval: Interval in seconds between polling for new files
        """
        self.glob_patterns = glob_patterns
        self.poll_interval = poll_interval
        self.tracker = FileTracker()
        self.logger = logging.getLogger(__name__)
        self.known_files: set = set()
    
    def get_matching_files(self) -> List[str]:
        """Get all files matching the glob patterns."""
        files = []
        for pattern in self.glob_patterns:
            matched = glob.glob(pattern, recursive=True)
            files.extend(matched)
        return sorted(list(set(files)))
    
    def get_file_inode(self, filepath: str) -> Optional[int]:
        """Get inode for a file."""
        try:
            return os.stat(filepath).st_ino
        except OSError:
            return None
    
    def file_was_rotated(self, filepath: str) -> bool:
        """Check if a file was rotated (inode changed)."""
        current_inode = self.get_file_inode(filepath)
        if current_inode is None:
            return False
        
        stored_inode = self.tracker.get_inode(filepath)
        if stored_inode is None:
            return False
        
        return current_inode != stored_inode
    
    def open_file(self, filepath: str) -> Optional[Any]:
        """Open a file for reading."""
        try:
            handle = open(filepath, 'r', encoding='utf-8', errors='replace')
            inode = self.get_file_inode(filepath)
            self.tracker.set_inode(filepath, inode)
            self.tracker.set_file_handle(filepath, handle)
            return handle
        except IOError as e:
            self.logger.warning(f"Failed to open {filepath}: {e}")
            return None
    
    def tail_file(self, filepath: str) -> List[str]:
        """Tail a single file and return new lines."""
        lines = []
        
        # Check if file was rotated
        if filepath in self.known_files and self.file_was_rotated(filepath):
            self.logger.info(f"File rotation detected for {filepath}")
            self.tracker.remove_file(filepath)
        
        # Open file if not already open
        handle = self.tracker.get_file_handle(filepath)
        if handle is None:
            handle = self.open_file(filepath)
            if handle is None:
                return lines
        
        try:
            # Seek to last known position
            position = self.tracker.get_position(filepath)
            handle.seek(position)
            
            # Read new lines
            for line in handle:
                line = line.rstrip('\n\r')
                if line:
                    lines.append(line)
            
            # Update position
            new_position = handle.tell()
            self.tracker.set_position(filepath, new_position)
            
        except IOError as e:
            self.logger.warning(f"Error reading {filepath}: {e}")
            self.tracker.close_file_handle(filepath)
        
        return lines
    
    def tail_all_files(self) -> List[tuple]:
        """Tail all matching files and return (filepath, line) tuples."""
        current_files = set(self.get_matching_files())
        
        # Handle removed files
        removed_files = self.known_files - current_files
        for filepath in removed_files:
            self.logger.info(f"File removed: {filepath}")
            self.tracker.remove_file(filepath)
        
        self.known_files = current_files
        
        # Tail all files
        results = []
        for filepath in sorted(current_files):
            lines = self.tail_file(filepath)
            for line in lines:
                results.append((filepath, line))
        
        return results
    
    def stream(self) -> None:
        """Generator that yields (filepath, line) tuples continuously."""
        while True:
            results = self.tail_all_files()
            for filepath, line in results:
                yield filepath, line
            time.sleep(self.poll_interval)


class LogFormatter:
    """Formats log entries into unified format."""
    
    def __init__(self, hostname: Optional[str] = None):
        """
        Initialize log formatter.
        
        Args:
            hostname: Hostname to use in log entries (defaults to system hostname)
        """
        self.hostname = hostname or socket.gethostname()
        self.level_detector = LogLevelDetector()
    
    def format_entry(self, filepath: str, line: str) -> LogEntry:
        """Format a raw log line into a LogEntry."""
        timestamp = datetime.utcnow().isoformat() + 'Z'
        log_level = self.level_detector.detect_level(line)
        
        return LogEntry(
            timestamp=timestamp,
            hostname=self.hostname,
            source_file=filepath,
            log_level=log_level,
            message=line[:1000],  # Limit message length
            raw_line=line
        )


class Backend:
    """Base class for log backends."""
    
    def __init__(self):
        """Initialize backend."""
        self.logger = logging.getLogger(__name__)
    
    def send(self, entry: LogEntry) -> bool:
        """Send a log entry to the backend."""
        raise NotImplementedError
    
    def close(self) -> None:
        """Close the backend connection."""
        pass


class TCPBackend(Backend):
    """TCP socket backend for sending logs."""
    
    def __init__(self, host: str, port: int, timeout: float = 5.0):
        """
        Initialize TCP backend.
        
        Args:
            host: Target host
            port: Target port
            timeout: Socket timeout in seconds
        """
        super().__init__()
        self.host = host
        self.port = port
        self.timeout = timeout
        self.socket = None
        self.connect()
    
    def connect(self) -> bool:
        """Establish TCP connection."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.timeout)
            self.socket.connect((self.host, self.port))
            self.logger.info(f"Connected to TCP backend at {self.host}:{self.port}")
            return True
        except socket.error as e:
            self.logger.error(f"Failed to connect to TCP backend: {e}")
            self.socket = None
            return False
    
    def send(self, entry: LogEntry) -> bool:
        """Send log entry via TCP."""
        if self.socket is None:
            if not self.connect():
                return False
        
        try:
            message = entry.to_json() + '\n'
            self.socket.sendall(message.encode('utf-8'))
            return True
        except socket.error as e:
            self.logger.error(f"Failed to send via TCP: {e}")
            self.socket = None
            return False
    
    def close(self) -> None:
        """Close TCP connection."""
        if self.socket:
            try:
                self.socket.close()
            except Exception:
                pass
            self.socket = None


class FileBackend(Backend):
    """File backend for writing logs to a file."""
    
    def __init__(self, filepath: str):
        """
        Initialize file backend.
        
        Args:
            filepath: Path to output file
        """
        super().__init__()
        self.filepath = filepath
        self.file_handle = None
        self.open_file()
    
    def open_file(self) -> bool:
        """Open output file."""
        try:
            self.file_handle = open(self.filepath, 'a', encoding='utf-8')
            self.logger.info(f"Opened file backend at {self.filepath}")
            return True
        except IOError as e:
            self.logger.error(f"Failed to open file backend: {e}")
            return False
    
    def send(self, entry: LogEntry) -> bool:
        """Write log entry to file."""
        if self.file_handle is None:
            if not self.open_file():
                return False
        
        try:
            self.file_handle.write(entry.to_json() + '\n')
            self.file_handle.flush()
            return True
        except IOError as e:
            self.logger.error(f"Failed to write to file backend: {e}")
            return False
    
    def close(self) -> None:
        """Close file."""
        if self.file_handle:
            try:
                self.file_handle.close()
            except Exception:
                pass
            self.file_handle = None


class KafkaBackend(Backend):
    """Kafka backend for sending logs (requires kafka-python)."""
    
    def __init__(self, bootstrap_servers: List[str], topic: str):
        """
        Initialize Kafka backend.
        
        Args:
            bootstrap_servers: List of Kafka bootstrap servers
            topic: Kafka topic to send logs to
        """
        super().__init__()
        self.bootstrap_servers = bootstrap_servers
        self.topic = topic
        self.producer = None
        self.connect()
    
    def connect(self) -> bool:
        """Establish Kafka connection."""
        try:
            from kafka import KafkaProducer
            self.producer = KafkaProducer(
                bootstrap_servers=self.bootstrap_servers,
                value_serializer=lambda v: v.encode('utf-8')
            )
            self.logger.info(f"Connected to Kafka at {self.bootstrap_servers}")
            return True
        except ImportError:
            self.logger.error("kafka-python not installed. Install with: pip install kafka-python")
            return False
        except Exception as e:
            self.logger.error(f"Failed to connect to Kafka: {e}")
            return False
    
    def send(self, entry: LogEntry) -> bool:
        """Send log entry to Kafka."""
        if self.producer is None:
            return False
        
        try:
            self.producer.send(self.topic, value=entry.to_json())
            return True
        except Exception as e:
            self.logger.error(f"Failed to send to Kafka: {e}")
            return False
    
    def close(self) -> None:
        """Close Kafka connection."""
        if self.producer:
            try:
                self.producer.close()
            except Exception:
                pass
            self.producer = None


class ElasticsearchBackend(Backend):
    """Elasticsearch backend for sending logs (requires elasticsearch)."""
    
    def __init__(self, hosts: List[str], index: str = "logs"):
        """
        Initialize Elasticsearch backend.
        
        Args:
            hosts: List of