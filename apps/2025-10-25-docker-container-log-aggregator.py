import docker
import sys
import threading
import queue
import logging
import argparse
import os
import time
from typing import List, Optional
from datetime import datetime

class DockerLogAggregator:
    def __init__(self, containers: Optional[List[str]] = None, output_file: Optional[str] = None, log_level: str = 'INFO'):
        self.client = docker.from_env()
        self.containers = containers or [container.name for container in self.client.containers.list()]
        self.output_file = output_file
        self.log_queue = queue.Queue()
        self.stop_event = threading.Event()
        
        logging.basicConfig(
            level=getattr(logging, log_level.upper()),
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def _log_consumer(self):
        file_handler = None
        if self.output_file:
            file_handler = open(self.output_file, 'a')

        try:
            while not self.stop_event.is_set():
                try:
                    log_entry = self.log_queue.get(timeout=1)
                    formatted_log = f"[{log_entry['container']}] {log_entry['message']}"
                    
                    if file_handler:
                        file_handler.write(formatted_log + '\n')
                        file_handler.flush()
                    
                    print(formatted_log)
                except queue.Empty:
                    continue
        finally:
            if file_handler:
                file_handler.close()

    def _log_producer(self, container_name):
        try:
            container = self.client.containers.get(container_name)
            for log_line in container.logs(stream=True, follow=True):
                if self.stop_event.is_set():
                    break
                
                log_entry = {
                    'container': container_name,
                    'message': log_line.decode('utf-8').strip()
                }
                self.log_queue.put(log_entry)
        except Exception as e:
            self.logger.error(f"Error fetching logs for {container_name}: {e}")

    def start(self):
        self.logger.info(f"Starting log aggregation for containers: {self.containers}")
        
        consumer_thread = threading.Thread(target=self._log_consumer)
        consumer_thread.start()

        producer_threads = []
        for container_name in self.containers:
            producer_thread = threading.Thread(target=self._log_producer, args=(container_name,))
            producer_thread.start()
            producer_threads.append(producer_thread)

        try:
            for thread in producer_threads:
                thread.join()
        except KeyboardInterrupt:
            self.logger.info("Interrupt received. Stopping log aggregation...")
            self.stop_event.set()
        finally:
            self.stop_event.set()
            consumer_thread.join()

def main():
    parser = argparse.ArgumentParser(description='Docker Container Log Aggregator')
    parser.add_argument('-c', '--containers', nargs='+', help='List of container names to aggregate logs from')
    parser.add_argument('-o', '--output', help='Output file path for logs')
    parser.add_argument('-l', '--log-level', default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], help='Logging level')
    
    args = parser.parse_args()
    
    aggregator = DockerLogAggregator(
        containers=args.containers,
        output_file=args.output,
        log_level=args.log_level
    )
    
    aggregator.start()

if __name__ == '__main__':
    main()