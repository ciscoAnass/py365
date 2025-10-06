import scapy.all as scapy
import argparse
import sys
import socket
import json
import base64
import threading
import queue
import time
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor

@dataclass
class PacketInfo:
    timestamp: float
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    payload_size: int
    payload_summary: str

class PacketSniffer:
    def __init__(self, interface: str, output_mode: str = 'console'):
        self.interface = interface
        self.output_mode = output_mode
        self.packet_queue = queue.Queue(maxsize=1000)
        self.captured_packets: List[PacketInfo] = []
        self.stop_event = threading.Event()

    def _classify_protocol(self, packet) -> str:
        if scapy.TCP in packet:
            if packet[scapy.TCP].dport == 80 or packet[scapy.TCP].sport == 80:
                return 'HTTP'
            if packet[scapy.TCP].dport == 443 or packet[scapy.TCP].sport == 443:
                return 'HTTPS'
            return 'TCP'
        elif scapy.UDP in packet:
            if packet[scapy.UDP].dport == 53 or packet[scapy.UDP].sport == 53:
                return 'DNS'
            return 'UDP'
        elif scapy.ICMP in packet:
            return 'ICMP'
        return 'Unknown'

    def _extract_packet_info(self, packet) -> Optional[PacketInfo]:
        try:
            if scapy.IP not in packet:
                return None

            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            protocol = self._classify_protocol(packet)

            src_port = dst_port = None
            if scapy.TCP in packet:
                src_port = packet[scapy.TCP].sport
                dst_port = packet[scapy.TCP].dport
            elif scapy.UDP in packet:
                src_port = packet[scapy.UDP].sport
                dst_port = packet[scapy.UDP].dport

            payload = packet.payload
            payload_size = len(payload)
            payload_summary = str(payload)[:100] if payload else ''

            return PacketInfo(
                timestamp=time.time(),
                protocol=protocol,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                payload_size=payload_size,
                payload_summary=payload_summary
            )
        except Exception:
            return None

    def _packet_handler(self, packet):
        packet_info = self._extract_packet_info(packet)
        if packet_info:
            try:
                self.packet_queue.put_nowait(packet_info)
            except queue.Full:
                pass

    def _console_output(self):
        while not self.stop_event.is_set():
            try:
                packet = self.packet_queue.get(timeout=1)
                print(f"[{packet.protocol}] {packet.src_ip}:{packet.src_port} -> {packet.dst_ip}:{packet.dst_port}")
                print(f"  Payload Size: {packet.payload_size}")
                print(f"  Payload Summary: {packet.payload_summary}\n")
                self.captured_packets.append(packet)
            except queue.Empty:
                continue

    def _json_output(self):
        while not self.stop_event.is_set():
            try:
                packet = self.packet_queue.get(timeout=1)
                self.captured_packets.append(packet)
            except queue.Empty:
                continue

    def start_capture(self, duration: Optional[int] = None):
        print(f"Starting packet capture on interface {self.interface}")
        
        output_thread = threading.Thread(
            target=self._console_output if self.output_mode == 'console' else self._json_output
        )
        output_thread.start()

        try:
            if duration:
                scapy.sniff(
                    iface=self.interface, 
                    prn=self._packet_handler, 
                    store=False, 
                    timeout=duration
                )
            else:
                scapy.sniff(
                    iface=self.interface, 
                    prn=self._packet_handler, 
                    store=False
                )
        except Exception as e:
            print(f"Error during packet capture: {e}")
        finally:
            self.stop_event.set()
            output_thread.join()

    def export_results(self, filename: str = 'packet_capture.json'):
        with open(filename, 'w') as f:
            json.dump([asdict(packet) for packet in self.captured_packets], f, indent=2)
        print(f"Exported {len(self.captured_packets)} packets to {filename}")

def main():
    parser = argparse.ArgumentParser(description='Advanced Packet Sniffer')
    parser.add_argument('-i', '--interface', required=True, help='Network interface to sniff')
    parser.add_argument('-d', '--duration', type=int, help='Capture duration in seconds')
    parser.add_argument('-o', '--output', choices=['console', 'json'], default='console')
    parser.add_argument('-e', '--export', help='Export results to JSON file')
    
    args = parser.parse_args()

    try:
        sniffer = PacketSniffer(args.interface, args.output)
        sniffer.start_capture(args.duration)
        
        if args.export:
            sniffer.export_results(args.export)
    except PermissionError:
        print("Error: Need root/admin privileges to capture packets")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nCapture stopped by user")

if __name__ == '__main__':
    main()