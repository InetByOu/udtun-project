#!/usr/bin/env python3
"""
UDP server with blind port handling
"""

import socket
import struct
import threading
import time
import select
from typing import Optional, Tuple, Dict, Set
from collections import deque

from .config import config
from .utils import create_packet_id

class UDPServer:
    """UDP server with port range handling"""
    
    def __init__(self):
        self.socket: Optional[socket.socket] = None
        self.running = False
        self.receive_handler: Optional[Callable] = None
        self.read_thread: Optional[threading.Thread] = None
        self.keepalive_thread: Optional[threading.Thread] = None
        self.client_last_seen: Dict[Tuple[str, int], float] = {}
        self.lock = threading.Lock()
        
        # Sequence tracking for anti-replay
        self.client_sequences: Dict[Tuple[str, int], deque] = {}
    
    def bind(self) -> bool:
        """Bind to UDP port"""
        try:
            # Create UDP socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Increase buffer sizes
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, config.udp_buffer_size)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, config.udp_buffer_size)
            
            # Bind to internal port
            self.socket.bind((config.udp_bind_ip, config.internal_port))
            
            # Set non-blocking
            self.socket.setblocking(False)
            
            return True
            
        except Exception as e:
            print(f"Error binding UDP socket: {e}")
            return False
    
    def set_receive_handler(self, handler: Callable):
        """Set packet receive handler"""
        self.receive_handler = handler
    
    def start(self):
        """Start UDP server"""
        if not self.bind():
            raise RuntimeError("Failed to bind UDP socket")
        
        self.running = True
        
        # Start receive thread
        self.read_thread = threading.Thread(target=self._receive_loop, daemon=True)
        self.read_thread.start()
        
        # Start keepalive thread
        self.keepalive_thread = threading.Thread(target=self._keepalive_loop, daemon=True)
        self.keepalive_thread.start()
    
    def stop(self):
        """Stop UDP server"""
        self.running = False
        
        if self.read_thread:
            self.read_thread.join(timeout=2)
        
        if self.keepalive_thread:
            self.keepalive_thread.join(timeout=2)
        
        if self.socket:
            self.socket.close()
            self.socket = None
    
    def _receive_loop(self):
        """Receive packets from UDP socket"""
        while self.running:
            try:
                # Use select for non-blocking read
                ready, _, _ = select.select([self.socket], [], [], 0.1)
                if ready:
                    packet, addr = self.socket.recvfrom(config.max_packet_size + 8)
                    
                    if packet:
                        # Update last seen
                        with self.lock:
                            self.client_last_seen[addr] = time.time()
                        
                        # Handle packet
                        if self.receive_handler:
                            self.receive_handler(packet, addr)
                
            except (BlockingIOError, InterruptedError):
                pass
            except socket.error as e:
                print(f"Socket error in receive loop: {e}")
                time.sleep(0.1)
            except Exception as e:
                print(f"Error in receive loop: {e}")
                time.sleep(0.1)
    
    def _keepalive_loop(self):
        """Cleanup old clients"""
        while self.running:
            try:
                time.sleep(config.session_timeout)
                
                with self.lock:
                    now = time.time()
                    to_remove = []
                    
                    for addr, last_seen in self.client_last_seen.items():
                        if now - last_seen > config.session_timeout * 2:
                            to_remove.append(addr)
                    
                    for addr in to_remove:
                        del self.client_last_seen[addr]
                        if addr in self.client_sequences:
                            del self.client_sequences[addr]
                
            except Exception as e:
                print(f"Error in keepalive loop: {e}")
    
    def send_packet(self, packet: bytes, addr: Tuple[str, int]):
        """Send packet to client"""
        if not self.socket:
            return
        
        try:
            self.socket.sendto(packet, addr)
        except Exception as e:
            print(f"Error sending packet to {addr}: {e}")
    
    def encode_packet(self, ip_packet: bytes, session_id: bytes = b"") -> bytes:
        """Encode IP packet for UDP transport"""
        # Simple encoding: [1-byte version][4-byte seq][session_id][ip_packet]
        seq = create_packet_id()
        
        header = struct.pack('!BI', 0x01, seq)
        if session_id:
            header += session_id
        
        return header + ip_packet
    
    def decode_packet(self, udp_packet: bytes) -> Tuple[bytes, Optional[int], Optional[bytes]]:
        """Decode UDP packet to IP packet"""
        if len(udp_packet) < 5:
            return b"", None, None
        
        version = udp_packet[0]
        if version != 0x01:
            return b"", None, None
        
        seq = struct.unpack('!I', udp_packet[1:5])[0]
        
        # Check for session ID (optional)
        session_id = None
        if len(udp_packet) > 5:
            # First 8 bytes after seq could be session ID
            if len(udp_packet) >= 13:
                session_id = udp_packet[5:13]
                ip_packet = udp_packet[13:]
            else:
                ip_packet = udp_packet[5:]
        else:
            ip_packet = b""
        
        return ip_packet, seq, session_id
    
    def check_replay(self, addr: Tuple[str, int], seq: int) -> bool:
        """Basic anti-replay check"""
        with self.lock:
            if addr not in self.client_sequences:
                self.client_sequences[addr] = deque(maxlen=1024)
                self.client_sequences[addr].append(seq)
                return True
            
            sequences = self.client_sequences[addr]
            
            # Check if sequence is too old
            if sequences and seq < sequences[0]:
                return False
            
            # Check if sequence already seen
            if seq in sequences:
                return False
            
            # Add new sequence
            sequences.append(seq)
            return True
