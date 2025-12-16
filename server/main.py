#!/usr/bin/env python3
"""
Main Server - WHISPER Tunnel Server
"""

import sys
import time
import threading
from typing import List, Tuple, Optional

# Import server modules
from .config import config
from .utils import apply_sysctl_tuning, select_readable
from .tun import TUNDevice
from .udp import UDPHandler, UDPPacket
from .session import SessionManager
from .ratelimit import RateLimiter
from .shutdown import GracefulShutdown

class WhisperServer:
    """Main server class"""
    
    def __init__(self):
        self.tun = TUNDevice(config.TUN_NAME, config.TUN_MTU)
        self.udp = UDPHandler(config.INTERNAL_PORT, config.SERVER_IP)
        self.session_manager = SessionManager(config.SESSION_TIMEOUT)
        self.rate_limiter = RateLimiter(config.MAX_RATE_PER_SESSION)
        self.shutdown = GracefulShutdown()
        
        # Statistics
        self.stats = {
            "start_time": time.time(),
            "total_packets": 0,
            "total_bytes": 0,
            "active_sessions": 0
        }
        
        # Sequence numbers for outgoing packets
        self.seq_numbers = {}
        
        # Register shutdown callbacks
        self.shutdown.register_callback(self.cleanup)
    
    def start(self) -> bool:
        """Start the server"""
        print("Starting WHISPER Tunnel Server...")
        
        # Apply kernel tuning
        print("Applying kernel performance tuning...")
        apply_sysctl_tuning()
        
        # Create TUN device
        print(f"Creating TUN device {config.TUN_NAME}...")
        if not self.tun.create():
            print("Failed to create TUN device")
            return False
        
        # Configure TUN
        print(f"Configuring TUN with IP {config.TUN_IP}...")
        if not self.tun.configure(config.TUN_IP, config.TUN_NETMASK):
            print("Failed to configure TUN")
            return False
        
        # Start UDP listener
        print(f"Starting UDP listener on port {config.INTERNAL_PORT}...")
        if not self.udp.start():
            print("Failed to start UDP listener")
            return False
        
        print("Server started successfully!")
        print(f"TUN Device: {config.TUN_NAME} ({config.TUN_IP})")
        print(f"UDP Port: {config.INTERNAL_PORT}")
        print(f"External Port Range: {config.EXTERNAL_PORT_START}-{config.EXTERNAL_PORT_END}")
        print("Waiting for client connections...")
        
        return True
    
    def handle_udp_packet(self, data: bytes, addr: Tuple[str, int]):
        """Handle incoming UDP packet"""
        # Decode packet
        decoded = UDPPacket.decode(data)
        if not decoded:
            if config.DEBUG:
                print(f"Invalid packet from {addr}")
            return
        
        ptype, session_id, seq_num, payload = decoded
        
        # Handle probe packets
        if ptype == UDPPacket.TYPE_PROBE:
            if config.DEBUG:
                print(f"Probe from {addr}")
            
            # Create or get session
            session = self.session_manager.create_session(addr)
            if session:
                # Send keepalive response
                keepalive = UDPPacket.encode_keepalive(session.session_id)
                self.udp.send(keepalive, addr)
            
            return
        
        # Get session
        session = None
        if session_id:
            session = self.session_manager.get_session(session_id)
        else:
            session = self.session_manager.get_session_by_addr(addr)
        
        if not session:
            if config.DEBUG:
                print(f"Unknown session from {addr}")
            return
        
        # Update session activity
        session.update_activity()
        session.packets_received += 1
        session.bytes_received += len(data)
        
        # Check rate limit
        if not self.rate_limiter.check_limit(session.session_id):
            if config.DEBUG:
                print(f"Rate limit exceeded for session {session.session_id}")
            return
        
        # Handle keepalive packets
        if ptype == UDPPacket.TYPE_KEEPALIVE:
            if config.DEBUG:
                print(f"Keepalive from {addr}")
            # Send keepalive response
            keepalive = UDPPacket.encode_keepalive(session.session_id)
            self.udp.send(keepalive, addr)
            return
        
        # Handle data packets
        if ptype == UDPPacket.TYPE_DATA:
            # Write to TUN device
            if payload and len(payload) > 0:
                self.tun.write_packet(payload)
                if config.LOG_PACKETS:
                    print(f"TUN <- UDP: {len(payload)} bytes from {addr}")
    
    def handle_tun_packets(self, packets: List[bytes]):
        """Handle outgoing TUN packets"""
        for packet in packets:
            if not packet or len(packet) < 20:  # Minimum IP header
                continue
            
            # Send to all active sessions
            for session_id, session in self.session_manager.sessions.items():
                if session.is_active:
                    # Get sequence number for this session
                    seq = self.seq_numbers.get(session_id, 0)
                    self.seq_numbers[session_id] = seq + 1
                    
                    # Encode packet
                    data_packet = UDPPacket.encode_data(
                        session_id, 
                        seq, 
                        packet[:config.MAX_PACKET_SIZE]
                    )
                    
                    # Send via UDP
                    if self.udp.send(data_packet, session.client_addr):
                        session.packets_sent += 1
                        session.bytes_sent += len(data_packet)
                        
                        if config.LOG_PACKETS:
                            print(f"TUN -> UDP: {len(packet)} bytes to {session.client_addr}")
    
    def run(self):
        """Main server loop"""
        print("Entering main loop...")
        
        last_cleanup = time.time()
        last_stats = time.time()
        
        while not self.shutdown.should_exit():
            try:
                # Read UDP packets
                udp_packets = self.udp.receive(config.BATCH_SIZE)
                for data, addr in udp_packets:
                    self.handle_udp_packet(data, addr)
                    self.stats["total_packets"] += 1
                    self.stats["total_bytes"] += len(data)
                
                # Read TUN packets
                tun_packets = self.tun.read_packets(config.BATCH_SIZE)
                if tun_packets:
                    self.handle_tun_packets(tun_packets)
                
                # Periodic cleanup
                current_time = time.time()
                if current_time - last_cleanup > 5.0:
                    self.session_manager.cleanup()
                    self.rate_limiter.cleanup()
                    last_cleanup = current_time
                
                # Statistics
                if current_time - last_stats > 10.0:
                    active = len(self.session_manager.sessions)
                    self.stats["active_sessions"] = active
                    
                    if active > 0 or config.DEBUG:
                        uptime = int(current_time - self.stats["start_time"])
                        print(f"Stats: {uptime}s uptime, {active} sessions, "
                              f"{self.stats['total_packets']} packets")
                    last_stats = current_time
                
                # Small sleep to prevent CPU spinning
                time.sleep(0.001)
                
            except Exception as e:
                print(f"Error in main loop: {e}")
                time.sleep(1)
    
    def cleanup(self):
        """Cleanup resources"""
        print("Cleaning up server resources...")
        
        # Close UDP socket
        self.udp.close()
        
        # Destroy TUN device
        self.tun.destroy()
        
        print("Server cleanup completed")
    
    def print_final_stats(self):
        """Print final statistics"""
        uptime = int(time.time() - self.stats["start_time"])
        print(f"\nServer Statistics:")
        print(f"  Uptime: {uptime} seconds")
        print(f"  Total packets processed: {self.stats['total_packets']}")
        print(f"  Total bytes processed: {self.stats['total_bytes']}")
        print(f"  Active sessions at exit: {self.stats['active_sessions']}")

def main():
    """Main entry point"""
    server = WhisperServer()
    
    if not server.start():
        print("Failed to start server")
        return 1
    
    try:
        server.run()
    except KeyboardInterrupt:
        print("\nServer interrupted by user")
    except Exception as e:
        print(f"Server error: {e}")
        return 1
    finally:
        server.print_final_stats()
        server.cleanup()
    
    print("Server stopped")
    return 0

if __name__ == "__main__":
    sys.exit(main())
