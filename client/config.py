#!/usr/bin/env python3
"""
Client Configuration
"""

import json
import os
from dataclasses import dataclass
from typing import Tuple

@dataclass
class ClientConfig:
    """Client configuration"""
    # Server Settings
    server_ip: str = ""  # MUST be set by user
    udp_port_range: Tuple[int, int] = (6000, 19999)
    probe_timeout: float = 0.5  # seconds per port
    max_probe_attempts: int = 3
    
    # TUN Settings
    tun_name: str = "udtun0"
    tun_ip: str = "10.9.0.101"
    tun_netmask: str = "255.255.255.0"
    tun_mtu: int = 1300
    tun_gateway: str = "10.9.0.1"
    
    # UDP Settings
    udp_bind_ip: str = "0.0.0.0"
    udp_bind_port: int = 0  # random
    udp_buffer_size: int = 2097152  # 2MB
    max_packet_size: int = 1500
    
    # Connection
    keepalive_interval: int = 10  # seconds
    reconnect_interval: int = 5  # seconds
    connection_timeout: int = 30  # seconds
    
    # Performance
    batch_size: int = 16
    read_timeout: float = 0.1
    
    # Logging
    log_level: str = "INFO"
    log_file: str = "/var/log/udtun/client.log"

config = ClientConfig()

def load_config(config_path: str = None) -> ClientConfig:
    """Load configuration from file"""
    if config_path and os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                data = json.load(f)
                for key, value in data.items():
                    if hasattr(config, key):
                        setattr(config, key, value)
        except Exception as e:
            print(f"Warning: Could not load config: {e}")
    
    # Validate server IP
    if not config.server_ip:
        raise ValueError("server_ip must be set in configuration")
    
    return config
