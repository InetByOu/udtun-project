#!/usr/bin/env python3
"""
Graceful shutdown handler
"""

import signal
import sys
import threading
from typing import Optional, Callable

class ShutdownHandler:
    """Handle graceful shutdown"""
    
    def __init__(self):
        self.should_stop = False
        self.callbacks = []
        self.lock = threading.Lock()
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        print(f"\nReceived signal {signum}, shutting down...")
        self.should_stop = True
        self.execute_callbacks()
        sys.exit(0)
    
    def add_callback(self, callback: Callable):
        """Add shutdown callback"""
        with self.lock:
            self.callbacks.append(callback)
    
    def execute_callbacks(self):
        """Execute all shutdown callbacks"""
        with self.lock:
            for callback in self.callbacks:
                try:
                    callback()
                except Exception as e:
                    print(f"Error in shutdown callback: {e}")
    
    def should_stop_now(self) -> bool:
        """Check if should stop"""
        return self.should_stop
