#!/usr/bin/env python3

import os
import sys
import signal
import argparse
import threading
import time
from datetime import datetime
from config import Config
from ssh_monitor import SSHMonitor
from packet_monitor import PacketMonitor
from alert_manager import AlertManager
from whitelist import WhitelistManager
from utils import setup_logging, check_privileges

class SecurityMonitor:
    def __init__(self, config):
        self.config = config
        self.running = False
        self.threads = []
        
        # Initialize components
        self.whitelist = WhitelistManager(config.whitelist_file)
        self.alert_manager = AlertManager(config)
        self.ssh_monitor = SSHMonitor(config, self.whitelist, self.alert_manager)
        self.packet_monitor = PacketMonitor(config, self.whitelist, self.alert_manager)
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        print(f"\nReceived signal {signum}. Shutting down gracefully...")
        self.stop()
    
    def start(self):
        """Start all monitoring threads"""
        if self.running:
            return
        
        self.running = True
        print(f"Starting Security Monitor at {datetime.now()}")
        
        # Start SSH monitoring if enabled
        if self.config.ssh_monitoring_enabled:
            ssh_thread = threading.Thread(target=self.ssh_monitor.start, daemon=True)
            ssh_thread.start()
            self.threads.append(ssh_thread)
            print(f"SSH monitoring started: {self.config.ssh_log_path}")
        
        # Start packet monitoring if enabled
        if self.config.packet_monitoring_enabled:
            if not check_privileges():
                print("Warning: Packet monitoring requires root privileges or CAP_NET_RAW capability")
                print("Run: sudo setcap cap_net_raw,cap_net_admin+ep $(which python3)")
            else:
                packet_thread = threading.Thread(target=self.packet_monitor.start, daemon=True)
                packet_thread.start()
                self.threads.append(packet_thread)
                print(f"Packet monitoring started: interface {self.config.packet_interface}")
        
        print("Security Monitor is running. Press Ctrl+C to stop.")
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
    
    def stop(self):
        """Stop all monitoring"""
        if not self.running:
            return
        
        self.running = False
        print("Stopping all monitors...")
        
        # Stop monitors
        self.ssh_monitor.stop()
        self.packet_monitor.stop()
        
        # Wait for threads to finish
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=2)
        
        print("Security Monitor stopped.")

def main():
    parser = argparse.ArgumentParser(description="Real-time Security Monitor")
    parser.add_argument("--config", "-c", help="Config file path")
    parser.add_argument("--ssh-log", help="SSH log file path")
    parser.add_argument("--ssh-threshold", type=int, help="SSH failure threshold")
    parser.add_argument("--packet-threshold", type=int, help="Packet threshold")
    parser.add_argument("--interface", "-i", help="Network interface to monitor")
    parser.add_argument("--window", "-w", type=int, help="Time window in seconds")
    parser.add_argument("--whitelist", help="Whitelist file path")
    parser.add_argument("--no-ssh", action="store_true", help="Disable SSH monitoring")
    parser.add_argument("--no-packet", action="store_true", help="Disable packet monitoring")
    parser.add_argument("--daemon", "-d", action="store_true", help="Run as daemon")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(verbose=args.verbose)
    
    # Load configuration
    config = Config(args.config)
    
    # Override config with command line arguments
    if args.ssh_log:
        config.ssh_log_path = args.ssh_log
    if args.ssh_threshold:
        config.ssh_threshold = args.ssh_threshold
    if args.packet_threshold:
        config.packet_threshold = args.packet_threshold
    if args.interface:
        config.packet_interface = args.interface
    if args.window:
        config.time_window = args.window
    if args.whitelist:
        config.whitelist_file = args.whitelist
    if args.no_ssh:
        config.ssh_monitoring_enabled = False
    if args.no_packet:
        config.packet_monitoring_enabled = False
    
    # Validate configuration
    if not config.ssh_monitoring_enabled and not config.packet_monitoring_enabled:
        print("Error: Both SSH and packet monitoring are disabled")
        return 1
    
    if config.ssh_monitoring_enabled and not os.path.exists(config.ssh_log_path):
        print(f"Error: SSH log file not found: {config.ssh_log_path}")
        return 1
    
    # Start monitoring
    monitor = SecurityMonitor(config)
    
    if args.daemon:
        print("Running in daemon mode...")
    
    try:
        monitor.start()
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())