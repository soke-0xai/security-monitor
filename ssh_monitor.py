import re
import os
import time
import logging
from datetime import datetime, timedelta
from collections import defaultdict, deque
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class SSHLogHandler(FileSystemEventHandler):
    def __init__(self, ssh_monitor):
        self.ssh_monitor = ssh_monitor
        self.last_position = 0
        
        # Initialize position to end of file
        if os.path.exists(self.ssh_monitor.log_path):
            with open(self.ssh_monitor.log_path, 'r') as f:
                f.seek(0, 2)  # Seek to end
                self.last_position = f.tell()
    
    def on_modified(self, event):
        if not event.is_directory and event.src_path == self.ssh_monitor.log_path:
            self.ssh_monitor.process_new_lines()

class SSHMonitor:
    def __init__(self, config, whitelist_manager, alert_manager):
        self.config = config
        self.whitelist = whitelist_manager
        self.alert_manager = alert_manager
        self.log_path = config.ssh_log_path
        self.threshold = config.ssh_threshold
        self.time_window = config.time_window
        
        # Track failed attempts per IP
        self.failed_attempts = defaultdict(deque)
        
        # SSH log patterns
        self.patterns = [
            # Failed password attempts
            re.compile(r'Failed password for (?:invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+)'),
            # Invalid user attempts
            re.compile(r'Invalid user (\w+) from (\d+\.\d+\.\d+\.\d+)'),
            # Authentication failures
            re.compile(r'authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+)'),
            # Connection closed by authenticating user
            re.compile(r'Connection closed by authenticating user \w+ (\d+\.\d+\.\d+\.\d+)'),
            # Maximum authentication attempts
            re.compile(r'maximum authentication attempts exceeded.*from (\d+\.\d+\.\d+\.\d+)'),
        ]
        
        self.observer = None
        self.handler = None
        self.running = False
        self.last_position = 0
        
        logging.info(f"SSH Monitor initialized for {self.log_path}")
    
    def start(self):
        """Start SSH log monitoring"""
        if self.running:
            return
        
        self.running = True
        
        try:
            # Setup file watcher
            self.handler = SSHLogHandler(self)
            self.observer = Observer()
            
            log_dir = os.path.dirname(self.log_path)
            self.observer.schedule(self.handler, log_dir, recursive=False)
            self.observer.start()
            
            logging.info(f"SSH monitoring started for {self.log_path}")
            
            # Process existing log entries from current position
            self.process_new_lines()
            
            # Keep monitoring
            while self.running:
                self.cleanup_old_entries()
                time.sleep(1)
                
        except Exception as e:
            logging.error(f"Error in SSH monitoring: {e}")
        finally:
            if self.observer:
                self.observer.stop()
                self.observer.join()
    
    def stop(self):
        """Stop SSH log monitoring"""
        self.running = False
        if self.observer:
            self.observer.stop()
        logging.info("SSH monitoring stopped")
    
    def process_new_lines(self):
        """Process new lines in the log file"""
        try:
            if not os.path.exists(self.log_path):
                return
            
            with open(self.log_path, 'r') as f:
                # Seek to last known position
                f.seek(self.handler.last_position if self.handler else 0)
                
                for line in f:
                    self.parse_log_line(line.strip())
                
                # Update position
                if self.handler:
                    self.handler.last_position = f.tell()
                    
        except Exception as e:
            logging.error(f"Error processing SSH log: {e}")
    
    def parse_log_line(self, line):
        """Parse a single log line for SSH failures"""
        current_time = datetime.now()
        
        for pattern in self.patterns:
            match = pattern.search(line)
            if match:
                # Extract IP address (last group in most patterns)
                groups = match.groups()
                ip_addr = groups[-1] if groups else None
                
                if ip_addr and self.is_valid_ip(ip_addr):
                    # Check if IP is whitelisted
                    if self.whitelist.is_whitelisted(ip_addr):
                        continue
                    
                    # Record the failed attempt
                    self.record_failed_attempt(ip_addr, current_time)
                    
                    # Check if threshold exceeded
                    if self.check_threshold(ip_addr):
                        self.trigger_alert(ip_addr, line)
                
                break  # Only match first pattern
    
    def is_valid_ip(self, ip):
        """Validate IP address format"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        try:
            for part in parts:
                num = int(part)
                if not 0 <= num <= 255:
                    return False
            return True
        except ValueError:
            return False
    
    def record_failed_attempt(self, ip_addr, timestamp):
        """Record a failed attempt for an IP"""
        self.failed_attempts[ip_addr].append(timestamp)
        logging.debug(f"Recorded SSH failure from {ip_addr}")
    
    def check_threshold(self, ip_addr):
        """Check if IP has exceeded failure threshold"""
        attempts = self.failed_attempts[ip_addr]
        if len(attempts) >= self.threshold:
            return True
        return False
    
    def cleanup_old_entries(self):
        """Remove entries older than time window"""
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(seconds=self.time_window)
        
        for ip_addr in list(self.failed_attempts.keys()):
            attempts = self.failed_attempts[ip_addr]
            
            # Remove old attempts
            while attempts and attempts[0] < cutoff_time:
                attempts.popleft()
            
            # Remove empty entries
            if not attempts:
                del self.failed_attempts[ip_addr]
    
    def trigger_alert(self, ip_addr, log_line):
        """Trigger alert for suspicious activity"""
        attempt_count = len(self.failed_attempts[ip_addr])
        
        alert_data = {
            'type': 'SSH_BRUTEFORCE',
            'ip': ip_addr,
            'count': attempt_count,
            'threshold': self.threshold,
            'time_window': self.time_window,
            'timestamp': datetime.now().isoformat(),
            'sample_log': log_line[:200]  # First 200 chars
        }
        
        self.alert_manager.send_alert(alert_data)
        
        # Clear the attempts to avoid spam alerts
        self.failed_attempts[ip_addr].clear()
    
    def get_status(self):
        """Get current monitoring status"""
        return {
            'running': self.running,
            'log_path': self.log_path,
            'active_ips': len(self.failed_attempts),
            'total_attempts': sum(len(attempts) for attempts in self.failed_attempts.values()),
            'threshold': self.threshold,
            'time_window': self.time_window
        }