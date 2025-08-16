import os
import logging
from dotenv import load_dotenv

class Config:
    def __init__(self, config_file=None):
        load_dotenv()
        
        # SSH Monitoring Configuration
        self.ssh_monitoring_enabled = True
        self.ssh_log_path = self._get_ssh_log_path()
        self.ssh_threshold = int(os.getenv('SSH_THRESHOLD', '5'))
        
        # Packet Monitoring Configuration
        self.packet_monitoring_enabled = True
        self.packet_interface = os.getenv('PACKET_INTERFACE', 'any')
        self.packet_threshold = int(os.getenv('PACKET_THRESHOLD', '100'))
        
        # General Configuration
        self.time_window = int(os.getenv('TIME_WINDOW', '60'))
        self.whitelist_file = os.getenv('WHITELIST_FILE', 'whitelist.txt')
        
        # Alert Configuration
        self.slack_webhook_url = os.getenv('SLACK_WEBHOOK_URL')
        self.slack_enabled = bool(self.slack_webhook_url)
        self.console_alerts = True
        
        # Logging Configuration
        self.log_level = os.getenv('LOG_LEVEL', 'INFO')
        self.log_file = os.getenv('LOG_FILE')
        
        if config_file and os.path.exists(config_file):
            self._load_config_file(config_file)
    
    def _get_ssh_log_path(self):
        """Detect SSH log file path based on system"""
        possible_paths = [
            '/var/log/auth.log',      # Debian/Ubuntu
            '/var/log/secure',        # RHEL/CentOS/Fedora
            '/var/log/messages'       # Some older systems
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                return path
        
        # Default to auth.log if none found
        return '/var/log/auth.log'
    
    def _load_config_file(self, config_file):
        """Load configuration from file (future implementation)"""
        pass
    
    def validate(self):
        """Validate configuration"""
        errors = []
        
        if self.ssh_monitoring_enabled:
            if not os.path.exists(self.ssh_log_path):
                errors.append(f"SSH log file not found: {self.ssh_log_path}")
            elif not os.access(self.ssh_log_path, os.R_OK):
                errors.append(f"Cannot read SSH log file: {self.ssh_log_path}")
        
        if self.ssh_threshold <= 0:
            errors.append("SSH threshold must be positive")
        
        if self.packet_threshold <= 0:
            errors.append("Packet threshold must be positive")
        
        if self.time_window <= 0:
            errors.append("Time window must be positive")
        
        return errors