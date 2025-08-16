import json
import logging
import requests
from datetime import datetime
from slack_sdk.webhook import WebhookClient

class AlertManager:
    def __init__(self, config):
        self.config = config
        self.slack_enabled = config.slack_enabled
        self.console_enabled = config.console_alerts
        
        if self.slack_enabled:
            self.slack_client = WebhookClient(config.slack_webhook_url)
            logging.info("Slack alerts enabled")
        
        logging.info("Alert manager initialized")
    
    def send_alert(self, alert_data):
        """Send alert through all configured channels"""
        try:
            if self.console_enabled:
                self.send_console_alert(alert_data)
            
            if self.slack_enabled:
                self.send_slack_alert(alert_data)
                
        except Exception as e:
            logging.error(f"Error sending alert: {e}")
    
    def send_console_alert(self, alert_data):
        """Send alert to console with color formatting"""
        alert_type = alert_data.get('type', 'UNKNOWN')
        timestamp = alert_data.get('timestamp', datetime.now().isoformat())
        
        # Color codes
        RED = '\033[91m'
        YELLOW = '\033[93m'
        BOLD = '\033[1m'
        RESET = '\033[0m'
        
        if alert_type == 'SSH_BRUTEFORCE':
            color = RED
            symbol = "[SSH ATTACK]"
            message = self.format_ssh_alert(alert_data)
        elif alert_type == 'PORT_SCAN':
            color = YELLOW
            symbol = "[PORT SCAN]"
            message = self.format_port_scan_alert(alert_data)
        else:
            color = RED
            symbol = "[SECURITY]"
            message = f"Unknown alert type: {alert_type}"
        
        # Print colored alert
        print(f"\n{color}{BOLD}{symbol}{RESET} {color}{timestamp}{RESET}")
        print(f"{color}{message}{RESET}")
        print("-" * 60)
        
        # Log the alert
        logging.warning(f"ALERT: {alert_type} - {message}")
    
    def format_ssh_alert(self, alert_data):
        """Format SSH brute force alert message"""
        ip = alert_data.get('ip', 'unknown')
        count = alert_data.get('count', 0)
        threshold = alert_data.get('threshold', 0)
        time_window = alert_data.get('time_window', 0)
        
        message = f"SSH Brute Force Attack Detected!\n"
        message += f"Source IP: {ip}\n"
        message += f"Failed attempts: {count} (threshold: {threshold})\n"
        message += f"Time window: {time_window} seconds\n"
        message += f"Recommended action: Block IP {ip} in firewall"
        
        return message
    
    def format_port_scan_alert(self, alert_data):
        """Format port scan alert message"""
        src_ip = alert_data.get('src_ip', 'unknown')
        count = alert_data.get('count', 0)
        threshold = alert_data.get('threshold', 0)
        unique_ports = alert_data.get('unique_ports', 0)
        unique_targets = alert_data.get('unique_targets', 0)
        sample_ports = alert_data.get('sample_ports', [])
        
        message = f"Port Scan Activity Detected!\n"
        message += f"Source IP: {src_ip}\n"
        message += f"SYN attempts: {count} (threshold: {threshold})\n"
        message += f"Unique ports scanned: {unique_ports}\n"
        message += f"Target IPs: {unique_targets}\n"
        
        if sample_ports:
            ports_str = ', '.join(map(str, sample_ports[:10]))
            if len(sample_ports) > 10:
                ports_str += "..."
            message += f"Sample ports: {ports_str}\n"
        
        message += f"Recommended action: Block IP {src_ip} in firewall"
        
        return message
    
    def send_slack_alert(self, alert_data):
        """Send alert to Slack"""
        try:
            alert_type = alert_data.get('type', 'UNKNOWN')
            
            if alert_type == 'SSH_BRUTEFORCE':
                message = self.create_ssh_slack_message(alert_data)
            elif alert_type == 'PORT_SCAN':
                message = self.create_port_scan_slack_message(alert_data)
            else:
                message = self.create_generic_slack_message(alert_data)
            
            response = self.slack_client.send(
                text=message['text'],
                blocks=message.get('blocks', [])
            )
            
            if response.status_code == 200:
                logging.info("Slack alert sent successfully")
            else:
                logging.error(f"Failed to send Slack alert: {response.status_code}")
                
        except Exception as e:
            logging.error(f"Error sending Slack alert: {e}")
    
    def create_ssh_slack_message(self, alert_data):
        """Create Slack message for SSH brute force attack"""
        ip = alert_data.get('ip', 'unknown')
        count = alert_data.get('count', 0)
        threshold = alert_data.get('threshold', 0)
        timestamp = alert_data.get('timestamp', datetime.now().isoformat())
        
        message = {
            "text": f"SSH Brute Force Attack from {ip}",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "SSH Brute Force Attack Detected"
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Source IP:*\n{ip}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Failed Attempts:*\n{count}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Threshold:*\n{threshold}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Time:*\n{timestamp}"
                        }
                    ]
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Recommended Action:* Block IP `{ip}` in firewall immediately"
                    }
                }
            ]
        }
        return message
    
    def create_port_scan_slack_message(self, alert_data):
        """Create Slack message for port scan"""
        src_ip = alert_data.get('src_ip', 'unknown')
        count = alert_data.get('count', 0)
        unique_ports = alert_data.get('unique_ports', 0)
        sample_ports = alert_data.get('sample_ports', [])
        timestamp = alert_data.get('timestamp', datetime.now().isoformat())
        
        ports_str = ', '.join(map(str, sample_ports[:10]))
        if len(sample_ports) > 10:
            ports_str += "..."
        
        message = {
            "text": f"Port Scan from {src_ip}",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "Port Scan Activity Detected"
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Source IP:*\n{src_ip}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*SYN Attempts:*\n{count}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Unique Ports:*\n{unique_ports}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Time:*\n{timestamp}"
                        }
                    ]
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Sample Ports:* {ports_str}"
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Recommended Action:* Block IP `{src_ip}` in firewall"
                    }
                }
            ]
        }
        return message
    
    def create_generic_slack_message(self, alert_data):
        """Create generic Slack message"""
        alert_type = alert_data.get('type', 'UNKNOWN')
        timestamp = alert_data.get('timestamp', datetime.now().isoformat())
        
        message = {
            "text": f"Security Alert: {alert_type}",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"Security Alert: {alert_type}"
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Time:* {timestamp}\n*Data:* ```{json.dumps(alert_data, indent=2)}```"
                    }
                }
            ]
        }
        return message
    
    def test_alerts(self):
        """Test all alert channels with sample data"""
        test_alerts = [
            {
                'type': 'SSH_BRUTEFORCE',
                'ip': '192.168.1.100',
                'count': 10,
                'threshold': 5,
                'time_window': 60,
                'timestamp': datetime.now().isoformat(),
                'sample_log': 'Failed password for root from 192.168.1.100'
            },
            {
                'type': 'PORT_SCAN',
                'src_ip': '10.0.0.50',
                'count': 150,
                'threshold': 100,
                'unique_ports': 25,
                'unique_targets': 1,
                'sample_ports': [22, 23, 25, 53, 80, 135, 139, 443, 445, 993],
                'timestamp': datetime.now().isoformat()
            }
        ]
        
        print("Testing alert system...")
        for alert in test_alerts:
            print(f"Sending test alert: {alert['type']}")
            self.send_alert(alert)
        
        print("Alert test complete")