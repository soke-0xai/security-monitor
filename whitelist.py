import os
import ipaddress
import logging
from datetime import datetime

class WhitelistManager:
    def __init__(self, whitelist_file='whitelist.txt'):
        self.whitelist_file = whitelist_file
        self.whitelisted_networks = []
        self.last_modified = 0
        
        self.load_whitelist()
        logging.info(f"Whitelist manager initialized with {len(self.whitelisted_networks)} entries")
    
    def load_whitelist(self):
        """Load whitelist from file"""
        self.whitelisted_networks = []
        
        if not os.path.exists(self.whitelist_file):
            # Create default whitelist file
            self.create_default_whitelist()
            return
        
        try:
            # Check if file was modified
            current_modified = os.path.getmtime(self.whitelist_file)
            if current_modified <= self.last_modified:
                return  # No changes
            
            self.last_modified = current_modified
            
            with open(self.whitelist_file, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    
                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue
                    
                    try:
                        # Parse as IP network (supports both single IPs and CIDR)
                        network = ipaddress.ip_network(line, strict=False)
                        self.whitelisted_networks.append(network)
                        logging.debug(f"Added to whitelist: {network}")
                        
                    except ValueError as e:
                        logging.warning(f"Invalid IP/network in whitelist line {line_num}: {line} - {e}")
            
            logging.info(f"Loaded {len(self.whitelisted_networks)} whitelist entries from {self.whitelist_file}")
            
        except Exception as e:
            logging.error(f"Error loading whitelist: {e}")
    
    def create_default_whitelist(self):
        """Create a default whitelist file with common private networks"""
        default_entries = [
            "# Security Monitor Whitelist",
            "# Add IP addresses or CIDR networks to exclude from monitoring",
            "# Examples:",
            "# 192.168.1.100",
            "# 10.0.0.0/8",
            "# 172.16.0.0/12",
            "",
            "# Localhost",
            "127.0.0.0/8",
            "::1/128",
            "",
            "# Common private networks (uncomment if needed)",
            "# 192.168.0.0/16",
            "# 10.0.0.0/8", 
            "# 172.16.0.0/12",
            "",
            "# Link-local addresses",
            "169.254.0.0/16",
            "fe80::/10",
        ]
        
        try:
            with open(self.whitelist_file, 'w') as f:
                f.write('\n'.join(default_entries))
            
            logging.info(f"Created default whitelist file: {self.whitelist_file}")
            
            # Reload to parse the new file
            self.load_whitelist()
            
        except Exception as e:
            logging.error(f"Error creating default whitelist: {e}")
    
    def is_whitelisted(self, ip_address):
        """Check if an IP address is whitelisted"""
        # Reload whitelist if file was modified
        self.load_whitelist()
        
        try:
            ip = ipaddress.ip_address(ip_address)
            
            for network in self.whitelisted_networks:
                if ip in network:
                    logging.debug(f"IP {ip_address} is whitelisted (matches {network})")
                    return True
            
            return False
            
        except ValueError:
            logging.warning(f"Invalid IP address format: {ip_address}")
            return False
    
    def add_to_whitelist(self, ip_or_network):
        """Add an IP or network to the whitelist"""
        try:
            # Validate the input
            network = ipaddress.ip_network(ip_or_network, strict=False)
            
            # Check if already whitelisted
            if network in self.whitelisted_networks:
                return False
            
            # Add to file
            with open(self.whitelist_file, 'a') as f:
                f.write(f"\n{ip_or_network}")
            
            # Reload whitelist
            self.load_whitelist()
            
            logging.info(f"Added {ip_or_network} to whitelist")
            return True
            
        except Exception as e:
            logging.error(f"Error adding to whitelist: {e}")
            return False
    
    def remove_from_whitelist(self, ip_or_network):
        """Remove an IP or network from the whitelist"""
        try:
            if not os.path.exists(self.whitelist_file):
                return False
            
            # Read all lines
            with open(self.whitelist_file, 'r') as f:
                lines = f.readlines()
            
            # Filter out the entry
            filtered_lines = []
            removed = False
            
            for line in lines:
                stripped = line.strip()
                if stripped != ip_or_network:
                    filtered_lines.append(line)
                else:
                    removed = True
            
            if removed:
                # Write back to file
                with open(self.whitelist_file, 'w') as f:
                    f.writelines(filtered_lines)
                
                # Reload whitelist
                self.load_whitelist()
                
                logging.info(f"Removed {ip_or_network} from whitelist")
                return True
            
            return False
            
        except Exception as e:
            logging.error(f"Error removing from whitelist: {e}")
            return False
    
    def get_whitelist_entries(self):
        """Get all whitelist entries"""
        return [str(network) for network in self.whitelisted_networks]
    
    def get_status(self):
        """Get whitelist status"""
        return {
            'file': self.whitelist_file,
            'entries': len(self.whitelisted_networks),
            'last_modified': datetime.fromtimestamp(self.last_modified).isoformat() if self.last_modified else None,
            'networks': self.get_whitelist_entries()
        }