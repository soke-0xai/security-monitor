import time
import logging
from datetime import datetime, timedelta
from collections import defaultdict, deque
from scapy.all import sniff, TCP, IP

class PacketMonitor:
    def __init__(self, config, whitelist_manager, alert_manager):
        self.config = config
        self.whitelist = whitelist_manager
        self.alert_manager = alert_manager
        self.interface = config.packet_interface
        self.threshold = config.packet_threshold
        self.time_window = config.time_window
        
        # Track SYN attempts per IP
        self.syn_attempts = defaultdict(deque)
        
        self.running = False
        
        logging.info(f"Packet Monitor initialized for interface {self.interface}")
    
    def start(self):
        """Start packet monitoring"""
        if self.running:
            return
        
        self.running = True
        
        try:
            logging.info(f"Starting packet capture on interface {self.interface}")
            
            # Define packet filter for TCP SYN packets
            filter_expr = "tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0"
            
            # Start packet capture
            sniff(
                iface=self.interface if self.interface != 'any' else None,
                filter=filter_expr,
                prn=self.process_packet,
                stop_filter=lambda x: not self.running,
                store=False  # Don't store packets in memory
            )
            
        except Exception as e:
            logging.error(f"Error in packet monitoring: {e}")
            if "Operation not permitted" in str(e):
                logging.error("Packet capture requires root privileges or CAP_NET_RAW capability")
                logging.error("Run: sudo setcap cap_net_raw,cap_net_admin+ep $(which python3)")
    
    def stop(self):
        """Stop packet monitoring"""
        self.running = False
        logging.info("Packet monitoring stopped")
    
    def process_packet(self, packet):
        """Process captured packet"""
        try:
            if not self.running:
                return
            
            # Extract IP layer
            if not packet.haslayer(IP):
                return
            
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            
            # Check if packet has TCP layer and is SYN packet
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                dst_port = tcp_layer.dport
                
                # Only process SYN packets (SYN=1, ACK=0)
                if tcp_layer.flags & 0x02 and not (tcp_layer.flags & 0x10):
                    self.record_syn_attempt(src_ip, dst_ip, dst_port)
                    
                    # Check if threshold exceeded
                    if self.check_threshold(src_ip):
                        self.trigger_alert(src_ip, dst_ip, dst_port)
        
        except Exception as e:
            logging.error(f"Error processing packet: {e}")
    
    def record_syn_attempt(self, src_ip, dst_ip, dst_port):
        """Record a SYN attempt"""
        current_time = datetime.now()
        
        # Check if source IP is whitelisted
        if self.whitelist.is_whitelisted(src_ip):
            return
        
        # Record the attempt
        self.syn_attempts[src_ip].append({
            'timestamp': current_time,
            'dst_ip': dst_ip,
            'dst_port': dst_port
        })
        
        logging.debug(f"Recorded SYN from {src_ip} to {dst_ip}:{dst_port}")
        
        # Cleanup old entries periodically
        self.cleanup_old_entries()
    
    def check_threshold(self, src_ip):
        """Check if IP has exceeded SYN threshold"""
        attempts = self.syn_attempts[src_ip]
        return len(attempts) >= self.threshold
    
    def cleanup_old_entries(self):
        """Remove entries older than time window"""
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(seconds=self.time_window)
        
        for src_ip in list(self.syn_attempts.keys()):
            attempts = self.syn_attempts[src_ip]
            
            # Remove old attempts
            while attempts and attempts[0]['timestamp'] < cutoff_time:
                attempts.popleft()
            
            # Remove empty entries
            if not attempts:
                del self.syn_attempts[src_ip]
    
    def trigger_alert(self, src_ip, last_dst_ip, last_dst_port):
        """Trigger alert for port scanning activity"""
        attempts = self.syn_attempts[src_ip]
        attempt_count = len(attempts)
        
        # Get unique ports and IPs targeted
        unique_ports = set()
        unique_ips = set()
        
        for attempt in attempts:
            unique_ports.add(attempt['dst_port'])
            unique_ips.add(attempt['dst_ip'])
        
        alert_data = {
            'type': 'PORT_SCAN',
            'src_ip': src_ip,
            'count': attempt_count,
            'threshold': self.threshold,
            'time_window': self.time_window,
            'unique_ports': len(unique_ports),
            'unique_targets': len(unique_ips),
            'last_target': f"{last_dst_ip}:{last_dst_port}",
            'timestamp': datetime.now().isoformat(),
            'sample_ports': list(unique_ports)[:10]  # First 10 ports
        }
        
        self.alert_manager.send_alert(alert_data)
        
        # Clear the attempts to avoid spam alerts
        self.syn_attempts[src_ip].clear()
    
    def get_status(self):
        """Get current monitoring status"""
        return {
            'running': self.running,
            'interface': self.interface,
            'active_ips': len(self.syn_attempts),
            'total_attempts': sum(len(attempts) for attempts in self.syn_attempts.values()),
            'threshold': self.threshold,
            'time_window': self.time_window
        }