import os
import sys
import logging
import platform
from datetime import datetime

def setup_logging(verbose=False, log_file=None):
    """Setup logging configuration"""
    log_level = logging.DEBUG if verbose else logging.INFO
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Setup root logger
    logger = logging.getLogger()
    logger.setLevel(log_level)
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler if specified
    if log_file:
        try:
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(log_level)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            logger.error(f"Failed to setup file logging: {e}")

def check_privileges():
    """Check if the current process has the necessary privileges for packet capture"""
    try:
        # On Unix-like systems, check for root or CAP_NET_RAW capability
        if platform.system() in ['Linux', 'Darwin', 'FreeBSD']:
            # Check if running as root
            if os.geteuid() == 0:
                return True
            
            # Check for CAP_NET_RAW capability (Linux only)
            if platform.system() == 'Linux':
                try:
                    import subprocess
                    result = subprocess.run(
                        ['getcap', sys.executable],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    if 'cap_net_raw' in result.stdout.lower():
                        return True
                except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
                    pass
            
            return False
        
        # On Windows, check for administrator privileges
        elif platform.system() == 'Windows':
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                return False
        
        return False
        
    except Exception:
        return False

def validate_ip_address(ip_string):
    """Validate IP address format"""
    import ipaddress
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False

def validate_port(port):
    """Validate port number"""
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False

def format_bytes(bytes_value):
    """Format bytes in human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} TB"

def format_duration(seconds):
    """Format duration in human readable format"""
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f} minutes"
    else:
        hours = seconds / 3600
        return f"{hours:.1f} hours"

def get_system_info():
    """Get basic system information"""
    return {
        'platform': platform.system(),
        'platform_release': platform.release(),
        'platform_version': platform.version(),
        'architecture': platform.machine(),
        'processor': platform.processor(),
        'python_version': platform.python_version(),
        'hostname': platform.node()
    }

def check_dependencies():
    """Check if all required dependencies are available"""
    dependencies = {
        'scapy': False,
        'watchdog': False,
        'slack_sdk': False,
        'python_dotenv': False,
        'ipaddress': False
    }
    
    # Check scapy
    try:
        import scapy
        dependencies['scapy'] = True
    except ImportError:
        pass
    
    # Check watchdog
    try:
        import watchdog
        dependencies['watchdog'] = True
    except ImportError:
        pass
    
    # Check slack_sdk
    try:
        import slack_sdk
        dependencies['slack_sdk'] = True
    except ImportError:
        pass
    
    # Check python-dotenv
    try:
        import dotenv
        dependencies['python_dotenv'] = True
    except ImportError:
        pass
    
    # Check ipaddress (usually built-in)
    try:
        import ipaddress
        dependencies['ipaddress'] = True
    except ImportError:
        pass
    
    return dependencies

def create_pid_file(pid_file_path):
    """Create a PID file for daemon mode"""
    try:
        with open(pid_file_path, 'w') as f:
            f.write(str(os.getpid()))
        return True
    except Exception as e:
        logging.error(f"Failed to create PID file: {e}")
        return False

def remove_pid_file(pid_file_path):
    """Remove PID file"""
    try:
        if os.path.exists(pid_file_path):
            os.remove(pid_file_path)
    except Exception as e:
        logging.error(f"Failed to remove PID file: {e}")

def is_process_running(pid):
    """Check if a process with given PID is running"""
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False

def get_log_files():
    """Get list of common log file locations"""
    log_locations = [
        '/var/log/auth.log',
        '/var/log/secure',
        '/var/log/messages',
        '/var/log/syslog'
    ]
    
    existing_logs = []
    for log_path in log_locations:
        if os.path.exists(log_path) and os.access(log_path, os.R_OK):
            existing_logs.append(log_path)
    
    return existing_logs

def get_network_interfaces():
    """Get list of available network interfaces"""
    interfaces = ['any']  # Default interface
    
    try:
        import psutil
        for interface, addresses in psutil.net_if_addrs().items():
            interfaces.append(interface)
    except ImportError:
        # Fallback method for Linux
        if platform.system() == 'Linux':
            try:
                with open('/proc/net/dev', 'r') as f:
                    for line in f:
                        if ':' in line:
                            interface = line.split(':')[0].strip()
                            if interface not in ['lo']:
                                interfaces.append(interface)
            except:
                pass
    
    return interfaces

def daemonize():
    """Daemonize the current process (Unix only)"""
    if platform.system() == 'Windows':
        logging.warning("Daemonization not supported on Windows")
        return False
    
    try:
        # First fork
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        logging.error(f"Fork #1 failed: {e}")
        sys.exit(1)
    
    # Decouple from parent environment
    os.chdir("/")
    os.setsid()
    os.umask(0)
    
    try:
        # Second fork
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        logging.error(f"Fork #2 failed: {e}")
        sys.exit(1)
    
    # Redirect standard file descriptors
    sys.stdout.flush()
    sys.stderr.flush()
    
    si = open('/dev/null', 'r')
    so = open('/dev/null', 'a+')
    se = open('/dev/null', 'a+')
    
    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())
    
    return True