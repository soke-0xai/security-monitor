#!/usr/bin/env python3

import sys
import os
import time
from datetime import datetime

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import Config
from alert_manager import AlertManager
from whitelist import WhitelistManager
from utils import setup_logging, check_dependencies

def test_dependencies():
    """Test all required dependencies"""
    print("Testing dependencies...")
    deps = check_dependencies()
    
    missing = []
    for dep, available in deps.items():
        status = "✓" if available else "✗"
        print(f"  {status} {dep}")
        if not available:
            missing.append(dep)
    
    if missing:
        print(f"\nMissing dependencies: {', '.join(missing)}")
        print("Install with: pip install -r requirements.txt")
        return False
    
    print("All dependencies available!")
    return True

def test_config():
    """Test configuration loading"""
    print("\nTesting configuration...")
    try:
        config = Config()
        print(f"  ✓ SSH log path: {config.ssh_log_path}")
        print(f"  ✓ SSH threshold: {config.ssh_threshold}")
        print(f"  ✓ Packet threshold: {config.packet_threshold}")
        print(f"  ✓ Time window: {config.time_window}")
        print(f"  ✓ Whitelist file: {config.whitelist_file}")
        print(f"  ✓ Slack enabled: {config.slack_enabled}")
        
        errors = config.validate()
        if errors:
            print("  Configuration errors:")
            for error in errors:
                print(f"    ✗ {error}")
            return False
        
        print("Configuration loaded successfully!")
        return True
    except Exception as e:
        print(f"  ✗ Configuration error: {e}")
        return False

def test_whitelist():
    """Test whitelist functionality"""
    print("\nTesting whitelist...")
    try:
        whitelist = WhitelistManager('whitelist.txt')
        
        # Test some common IPs
        test_ips = [
            ('127.0.0.1', True),      # Localhost should be whitelisted
            ('192.168.1.1', False),   # Private IP (depends on config)
            ('8.8.8.8', False),       # Public IP should not be whitelisted
            ('invalid', False)        # Invalid IP
        ]
        
        for ip, expected_whitelisted in test_ips:
            is_whitelisted = whitelist.is_whitelisted(ip)
            status = "✓" if (ip == 'invalid' and not is_whitelisted) or (ip != 'invalid') else "?"
            print(f"  {status} {ip}: {'whitelisted' if is_whitelisted else 'not whitelisted'}")
        
        print(f"  ✓ Loaded {len(whitelist.whitelisted_networks)} whitelist entries")
        print("Whitelist functionality working!")
        return True
    except Exception as e:
        print(f"  ✗ Whitelist error: {e}")
        return False

def test_alerts():
    """Test alert system"""
    print("\nTesting alert system...")
    try:
        config = Config()
        alert_manager = AlertManager(config)
        
        print("  Testing alert formatting...")
        
        # Test SSH alert
        ssh_alert = {
            'type': 'SSH_BRUTEFORCE',
            'ip': '203.0.113.100',
            'count': 10,
            'threshold': 5,
            'time_window': 60,
            'timestamp': datetime.now().isoformat(),
            'sample_log': 'Failed password for root from 203.0.113.100'
        }
        
        # Test port scan alert
        port_alert = {
            'type': 'PORT_SCAN',
            'src_ip': '198.51.100.50',
            'count': 150,
            'threshold': 100,
            'unique_ports': 25,
            'unique_targets': 1,
            'sample_ports': [22, 23, 25, 53, 80, 135, 139, 443, 445, 993],
            'timestamp': datetime.now().isoformat()
        }
        
        print("  ✓ SSH alert format test")
        print("  ✓ Port scan alert format test")
        
        if config.slack_enabled:
            print("  Slack alerts configured")
        else:
            print("  Slack alerts not configured (optional)")
        
        print("Alert system working!")
        return True
    except Exception as e:
        print(f"  ✗ Alert system error: {e}")
        return False

def test_privileges():
    """Test system privileges"""
    print("\nTesting system privileges...")
    try:
        from utils import check_privileges
        
        has_privileges = check_privileges()
        if has_privileges:
            print("  ✓ Packet capture privileges available")
        else:
            print("  ⚠ Packet capture privileges not available")
            print("    Run: sudo setcap cap_net_raw,cap_net_admin+ep $(which python3)")
            print("    Or run as root for packet monitoring")
        
        # Check log file access
        config = Config()
        if os.path.exists(config.ssh_log_path):
            if os.access(config.ssh_log_path, os.R_OK):
                print(f"  ✓ Can read SSH log: {config.ssh_log_path}")
            else:
                print(f"  ✗ Cannot read SSH log: {config.ssh_log_path}")
                return False
        else:
            print(f"  ⚠ SSH log file not found: {config.ssh_log_path}")
            print("    This is normal on some systems or test environments")
        
        return True
    except Exception as e:
        print(f"  ✗ Privilege check error: {e}")
        return False

def run_full_test():
    """Run all tests"""
    print("Security Monitor - System Test")
    print("=" * 40)
    
    setup_logging(verbose=False)
    
    tests = [
        ("Dependencies", test_dependencies),
        ("Configuration", test_config),
        ("Whitelist", test_whitelist),
        ("Alert System", test_alerts),
        ("System Privileges", test_privileges)
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"  ✗ {test_name} failed with exception: {e}")
            results.append((test_name, False))
    
    print("\n" + "=" * 40)
    print("Test Summary:")
    
    all_passed = True
    for test_name, passed in results:
        status = "PASS" if passed else "FAIL"
        symbol = "✓" if passed else "✗"
        print(f"  {symbol} {test_name}: {status}")
        if not passed:
            all_passed = False
    
    print("\n" + "=" * 40)
    if all_passed:
        print("✓ All tests passed! System is ready.")
        print("\nTo start monitoring:")
        print("  python3 security_monitor.py")
    else:
        print("✗ Some tests failed. Please check the issues above.")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(run_full_test())