"""
IP checking utilities for demonstrating VPN masking functionality.
Provides methods to check public IP addresses before and after VPN connection.
"""

import requests
import socket
import logging

logger = logging.getLogger(__name__)

class IPChecker:
    """Utility class for checking IP addresses and demonstrating VPN masking."""
    
    def __init__(self):
        self.ip_services = [
            'https://httpbin.org/ip',
            'https://api.ipify.org?format=json',
            'https://ipinfo.io/json'
        ]
    
    def get_public_ip(self):
        """
        Get the current public IP address.
        
        Returns:
            str: Public IP address or None if unable to determine
        """
        for service in self.ip_services:
            try:
                response = requests.get(service, timeout=10)
                response.raise_for_status()
                
                data = response.json()
                
                # Different services return IP in different formats
                if 'origin' in data:  # httpbin.org
                    return data['origin'].split(',')[0].strip()
                elif 'ip' in data:  # ipify.org and ipinfo.io
                    return data['ip']
                    
            except Exception as e:
                logger.warning(f"Failed to get IP from {service}: {e}")
                continue
        
        logger.error("Unable to determine public IP from any service")
        return None
    
    def get_local_ip(self):
        """
        Get the local IP address of this machine.
        
        Returns:
            str: Local IP address
        """
        try:
            # Connect to a remote address to determine local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception as e:
            logger.error(f"Failed to get local IP: {e}")
            return "127.0.0.1"
    
    def check_vpn_effectiveness(self, original_ip):
        """
        Check if VPN is working by comparing current IP with original IP.
        
        Args:
            original_ip (str): Original IP before VPN connection
            
        Returns:
            dict: Results of VPN effectiveness check
        """
        current_ip = self.get_public_ip()
        
        if current_ip is None:
            return {
                'success': False,
                'error': 'Unable to determine current IP'
            }
        
        vpn_working = current_ip != original_ip
        
        return {
            'success': True,
            'original_ip': original_ip,
            'current_ip': current_ip,
            'vpn_working': vpn_working,
            'ip_changed': vpn_working
        }
    
    def demonstrate_ip_masking(self):
        """
        Demonstrate IP masking by showing before/after IP addresses.
        
        Returns:
            dict: Demonstration results
        """
        print("\n=== IP Masking Demonstration ===")
        
        print("Checking original IP address...")
        original_ip = self.get_public_ip()
        
        if original_ip:
            print(f"Original IP: {original_ip}")
            return {
                'original_ip': original_ip,
                'local_ip': self.get_local_ip()
            }
        else:
            print("Failed to determine original IP")
            return None

def make_test_request():
    """
    Make a test HTTP request to demonstrate traffic routing through VPN.
    
    Returns:
        dict: Response data or error information
    """
    try:
        response = requests.get('https://httpbin.org/ip', timeout=10)
        response.raise_for_status()
        return {
            'success': True,
            'data': response.json()
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }
