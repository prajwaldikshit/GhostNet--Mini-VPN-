#!/usr/bin/env python3
"""
VPN Client - Connects to VPN server and demonstrates IP masking with encrypted traffic.
Routes HTTP requests through the VPN server to demonstrate IP masking functionality.
"""

import socket
import json
import time
import logging
import threading
import sys
from crypto_utils import AESCipher, serialize_message, deserialize_message
from ip_checker import IPChecker, make_test_request

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vpn_client.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class VPNClient:
    """VPN Client that connects to server and routes traffic through encrypted tunnel."""
    
    def __init__(self, server_host='127.0.0.1', server_port=8000):
        """
        Initialize VPN Client.
        
        Args:
            server_host (str): VPN server address
            server_port (int): VPN server port
        """
        self.server_host = server_host
        self.server_port = server_port
        self.socket = None
        self.cipher = None
        self.connected = False
        self.server_ip = None
        
        # IP checking utility
        self.ip_checker = IPChecker()
        self.original_ip = None
    
    def connect(self):
        """Connect to the VPN server and establish encrypted tunnel."""
        try:
            print(f"Connecting to VPN server at {self.server_host}:{self.server_port}...")
            
            # Get original IP before connecting
            print("Checking original IP address...")
            self.original_ip = self.ip_checker.get_public_ip()
            if self.original_ip:
                print(f"Original IP: {self.original_ip}")
            else:
                print("Warning: Could not determine original IP")
            
            # Connect to server
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_host, self.server_port))
            
            # Receive handshake with encryption key
            handshake_data = self.socket.recv(4096)
            message_type, handshake_info = deserialize_message(handshake_data.decode('utf-8'))
            
            if message_type == 'handshake':
                # Initialize encryption with received key
                encryption_key = handshake_info['encryption_key']
                self.cipher = AESCipher.from_base64_key(encryption_key)
                self.server_ip = handshake_info.get('server_ip')
                
                self.connected = True
                print(f"✓ Connected to VPN server!")
                print(f"✓ Encryption established")
                print(f"✓ Server IP: {self.server_ip}")
                print("✓ VPN tunnel is active\n")
                
                logger.info(f"Connected to VPN server at {self.server_host}:{self.server_port}")
                return True
            else:
                raise Exception("Invalid handshake response")
                
        except Exception as e:
            logger.error(f"Failed to connect to VPN server: {e}")
            print(f"✗ Connection failed: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from VPN server."""
        self.connected = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        print("Disconnected from VPN server")
        logger.info("Disconnected from VPN server")
    
    def send_encrypted_message(self, message_type, data):
        """
        Send encrypted message to server.
        
        Args:
            message_type (str): Message type
            data (any): Message data
            
        Returns:
            bool: Success status
        """
        try:
            if not self.connected or not self.cipher:
                return False
            
            message = serialize_message(message_type, data)
            encrypted_message = self.cipher.encrypt(message)
            self.socket.send(json.dumps(encrypted_message).encode('utf-8'))
            return True
        except Exception as e:
            logger.error(f"Error sending encrypted message: {e}")
            return False
    
    def receive_encrypted_message(self, timeout=10):
        """
        Receive and decrypt message from server.
        
        Args:
            timeout (int): Receive timeout in seconds
            
        Returns:
            tuple: (message_type, data) or (None, None) on error
        """
        try:
            self.socket.settimeout(timeout)
            data = self.socket.recv(4096)
            
            if not data:
                return None, None
            
            # Decrypt message
            encrypted_package = json.loads(data.decode('utf-8'))
            decrypted_data = self.cipher.decrypt(encrypted_package)
            message_type, message_data = deserialize_message(decrypted_data.decode('utf-8'))
            
            return message_type, message_data
            
        except socket.timeout:
            logger.warning("Timeout receiving message from server")
            return None, None
        except Exception as e:
            logger.error(f"Error receiving encrypted message: {e}")
            return None, None
    
    def make_http_request(self, url, method='GET', headers=None):
        """
        Make HTTP request through VPN tunnel.
        
        Args:
            url (str): URL to request
            method (str): HTTP method
            headers (dict): HTTP headers
            
        Returns:
            dict: Response data or None on error
        """
        if not self.connected:
            print("Error: Not connected to VPN server")
            return None
        
        request_data = {
            'url': url,
            'method': method,
            'headers': headers or {}
        }
        
        print(f"Making {method} request to {url} through VPN tunnel...")
        
        # Send request through encrypted tunnel
        if not self.send_encrypted_message('http_request', request_data):
            print("Error: Failed to send request through VPN")
            return None
        
        # Receive response
        message_type, response_data = self.receive_encrypted_message()
        
        if message_type == 'http_response':
            print(f"✓ Received response (Status: {response_data['status_code']})")
            return response_data
        elif message_type == 'http_error':
            print(f"✗ Request failed: {response_data.get('error', 'Unknown error')}")
            return response_data
        else:
            print("✗ Invalid response from VPN server")
            return None
    
    def demonstrate_ip_masking(self):
        """Demonstrate IP masking by making requests through VPN."""
        print("\n=== IP Masking Demonstration ===")
        
        if not self.connected:
            print("Error: Not connected to VPN server")
            return
        
        # Show original IP
        print(f"Original IP (before VPN): {self.original_ip}")
        print(f"VPN Server IP: {self.server_ip}")
        
        # Make request through VPN to check current IP
        print("\nChecking IP through VPN tunnel...")
        response = self.make_http_request('https://httpbin.org/ip')
        
        if response and 'content' in response:
            try:
                ip_data = json.loads(response['content'])
                current_ip = ip_data.get('origin', 'Unknown')
                
                print(f"Current IP (through VPN): {current_ip}")
                
                # Analyze results
                if current_ip != self.original_ip:
                    print("✓ IP MASKING SUCCESSFUL!")
                    print(f"✓ Your traffic appears to come from: {current_ip}")
                    print(f"✓ Original IP ({self.original_ip}) is hidden")
                else:
                    print("✗ IP masking may not be working properly")
                    
            except json.JSONDecodeError:
                print("✗ Could not parse IP response")
        else:
            print("✗ Failed to check IP through VPN")
        
        print("\n" + "="*50)
    
    def ping_server(self):
        """Send ping to server to test connection."""
        if not self.connected:
            return False
        
        print("Pinging VPN server...")
        if self.send_encrypted_message('ping', {'timestamp': time.time()}):
            message_type, response = self.receive_encrypted_message(timeout=5)
            if message_type == 'pong':
                print("✓ Ping successful")
                return True
        
        print("✗ Ping failed")
        return False
    
    def run_interactive_demo(self):
        """Run interactive demonstration of VPN functionality."""
        if not self.connect():
            return
        
        try:
            while True:
                print("\n=== Mini VPN Client Menu ===")
                print("1. Demonstrate IP masking")
                print("2. Make custom HTTP request")
                print("3. Ping VPN server")
                print("4. Show connection status")
                print("5. Quit")
                
                choice = input("\nEnter your choice (1-5): ").strip()
                
                if choice == '1':
                    self.demonstrate_ip_masking()
                    
                elif choice == '2':
                    url = input("Enter URL: ").strip()
                    if url:
                        response = self.make_http_request(url)
                        if response:
                            print(f"Status: {response.get('status_code')}")
                            content = response.get('content', '')
                            if len(content) > 500:
                                print(f"Content (first 500 chars): {content[:500]}...")
                            else:
                                print(f"Content: {content}")
                
                elif choice == '3':
                    self.ping_server()
                
                elif choice == '4':
                    print(f"Connected: {self.connected}")
                    print(f"Server: {self.server_host}:{self.server_port}")
                    print(f"Original IP: {self.original_ip}")
                    print(f"Server IP: {self.server_ip}")
                
                elif choice == '5':
                    break
                
                else:
                    print("Invalid choice. Please try again.")
                    
        except KeyboardInterrupt:
            print("\nExiting...")
        finally:
            self.disconnect()

def main():
    """Main client function."""
    print("=== Mini VPN Client ===")
    print("Demonstrating IP masking with encrypted traffic tunneling\n")
    
    # Parse command line arguments (simple implementation)
    server_host = '127.0.0.1'
    server_port = 8000
    
    if len(sys.argv) > 1:
        server_host = sys.argv[1]
    if len(sys.argv) > 2:
        try:
            server_port = int(sys.argv[2])
        except ValueError:
            print("Invalid port number")
            return
    
    client = VPNClient(server_host, server_port)
    client.run_interactive_demo()

if __name__ == "__main__":
    main()
