#!/usr/bin/env python3
"""
VPN Server - Mini VPN implementation with AES encryption and traffic forwarding.
Accepts client connections, encrypts/decrypts traffic, and forwards to the internet.
"""

import socket
import threading
import logging
import json
import time
import signal
import sys
import requests
from crypto_utils import AESCipher, serialize_message, deserialize_message
from ip_checker import IPChecker

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vpn_server.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class VPNServer:
    """VPN Server that handles encrypted client connections and traffic forwarding."""
    
    def __init__(self, host='0.0.0.0', port=8000):
        """
        Initialize VPN Server.
        
        Args:
            host (str): Server bind address
            port (int): Server bind port
        """
        self.host = host
        self.port = port
        self.server_socket = None
        self.clients = {}  # client_id -> client_info
        self.running = False
        self.client_counter = 0
        
        # Initialize encryption
        self.cipher = AESCipher()
        logger.info(f"Server encryption key: {self.cipher.get_key_base64()}")
        
        # Get server's public IP for demonstration
        ip_checker = IPChecker()
        self.server_public_ip = ip_checker.get_public_ip()
        logger.info(f"Server public IP: {self.server_public_ip}")
    
    def start(self):
        """Start the VPN server and listen for connections."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            
            self.running = True
            logger.info(f"VPN Server started on {self.host}:{self.port}")
            print(f"VPN Server running on {self.host}:{self.port}")
            print(f"Server Public IP: {self.server_public_ip}")
            print(f"Encryption Key: {self.cipher.get_key_base64()}")
            print("Waiting for client connections...\n")
            
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    self.client_counter += 1
                    client_id = f"client_{self.client_counter}"
                    
                    logger.info(f"New connection from {client_address} (ID: {client_id})")
                    
                    # Store client info
                    self.clients[client_id] = {
                        'socket': client_socket,
                        'address': client_address,
                        'connected_at': time.time()
                    }
                    
                    # Handle client in separate thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_id, client_socket, client_address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except socket.error as e:
                    if self.running:
                        logger.error(f"Error accepting connection: {e}")
                    
        except Exception as e:
            logger.error(f"Failed to start server: {e}")
            raise
    
    def handle_client(self, client_id, client_socket, client_address):
        """
        Handle individual client connection and traffic forwarding.
        
        Args:
            client_id (str): Unique client identifier
            client_socket (socket): Client socket connection
            client_address (tuple): Client address (host, port)
        """
        try:
            # Send handshake with encryption key
            handshake_data = {
                'encryption_key': self.cipher.get_key_base64(),
                'server_ip': self.server_public_ip
            }
            handshake_msg = serialize_message('handshake', handshake_data)
            client_socket.send(handshake_msg.encode('utf-8'))
            
            logger.info(f"Sent handshake to {client_id}")
            
            while self.running:
                try:
                    # Receive encrypted data from client
                    data = client_socket.recv(4096)
                    if not data:
                        break
                    
                    # Decrypt message
                    try:
                        decrypted_data = self.cipher.decrypt(json.loads(data.decode('utf-8')))
                        message_type, message_data = deserialize_message(decrypted_data.decode('utf-8'))
                        
                        if message_type == 'http_request':
                            # Forward HTTP request to internet and send back response
                            self.forward_http_request(client_socket, message_data)
                        elif message_type == 'ping':
                            # Respond to ping
                            self.send_encrypted_message(client_socket, 'pong', {'timestamp': time.time()})
                        else:
                            logger.warning(f"Unknown message type from {client_id}: {message_type}")
                            
                    except Exception as e:
                        logger.error(f"Error processing message from {client_id}: {e}")
                        
                except socket.timeout:
                    continue
                except socket.error as e:
                    logger.warning(f"Socket error with {client_id}: {e}")
                    break
                    
        except Exception as e:
            logger.error(f"Error handling client {client_id}: {e}")
        finally:
            self.cleanup_client(client_id, client_socket)
    
    def forward_http_request(self, client_socket, request_data):
        """
        Forward HTTP request to the internet and return response.
        
        Args:
            client_socket (socket): Client socket to send response to
            request_data (dict): HTTP request data
        """
        try:
            url = request_data.get('url')
            method = request_data.get('method', 'GET')
            headers = request_data.get('headers', {})
            
            logger.info(f"Forwarding {method} request to {url}")
            
            # Make request to internet
            if method.upper() == 'GET':
                response = requests.get(url, headers=headers, timeout=10)
            elif method.upper() == 'POST':
                data = request_data.get('data', {})
                response = requests.post(url, headers=headers, json=data, timeout=10)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            # Prepare response data
            response_data = {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content': response.text,
                'url': response.url
            }
            
            # Send encrypted response back to client
            self.send_encrypted_message(client_socket, 'http_response', response_data)
            logger.info(f"Forwarded response (status: {response.status_code})")
            
        except Exception as e:
            logger.error(f"Error forwarding HTTP request: {e}")
            error_response = {
                'error': str(e),
                'status_code': 500
            }
            self.send_encrypted_message(client_socket, 'http_error', error_response)
    
    def send_encrypted_message(self, client_socket, message_type, data):
        """
        Send encrypted message to client.
        
        Args:
            client_socket (socket): Client socket
            message_type (str): Message type
            data (any): Message data
        """
        try:
            message = serialize_message(message_type, data)
            encrypted_message = self.cipher.encrypt(message)
            client_socket.send(json.dumps(encrypted_message).encode('utf-8'))
        except Exception as e:
            logger.error(f"Error sending encrypted message: {e}")
    
    def cleanup_client(self, client_id, client_socket):
        """
        Clean up client connection.
        
        Args:
            client_id (str): Client identifier
            client_socket (socket): Client socket
        """
        try:
            client_socket.close()
        except:
            pass
        
        if client_id in self.clients:
            del self.clients[client_id]
        
        logger.info(f"Cleaned up client {client_id}")
    
    def stop(self):
        """Stop the VPN server gracefully."""
        logger.info("Stopping VPN server...")
        self.running = False
        
        # Close all client connections
        for client_id, client_info in self.clients.copy().items():
            try:
                client_info['socket'].close()
            except:
                pass
        
        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        logger.info("VPN server stopped")
    
    def get_status(self):
        """Get server status information."""
        return {
            'running': self.running,
            'connected_clients': len(self.clients),
            'server_ip': self.server_public_ip,
            'clients': {cid: {'address': info['address'], 'connected_at': info['connected_at']} 
                       for cid, info in self.clients.items()}
        }

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully."""
    print("\nShutting down VPN server...")
    if 'server' in globals():
        server.stop()
    sys.exit(0)

def main():
    """Main server function."""
    global server
    
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    print("=== Mini VPN Server ===")
    print("Starting VPN server with AES encryption and traffic forwarding...\n")
    
    try:
        server = VPNServer()
        server.start()
    except KeyboardInterrupt:
        print("\nServer interrupted by user")
    except Exception as e:
        print(f"Server error: {e}")
        logger.error(f"Server error: {e}")
    finally:
        if 'server' in locals():
            server.stop()

if __name__ == "__main__":
    main()
