#!/usr/bin/env python3
"""
Web Frontend for Mini VPN - Interactive web interface to demonstrate VPN functionality
"""

from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import threading
import time
import json
import logging
from vpn_client import VPNClient
from ip_checker import IPChecker

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mini-vpn-demo-key'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global VPN client instance
vpn_client = None
client_lock = threading.Lock()
original_ip = None

class WebVPNClient:
    """Wrapper around VPN client for web interface"""
    
    def __init__(self):
        self.client = None
        self.connected = False
        self.original_ip = None
        self.server_ip = None
        self.ip_checker = IPChecker()
        
    def get_original_ip(self):
        """Get the original IP address"""
        if not self.original_ip:
            self.original_ip = self.ip_checker.get_public_ip()
        return self.original_ip
    
    def connect_to_vpn(self, server_host='127.0.0.1', server_port=8000):
        """Connect to VPN server"""
        try:
            self.client = VPNClient(server_host, server_port)
            if self.client.connect():
                self.connected = True
                self.server_ip = self.client.server_ip
                return {
                    'success': True,
                    'message': 'Connected to VPN server',
                    'server_ip': self.server_ip
                }
            else:
                return {
                    'success': False,
                    'message': 'Failed to connect to VPN server'
                }
        except Exception as e:
            logger.error(f"Connection error: {e}")
            return {
                'success': False,
                'message': f'Connection error: {str(e)}'
            }
    
    def disconnect_from_vpn(self):
        """Disconnect from VPN server"""
        try:
            if self.client:
                self.client.disconnect()
            self.connected = False
            self.client = None
            return {
                'success': True,
                'message': 'Disconnected from VPN server'
            }
        except Exception as e:
            logger.error(f"Disconnection error: {e}")
            return {
                'success': False,
                'message': f'Disconnection error: {str(e)}'
            }
    
    def test_ip_masking(self):
        """Test IP masking functionality"""
        if not self.connected or not self.client:
            return {
                'success': False,
                'message': 'Not connected to VPN server'
            }
        
        try:
            response = self.client.make_http_request('https://httpbin.org/ip')
            if response and 'content' in response:
                ip_data = json.loads(response['content'])
                vpn_ip = ip_data.get('origin', 'Unknown')
                
                return {
                    'success': True,
                    'original_ip': self.original_ip,
                    'vpn_ip': vpn_ip,
                    'server_ip': self.server_ip,
                    'ip_masked': vpn_ip != self.original_ip,
                    'response': response
                }
            else:
                return {
                    'success': False,
                    'message': 'Failed to make request through VPN'
                }
        except Exception as e:
            logger.error(f"IP masking test error: {e}")
            return {
                'success': False,
                'message': f'Test error: {str(e)}'
            }
    
    def ping_server(self):
        """Ping VPN server"""
        if not self.connected or not self.client:
            return {
                'success': False,
                'message': 'Not connected to VPN server'
            }
        
        try:
            result = self.client.ping_server()
            return {
                'success': result,
                'message': 'Ping successful' if result else 'Ping failed'
            }
        except Exception as e:
            logger.error(f"Ping error: {e}")
            return {
                'success': False,
                'message': f'Ping error: {str(e)}'
            }

# Global web client instance
web_client = WebVPNClient()

@app.route('/')
def index():
    """Main page"""
    return render_template('index.html')

@app.route('/api/status')
def get_status():
    """Get current VPN status"""
    return jsonify({
        'connected': web_client.connected,
        'original_ip': web_client.get_original_ip(),
        'server_ip': web_client.server_ip,
        'timestamp': time.time()
    })

@app.route('/api/connect', methods=['POST'])
def connect_vpn():
    """Connect to VPN server"""
    data = request.get_json() or {}
    server_host = data.get('host', '127.0.0.1')
    server_port = data.get('port', 8000)
    
    result = web_client.connect_to_vpn(server_host, server_port)
    
    # Emit status update to all clients
    socketio.emit('status_update', {
        'connected': web_client.connected,
        'server_ip': web_client.server_ip
    })
    
    return jsonify(result)

@app.route('/api/disconnect', methods=['POST'])
def disconnect_vpn():
    """Disconnect from VPN server"""
    result = web_client.disconnect_from_vpn()
    
    # Emit status update to all clients
    socketio.emit('status_update', {
        'connected': web_client.connected,
        'server_ip': None
    })
    
    return jsonify(result)

@app.route('/api/test-ip', methods=['POST'])
def test_ip_masking():
    """Test IP masking functionality"""
    result = web_client.test_ip_masking()
    
    # Emit test results to all clients
    socketio.emit('ip_test_result', result)
    
    return jsonify(result)

@app.route('/api/ping', methods=['POST'])
def ping_server():
    """Ping VPN server"""
    result = web_client.ping_server()
    return jsonify(result)

@app.route('/api/make-request', methods=['POST'])
def make_request():
    """Make custom HTTP request through VPN"""
    if not web_client.connected or not web_client.client:
        return jsonify({
            'success': False,
            'message': 'Not connected to VPN server'
        })
    
    data = request.get_json()
    url = data.get('url', 'https://httpbin.org/ip')
    
    try:
        response = web_client.client.make_http_request(url)
        return jsonify({
            'success': True,
            'response': response
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Request error: {str(e)}'
        })

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logger.info('Web client connected')
    emit('status_update', {
        'connected': web_client.connected,
        'original_ip': web_client.get_original_ip(),
        'server_ip': web_client.server_ip
    })

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info('Web client disconnected')

def main():
    """Main function to run the web application"""
    print("=== Mini VPN Web Interface ===")
    print("Starting web interface for VPN demonstration...")
    print("Access the web interface at: http://localhost:5000")
    print()
    
    # Get original IP on startup
    original_ip = web_client.get_original_ip()
    if original_ip:
        print(f"Your original IP address: {original_ip}")
    else:
        print("Warning: Could not determine original IP address")
    
    print("\nStarting web server...")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)

if __name__ == '__main__':
    main()