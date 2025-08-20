---
GhostNet--Mini-VPN
---
Mini VPN - Python Socket-based VPN with AES Encryption
A demonstration Virtual Private Network (VPN) implementation built with Python that showcases network programming, cryptography, and traffic forwarding concepts. This project features a complete VPN system with both command-line and web interfaces, demonstrating core VPN functionality including AES-256 encryption and IP masking.
________________________________________
🌟 Features
•	🔐 AES-256 Encryption: All communication between client and server is encrypted using industry-standard AES-256 encryption.
•	🎭 IP Masking: Client traffic appears to originate from the VPN server’s IP address.
•	🌐 Web Interface: Beautiful, interactive web dashboard for easy VPN management and testing.
•	👥 Multi-client Support: Server can handle multiple concurrent clients using Python threading.
•	🚀 HTTP Traffic Forwarding: HTTP requests are securely forwarded through the VPN server.
•	📊 Real-time Monitoring: Live connection status, activity logs, and performance metrics.
•	🔍 Testing Tools: Built-in IP masking tests and custom HTTP request capabilities.
•	📱 Responsive Design: Web interface works seamlessly on desktop and mobile devices.
________________________________________
🏗️ Architecture
System Overview
┌─────────────────┐    Encrypted    ┌─────────────────┐    HTTP/HTTPS    ┌─────────────────┐
│   VPN Client    │◄────────────────►│   VPN Server    │◄─────────────────►│   Internet      │
│                 │    AES-256      │                 │                  │   (httpbin.org) │
└─────────────────┘                 └─────────────────┘                  └─────────────────┘
         │                                   │
         ▼                                   ▼
┌─────────────────┐                 ┌─────────────────┐
│  Web Interface  │                 │  Activity Logs  │
│  (Dashboard)    │                 │  & Monitoring   │
└─────────────────┘                 └─────────────────┘
Core Components
•	VPN Server (vpn_server.py): Central server handling encrypted connections and traffic forwarding.
•	VPN Client (vpn_client.py): Command-line client with interactive demonstration capabilities.
•	Web Interface (web_app.py): Flask-based web dashboard for easy VPN management.
•	Crypto Utilities (crypto_utils.py): AES encryption/decryption and message serialization.
•	IP Checker (ip_checker.py): IP address verification and masking demonstration tools.
________________________________________

Screenshots: 📸

<img width="975" height="472" alt="image" src="https://github.com/user-attachments/assets/ba3bb4d4-a641-4e12-ba81-72918d5295e6" />
<img width="975" height="461" alt="image" src="https://github.com/user-attachments/assets/01ede041-6385-4bef-b7b2-e90bc9d6a218" />
<img width="975" height="472" alt="image" src="https://github.com/user-attachments/assets/edb68a80-2332-4327-a2f0-51e092b99210" />
<img width="975" height="452" alt="image" src="https://github.com/user-attachments/assets/06e20350-11c2-4d80-8478-da59c2bec0e1" />
<img width="975" height="487" alt="image" src="https://github.com/user-attachments/assets/23372c84-b559-418b-ad52-626b1f3db8b8" />
<img width="975" height="304" alt="image" src="https://github.com/user-attachments/assets/6f0e455a-dd6a-43e9-926b-e95f4692199c" />
<img width="975" height="172" alt="image" src="https://github.com/user-attachments/assets/fd5b3804-64d4-44c5-af1e-597757bab23e" />
<img width="975" height="513" alt="image" src="https://github.com/user-attachments/assets/2895f568-4d6d-4d3f-8576-f4154d49e789" />

________________________________________
🚀 Quick Start
Prerequisites
•	Python 3.7+
•	Required packages: cryptography, flask, flask-socketio, requests
Installation & Setup
1.	Clone or download the project files.
2.	Install dependencies (handled automatically by Replit).
3.	Start the VPN Server:
python vpn_server.py
4.	Launch the Web Interface:
python web_app.py
5.	Access the Web Dashboard at http://localhost:5000.
Alternative: Command Line Usage
Start the command-line client for interactive testing:
python vpn_client.py
________________________________________
💻 Usage Guide
Web Interface
•	Access Dashboard: Open http://localhost:5000 in your browser.
•	Connect to VPN: Click “Connect to VPN” (default: 127.0.0.1:8000).
•	Test IP Masking: Click “Test IP Masking” to see your IP change.
•	Custom Requests: Test any URL through the encrypted VPN tunnel.
•	Monitor Activity: View real-time logs and connection status.
Command Line Interface
The command-line client provides an interactive menu:
=== Mini VPN Client Menu ===
1. Demonstrate IP masking
2. Make custom HTTP request
3. Ping VPN server
4. Show connection status
5. Quit
API Endpoints
•	GET /api/status - Get current VPN connection status
•	POST /api/connect - Connect to VPN server
•	POST /api/disconnect - Disconnect from VPN server
•	POST /api/test-ip - Test IP masking functionality
•	POST /api/ping - Ping VPN server
•	POST /api/make-request - Make custom HTTP request through VPN
________________________________________
📁 Project Structure
mini-vpn/
├── vpn_server.py          # VPN server with encryption & traffic forwarding
├── vpn_client.py          # Interactive VPN client (command-line)
├── web_app.py             # Flask web interface & dashboard
├── crypto_utils.py        # AES encryption utilities
├── ip_checker.py          # IP address checking & verification
├── templates/
│   └── index.html         # Web interface frontend
├── README.md              # Documentation
└── replit.md              # Project configuration & preferences
________________________________________
🔧 Technical Details
Encryption
•	Algorithm: AES-256 in CBC mode
•	Key Generation: Cryptographically secure random 256-bit keys
•	Initialization Vectors: Random IV for each message
•	Padding: PKCS7 padding for block alignment
Network Communication
•	Protocol: TCP sockets for reliable communication
•	Message Format: JSON serialization with encrypted payloads
•	Threading: Multi-threaded server supporting concurrent clients
•	Error Handling: Comprehensive error handling and logging
Security Features
•	Encrypted Handshake: Secure key exchange during connection
•	Message Authentication: Integrity verification for all communications
•	No Key Storage: Keys generated fresh for each session
•	Session Management: Proper connection cleanup and resource management
________________________________________
🧪 Testing & Demonstration
IP Masking Test
Steps: 1. Check original public IP. 2. Establish encrypted VPN tunnel. 3. Make HTTP requests through the tunnel. 4. Verify that external services see the server’s IP instead of yours.
Example Output:
=== IP Masking Demonstration ===
Original IP (before VPN): 203.0.113.1
VPN Server IP: 198.51.100.1
Current IP (through VPN): 198.51.100.1
✓ IP MASKING SUCCESSFUL!
✓ Your traffic appears to come from: 198.51.100.1
✓ Original IP (203.0.113.1) is hidden
________________________________________
⚠️ Security Considerations
•	Educational Purpose: This is a demonstration VPN for learning network programming concepts. It is NOT intended for production use or real privacy protection.
•	Limitations:
o	No perfect forward secrecy
o	Simplified key management
o	Limited to HTTP traffic demonstration
o	No DNS leak protection
o	Single-hop architecture
________________________________________
🔍 Troubleshooting
Common Issues
•	VPN Connection Failed: Ensure VPN server is running on port 8000, check firewall settings.
•	Web Interface Not Loading: Confirm web server is running on port 5000, check browser console.
•	IP Masking Not Working: Works best when server and client have different public IPs.
Debugging
•	vpn_server.log - Server activity and errors
•	vpn_client.log - Client connection and request logs
•	Web browser console - Frontend errors
________________________________________
🔧 Configuration
Server Settings
Edit vpn_server.py to modify: - Bind Address: Default 0.0.0.0 - Port: Default 8000 - Connection Timeout: Adjust socket timeout values - Logging Level: Change logging.INFO to logging.DEBUG
Client Settings
Edit vpn_client.py or use command-line arguments:
python vpn_client.py <server_host> <server_port>
________________________________________
📊 Performance
•	Encryption Overhead: ~5-10% for small messages
•	Connection Setup: <100ms for local connections
•	Throughput: Limited by Python threading and encryption processing
•	Concurrent Clients: Tested with up to 10 simultaneous connections
________________________________________
🚀 Future Enhancements
•	UDP support for better performance
•	Perfect forward secrecy
•	DNS tunneling capabilities
•	Traffic obfuscation techniques
•	Authentication and user management
•	Bandwidth limiting and QoS
•	Mobile app interface
________________________________________
🤝 Contributing
•	Fork and experiment with the code
•	Implement additional features
•	Improve security mechanisms
•	Add new encryption algorithms
•	Enhance the web interface
________________________________________

🎓 Educational Value
•	Network Programming: Socket programming, client-server architecture
•	Cryptography: Symmetric encryption, secure key exchange
•	Web Development: Flask, REST APIs, real-time interfaces
•	Systems Programming: Threading, process management, logging
•	Security: VPN protocols, traffic analysis, IP masking
Disclaimer: This is an educational demonstration. Do not use for actual privacy protection or in production environments.

_______________________________________

This project was personally developed by Prajwal Dikshit and Vibudhan Dubey as part of our MCA learning journey.
