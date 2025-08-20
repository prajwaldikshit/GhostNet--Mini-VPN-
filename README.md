# Mini VPN - Python Socket-based VPN with AES Encryption

A demonstration Virtual Private Network (VPN) implementation using Python sockets, featuring AES encryption and IP masking capabilities. This project showcases network programming, cryptography, and traffic forwarding concepts.

## Features

- **Encrypted Traffic**: All communication between client and server is encrypted using AES-256 encryption
- **IP Masking**: Client traffic appears to originate from the VPN server's IP address
- **Multi-client Support**: Server can handle multiple concurrent clients using threading
- **Traffic Forwarding**: HTTP requests are forwarded through the VPN server to the internet
- **Real-time Demonstration**: Interactive client interface to demonstrate VPN functionality
- **Comprehensive Logging**: Detailed logging of connections, encryption, and traffic

## Architecture

