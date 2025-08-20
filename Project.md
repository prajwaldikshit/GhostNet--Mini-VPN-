# Overview

This is a demonstration Virtual Private Network (VPN) implementation built with Python that showcases network programming, cryptography, and traffic forwarding concepts. The system consists of a VPN server and client that establish encrypted tunnels to mask client IP addresses and route traffic securely through the server.

The project demonstrates core VPN functionality including AES-256 encryption for all communications, IP masking where client traffic appears to originate from the server's IP address, and HTTP request forwarding through the encrypted tunnel. It's designed as an educational tool to understand VPN principles rather than a production-ready solution.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Core Components

**Client-Server Architecture**: The system uses a traditional client-server model where the VPN client connects to a centralized VPN server. The server can handle multiple concurrent clients using Python threading.

**Socket-based Communication**: Built on Python's socket library for network communication, establishing TCP connections between clients and the server for reliable data transmission.

**Encryption Layer**: Implements AES-256 encryption in CBC mode using the cryptography library. All traffic between client and server is encrypted with randomly generated initialization vectors (IVs) for each message, ensuring secure communication.

**Traffic Forwarding**: The server acts as a proxy, receiving encrypted HTTP requests from clients, decrypting them, forwarding to target websites, and returning encrypted responses. This creates the IP masking effect where external services see the server's IP instead of the client's.

**Multi-threading Support**: The server uses threading to handle multiple simultaneous client connections, with each client getting its own dedicated thread for request processing.

## Key Design Patterns

**Utility Classes**: Separated concerns with dedicated utility classes - `AESCipher` for encryption operations, `IPChecker` for IP address verification, and message serialization functions for secure data transmission.

**Logging Integration**: Comprehensive logging throughout the system using Python's logging module, with both file and console output for monitoring connections, encryption operations, and traffic flow.

**Error Handling**: Robust error handling with fallback mechanisms, particularly in IP checking where multiple services are tried if one fails.

# External Dependencies

**Python Standard Library**: Uses `socket` for network communication, `threading` for concurrent client handling, `logging` for system monitoring, and `json` for data serialization.

**Cryptography Library**: Leverages the `cryptography` package for AES encryption implementation, providing secure cipher operations with proper padding and IV generation.

**Requests Library**: Uses `requests` for making HTTP calls during IP checking and traffic forwarding operations.

**IP Checking Services**: Integrates with multiple public IP checking services including httpbin.org, ipify.org, and ipinfo.io to demonstrate IP masking functionality and provide fallback options.

No database is required as this is a demonstration system that doesn't persist connection or user data.
