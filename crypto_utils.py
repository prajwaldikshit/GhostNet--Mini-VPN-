"""
Cryptographic utilities for VPN encryption/decryption using AES.
Provides symmetric encryption for secure communication between client and server.
"""

import os
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64

class AESCipher:
    """AES encryption/decryption handler for VPN traffic."""
    
    def __init__(self, key=None):
        """
        Initialize AES cipher with a key.
        
        Args:
            key (bytes): 32-byte AES key. If None, generates a new random key.
        """
        if key is None:
            self.key = os.urandom(32)  # 256-bit key
        else:
            self.key = key
    
    def encrypt(self, data):
        """
        Encrypt data using AES-CBC mode.
        
        Args:
            data (str or bytes): Data to encrypt
            
        Returns:
            dict: Contains encrypted data and IV in base64 format
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # Generate random IV
        iv = os.urandom(16)
        
        # Pad data to block size
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data)
        padded_data += padder.finalize()
        
        # Encrypt
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        return {
            'data': base64.b64encode(encrypted_data).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8')
        }
    
    def decrypt(self, encrypted_package):
        """
        Decrypt data using AES-CBC mode.
        
        Args:
            encrypted_package (dict): Contains encrypted data and IV
            
        Returns:
            bytes: Decrypted data
        """
        encrypted_data = base64.b64decode(encrypted_package['data'])
        iv = base64.b64decode(encrypted_package['iv'])
        
        # Decrypt
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Remove padding
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data)
        data += unpadder.finalize()
        
        return data
    
    def get_key_base64(self):
        """Get the encryption key in base64 format for sharing."""
        return base64.b64encode(self.key).decode('utf-8')
    
    @classmethod
    def from_base64_key(cls, key_b64):
        """Create AESCipher instance from base64 encoded key."""
        key = base64.b64decode(key_b64)
        return cls(key)

def serialize_message(message_type, data):
    """
    Serialize a message for network transmission.
    
    Args:
        message_type (str): Type of message ('data', 'handshake', etc.)
        data (any): Message data
        
    Returns:
        str: JSON serialized message
    """
    return json.dumps({
        'type': message_type,
        'data': data
    })

def deserialize_message(message):
    """
    Deserialize a message from network transmission.
    
    Args:
        message (str): JSON serialized message
        
    Returns:
        tuple: (message_type, data)
    """
    try:
        parsed = json.loads(message)
        return parsed['type'], parsed['data']
    except (json.JSONDecodeError, KeyError):
        return None, None
