"""
config.py - Configuration for Secure Chat System
"""

class Config:
    # Network settings
    RELAY_HOST = "localhost"
    RELAY_PORT = 5000
    
    # File paths
    RELAY_PUBKEY_FILE = "relay_pubkey.pem"
    RELAY_PRIVKEY_FILE = "relay_privkey.pem"
    
    # Timeouts
    CONNECTION_TIMEOUT = 10
    REGISTRATION_TIMEOUT = 30
    AUTH_TIMEOUT = 30