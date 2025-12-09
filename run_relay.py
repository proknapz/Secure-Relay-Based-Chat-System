"""
run_relay.py - Start the Relay Server

This script:
1. Starts the relay server
2. Saves the relay's public key to a file for clients to use
3. Handles graceful shutdown
"""

import sys
import os
import argparse

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from relay.relay_server import RelayServer
from config import Config


def save_relay_public_key(relay: RelayServer):
    """Save relay's public key to file for clients"""
    try:
        with open(Config.RELAY_PUBKEY_FILE, 'wb') as f:
            f.write(relay.public_key_pem)
        print(f"[Setup] ✓ Relay public key saved to: {Config.RELAY_PUBKEY_FILE}")
        print(f"[Setup] Clients will use this key for authentication\n")
    except Exception as e:
        print(f"[Setup] ✗ Error saving public key: {e}")


def main():
    parser = argparse.ArgumentParser(description='Start the Relay Server')
    parser.add_argument('--host', default=Config.RELAY_HOST, help='Host to bind the relay')
    parser.add_argument('--port', type=int, default=Config.RELAY_PORT, help='Port to bind the relay')
    args = parser.parse_args()

    print("=" * 60)
    print("   SECURE RELAY-BASED CHAT SYSTEM - RELAY SERVER")
    print("=" * 60)
    print()

    # Create relay server with CLI-configured host/port
    relay = RelayServer(host=args.host, port=args.port)
    
    # Save public key for clients
    save_relay_public_key(relay)
    
    print("Starting relay server...")
    print("Press Ctrl+C to stop")
    print("-" * 60)
    print()
    
    try:
        relay.start()
    except KeyboardInterrupt:
        print("\n")
        print("-" * 60)
        print("Shutting down relay server...")
        relay.stop()
        print("✓ Relay server stopped successfully")


if __name__ == "__main__":
    main()