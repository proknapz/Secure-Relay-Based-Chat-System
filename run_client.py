"""
run_client.py - Start a Client

Usage:
    python run_client.py Alice
    python run_client.py Bob
    
This script:
1. Loads the relay's public key
2. Connects to the relay
3. Registers the client
4. Authenticates with the relay
5. Reports success
"""

import sys
import os
import time

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from client.client import SecureChatClient
from config import Config


def load_relay_public_key() -> bytes:
    """Load relay's public key from file"""
    try:
        with open(Config.RELAY_PUBKEY_FILE, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        print(f"✗ Error: {Config.RELAY_PUBKEY_FILE} not found!")
        print(f"  Make sure the relay server is running first.")
        print(f"  Run: python run_relay.py")
        sys.exit(1)
    except Exception as e:
        print(f"✗ Error loading relay public key: {e}")
        sys.exit(1)


def main():
    # Check arguments
    if len(sys.argv) < 2:
        print("Usage: python run_client.py <ClientID>")
        print("Example: python run_client.py Alice")
        sys.exit(1)
    
    client_id = sys.argv[1]
    
    print("=" * 60)
    print(f"   SECURE RELAY-BASED CHAT SYSTEM - CLIENT: {client_id}")
    print("=" * 60)
    print()
    
    # Create client
    client = SecureChatClient(
        client_id=client_id,
        relay_host=Config.RELAY_HOST,
        relay_port=Config.RELAY_PORT
    )
    
    try:
        # Step 1: Connect
        print("Step 1: Connecting to relay server...")
        if not client.connect():
            print("✗ Failed to connect to relay")
            return
        
        time.sleep(0.5)
        
        # Step 2: Register (Phase 1)
        print("\nStep 2: Registering with relay (Phase 1)...")
        if not client.register():
            print("✗ Registration failed")
            client.disconnect()
            return
        
        time.sleep(0.5)
        
        # Step 3: Authenticate (Phase 2)
        print("\nStep 3: Authenticating with relay (Phase 2)...")
        relay_pubkey = load_relay_public_key()
        if not client.authenticate(relay_pubkey):
            print("✗ Authentication failed")
            client.disconnect()
            return
        
        # Success!
        print()
        print("=" * 60)
        print("✓ CLIENT-RELAY SECURE COMMUNICATION ESTABLISHED!")
        print("=" * 60)
        print()
        print("Client Status:")
        status = client.get_status()
        for key, value in status.items():
            symbol = "✓" if value else "✗"
            print(f"  {symbol} {key}: {value}")
        
        print()
        print("-" * 60)
        print("Phase 1 (Registration): COMPLETE")
        print("  - RSA keypair generated")
        print("  - Public key registered with relay")
        print("  - Digital signature verified")
        print()
        print("Phase 2 (Authentication): COMPLETE")
        print("  - Nonce challenge sent to relay")
        print("  - Relay's signature verified")
        print("  - Mutual authentication established")
        print("-" * 60)
        print()
        print(f"Client {client_id} is ready for secure sessions!")
        print("Press Ctrl+C to disconnect")
        
        # Keep client running
        while True:
            time.sleep(1)
    
    except KeyboardInterrupt:
        print("\n\nDisconnecting...")
        client.disconnect()
        print(f"✓ Client {client_id} disconnected")
    except Exception as e:
        print(f"\n✗ Error: {e}")
        client.disconnect()


if __name__ == "__main__":
    main()