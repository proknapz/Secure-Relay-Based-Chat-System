"""
client.py - Secure Chat Client Implementation

Implements:
- Phase 1: Registration with relay
- Phase 2: Authentication with relay
- Phase 3: Session setup with other clients (coming next)
- Phase 4: Secure messaging (coming next)
"""

import socket
import time
import json
from typing import Optional, Tuple

from client.crypto_handler import CryptoHandler
from common.protocol import (
    RegistrationMessage, RegistrationAck,
    AuthChallenge, AuthResponse, AuthVerify,
    MessageType, ProtocolConstants,
    parse_message, create_error
)


class SecureChatClient:
    """
    Secure chat client that communicates through a relay server
    """
    
    def __init__(self, client_id: str, relay_host: str = "localhost", relay_port: int = 5000):
        self.client_id = client_id
        self.relay_host = relay_host
        self.relay_port = relay_port
        
        # Cryptographic handler
        self.crypto = CryptoHandler()
        
        # Connection state
        self.socket: Optional[socket.socket] = None
        self.is_connected = False
        self.is_registered = False
        self.is_authenticated = False
        
        # Keys
        self.private_key_pem: Optional[bytes] = None
        self.public_key_pem: Optional[bytes] = None
        self.relay_public_key_pem: Optional[bytes] = None
        
        print(f"[{self.client_id}] Client initialized")
    
    # =====================================================
    # Connection Management
    # =====================================================
    
    def connect(self) -> bool:
        """Connect to relay server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.relay_host, self.relay_port))
            self.is_connected = True
            print(f"[{self.client_id}] ✓ Connected to relay at {self.relay_host}:{self.relay_port}")
            return True
        except Exception as e:
            print(f"[{self.client_id}] ✗ Connection failed: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from relay server"""
        if self.socket:
            self.socket.close()
            self.socket = None
        self.is_connected = False
        self.is_authenticated = False
        print(f"[{self.client_id}] Disconnected from relay")
    
    def send_message(self, message: str):
        """Send message to relay"""
        if not self.socket:
            raise ConnectionError("Not connected to relay")
        
        # Add length prefix for framing
        msg_bytes = message.encode('utf-8')
        length_prefix = len(msg_bytes).to_bytes(4, byteorder='big')
        self.socket.sendall(length_prefix + msg_bytes)
    
    def receive_message(self, timeout: float = 30.0) -> str:
        """Receive message from relay"""
        if not self.socket:
            raise ConnectionError("Not connected to relay")
        
        self.socket.settimeout(timeout)
        
        try:
            # Read length prefix
            length_bytes = self.socket.recv(4)
            if not length_bytes:
                raise ConnectionError("Connection closed by relay")
            
            msg_length = int.from_bytes(length_bytes, byteorder='big')
            
            # Read message
            msg_bytes = b""
            while len(msg_bytes) < msg_length:
                chunk = self.socket.recv(msg_length - len(msg_bytes))
                if not chunk:
                    raise ConnectionError("Connection closed while reading message")
                msg_bytes += chunk
            
            return msg_bytes.decode('utf-8')
        except socket.timeout:
            raise TimeoutError("Timeout waiting for relay response")
    
    # =====================================================
    # Phase 1: Registration
    # =====================================================
    
    def register(self) -> bool:
        """
        Register with relay server
        Sends: { ClientID, ClientPubKey, Timestamp, Signature_Client }
        """
        print(f"\n[{self.client_id}] === Phase 1: Registration ===")
        
        if not self.is_connected:
            print(f"[{self.client_id}] ✗ Not connected to relay")
            return False
        
        try:
            # Generate RSA keypair
            print(f"[{self.client_id}] Generating RSA keypair...")
            self.private_key_pem, self.public_key_pem = self.crypto.generate_rsa_keypair(
                ProtocolConstants.RSA_KEY_SIZE
            )
            self.crypto.load_private_key(self.private_key_pem)
            print(f"[{self.client_id}] ✓ RSA keypair generated")
            
            # Create registration message
            reg_msg = RegistrationMessage(
                client_id=self.client_id,
                client_pubkey=self.public_key_pem.decode('utf-8'),
                timestamp=time.time()
            )
            
            # Sign the message
            signable_data = reg_msg.get_signable_data()
            reg_msg.signature = self.crypto.sign_data(signable_data)
            print(f"[{self.client_id}] ✓ Created and signed registration message")
            # DEBUG: print registration message contents for inspection
            try:
                print(f"DEBUG: REG_MSG_JSON: {reg_msg.to_json()}")
            except Exception:
                pass
            
            # Send registration
            self.send_message(reg_msg.to_json())
            print(f"[{self.client_id}] → Sent registration to relay")
            
            # Wait for acknowledgment
            response_json = self.receive_message(timeout=ProtocolConstants.REGISTRATION_TIMEOUT)
            response = parse_message(response_json)
            
            if isinstance(response, RegistrationAck):
                if response.status == "success":
                    self.is_registered = True
                    print(f"[{self.client_id}] ✓ Registration successful!")
                    return True
                else:
                    print(f"[{self.client_id}] ✗ Registration failed: {response.message}")
                    return False
            else:
                print(f"[{self.client_id}] ✗ Unexpected response type: {type(response)}")
                return False
                
        except Exception as e:
            print(f"[{self.client_id}] ✗ Registration error: {e}")
            return False
    
    # =====================================================
    # Phase 2: Authentication
    # =====================================================
    
    def authenticate(self, relay_public_key_pem: bytes) -> bool:
        """
        Authenticate with relay using challenge-response
        
        a) Client encrypts nonce with relay's public key: M1 = E_PR(N_C)
        b) Relay decrypts, signs nonce and returns: M2 = Sign_SK(N_C)
        c) Client verifies signed nonce
        
        Args:
            relay_public_key_pem: Relay's public key in PEM format
        """
        print(f"\n[{self.client_id}] === Phase 2: Authentication ===")
        
        if not self.is_registered:
            print(f"[{self.client_id}] ✗ Must register before authenticating")
            return False
        
        self.relay_public_key_pem = relay_public_key_pem
        
        try:
            # Generate random nonce
            nonce = self.crypto.generate_nonce(ProtocolConstants.NONCE_SIZE)
            print(f"[{self.client_id}] Generated challenge nonce")
            # DEBUG: print nonce (base64)
            try:
                print(f"DEBUG: NONCE_RAW: {nonce}")
            except Exception:
                pass
            
            # Encrypt nonce with relay's public key
            encrypted_nonce = self.crypto.encrypt_with_public_key(
                relay_public_key_pem,
                nonce.encode('utf-8')
            )
            print(f"[{self.client_id}] ✓ Encrypted nonce with relay's public key")
            # DEBUG: print encrypted nonce and a short preview of relay public key
            try:
                print(f"DEBUG: ENCRYPTED_NONCE: {encrypted_nonce}")
                pem_lines = relay_public_key_pem.decode('utf-8').splitlines()
                head = '\n'.join(pem_lines[:3])
                tail = '\n'.join(pem_lines[-3:])
                print(f"DEBUG: RELAY_PUBKEY_PEM_HEAD:\n{head}")
                print(f"DEBUG: RELAY_PUBKEY_PEM_TAIL:\n{tail}")
            except Exception:
                pass
            
            # Create and send auth challenge
            auth_challenge = AuthChallenge(
                client_id=self.client_id,
                encrypted_nonce=encrypted_nonce
            )
            
            self.send_message(auth_challenge.to_json())
            print(f"[{self.client_id}] → Sent authentication challenge to relay")
            
            # Wait for relay's signed response
            response_json = self.receive_message(timeout=ProtocolConstants.AUTH_TIMEOUT)
            # DEBUG: print raw response JSON from relay
            try:
                print(f"DEBUG: AUTH_RESPONSE_JSON: {response_json}")
            except Exception:
                pass
            response = parse_message(response_json)
            
            if not isinstance(response, AuthResponse):
                print(f"[{self.client_id}] ✗ Unexpected response type: {type(response)}")
                return False
            
            print(f"[{self.client_id}] ← Received signed nonce from relay")
            
            # Verify relay's signature on the nonce
            is_valid = self.crypto.verify_signature(
                relay_public_key_pem,
                nonce,
                response.signed_nonce
            )
            
            if is_valid:
                self.is_authenticated = True
                print(f"[{self.client_id}] ✓ Relay authenticated successfully!")
                
                # Send verification confirmation
                verify_msg = AuthVerify(
                    client_id=self.client_id,
                    status="success"
                )
                self.send_message(verify_msg.to_json())
                print(f"[{self.client_id}] → Sent authentication confirmation")
                
                return True
            else:
                print(f"[{self.client_id}] ✗ Relay signature verification FAILED!")
                
                # Send verification failure
                verify_msg = AuthVerify(
                    client_id=self.client_id,
                    status="failed"
                )
                self.send_message(verify_msg.to_json())
                
                return False
                
        except Exception as e:
            print(f"[{self.client_id}] ✗ Authentication error: {e}")
            return False
    
    # =====================================================
    # Helper Methods
    # =====================================================
    
    def get_public_key(self) -> str:
        """Get client's public key as string"""
        if self.public_key_pem:
            return self.public_key_pem.decode('utf-8')
        return ""
    
    def is_ready(self) -> bool:
        """Check if client is ready to establish sessions"""
        return self.is_connected and self.is_registered and self.is_authenticated
    
    def get_status(self) -> dict:
        """Get client status"""
        return {
            "client_id": self.client_id,
            "connected": self.is_connected,
            "registered": self.is_registered,
            "authenticated": self.is_authenticated,
            "ready": self.is_ready()
        }   