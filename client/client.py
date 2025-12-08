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
import base64
import threading
from typing import Optional, Tuple, Dict

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

        # Listener & session state
        self.listener_thread: Optional[threading.Thread] = None
        self.listener_running = False
        # session mappings: peer_id -> session_id
        self.sessions: Dict[str, str] = {}
        # inverse mapping: session_id -> peer_id
        self.session_by_id: Dict[str, str] = {}
        # sequence counters per session
        self.seq_counters: Dict[str, int] = {}
        self.incoming_seq_counters: Dict[str, int] = {}
        
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
            try:
                # Shutdown the socket properly first
                self.socket.shutdown(socket.SHUT_RDWR)
                self.socket.close()
            except (socket.error, OSError):
                # Ignore errors if socket is already closed
                pass
            finally:
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
        
        try:
            if timeout is not None:
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
            except (socket.error, OSError) as e:
                if not self.listener_running:
                    # If we're shutting down, convert to timeout
                    raise TimeoutError("Shutdown in progress")
                raise  # Re-raise the original error
        except Exception as e:
            if not self.listener_running:
                # If we're shutting down, convert all errors to timeout
                raise TimeoutError("Shutdown in progress")
            raise  # Re-raise the original error
    
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

    # =====================================================
    # Listener / Session Helpers
    # =====================================================

    def start_listener(self):
        """Start background listener for incoming relay messages"""
        if self.listener_thread and self.listener_thread.is_alive():
            return
        self.listener_running = True
        self.listener_thread = threading.Thread(target=self._listen_loop, daemon=True)
        self.listener_thread.start()

    def stop_listener(self):
        """Stop the listener thread"""
        self.listener_running = False
        if self.listener_thread and self.listener_thread.is_alive():
            try:
                # Set a short timeout on the socket to break out of receive_message
                if self.socket:
                    self.socket.settimeout(0.1)
                # Wait for thread to finish with timeout
                self.listener_thread.join(timeout=1.0)
                if self.listener_thread.is_alive():
                    # If thread is still alive, force socket closure
                    if self.socket:
                        try:
                            self.socket.shutdown(socket.SHUT_RDWR)
                            self.socket.close()
                        except (socket.error, OSError):
                            pass
                    # Wait again for thread to finish
                    self.listener_thread.join(timeout=1.0)
            except Exception:
                pass  # Ignore any errors during cleanup
            finally:
                self.listener_thread = None

    def _listen_loop(self):
        """Loop to receive and handle incoming messages from relay"""
        while self.listener_running:
            # Check if socket is valid
            if not self.socket:
                break
            
            try:
                # Set a reasonable timeout to allow checking listener_running
                self.socket.settimeout(1.0)
                try:
                    msg_json = self.receive_message(timeout=None)
                    if not msg_json:
                        # Connection closed
                        break
                except TimeoutError:
                    # Normal timeout, just continue the loop
                    continue
                except (socket.error, OSError) as e:
                    # Socket error or already closed
                    print(f"[{self.client_id}] Connection closed: {e}")
                    break

                try:
                    message = parse_message(msg_json)
                except Exception as e:
                    print(f"[{self.client_id}] Error parsing incoming message: {e}")
                    continue

                # Handle messages
                from common.protocol import SessionRequest, SessionResponse, SessionEstablished, EncryptedMessage, ErrorMessage

                if isinstance(message, SessionRequest):
                    print(f"[{self.client_id}] ← SessionRequest from {message.sender_id}")
                    
                    # Verify signature
                    try:
                        if not message.sender_pubkey:
                            print(f"[{self.client_id}] ✗ Missing public key in SessionRequest")
                            continue
                            
                        signable_data = message.get_signable_data()
                        is_valid = self.crypto.verify_signature(
                            message.sender_pubkey.encode('utf-8'),
                            signable_data,
                            message.signature
                        )
                        
                        if not is_valid:
                            print(f"[{self.client_id}] ✗ Invalid signature on SessionRequest from {message.sender_id}")
                            continue
                            
                        print(f"[{self.client_id}] ✓ Verified signature from {message.sender_id}")
                    except Exception as e:
                        print(f"[{self.client_id}] ✗ Error verifying signature: {e}")
                        continue
                    
                    # Save peer's DH public value
                    peer_public = self.crypto.base64_to_int(message.ephemeral_dh_public)
                    
                    # Generate our DH keypair
                    private_value, public_value = self.crypto.generate_dh_keypair(
                        self.crypto.dh_prime,
                        self.crypto.dh_generator
                    )
                    self.crypto._dh_private = private_value
                    
                    # Generate and save nonce
                    nonce_b = self.crypto.generate_nonce(16)
                    self._temp_session_data = {
                        'peer_public': peer_public,
                        'nonce_a': message.nonce_a,
                        'nonce_b': nonce_b,
                    }
                    
                    # Send response with our public value
                    response = SessionResponse(
                        sender_id=self.client_id,
                        receiver_id=message.sender_id,
                        nonce_a=message.nonce_a,
                        nonce_b=nonce_b,
                        ephemeral_dh_public=self.crypto.int_to_base64(public_value),
                        signature="",
                        timestamp=time.time(),
                        sender_pubkey=self.get_public_key()
                    )
                    
                    # Sign the response
                    signable_data = response.get_signable_data()
                    response.signature = self.crypto.sign_data(signable_data)
                    
                    self.send_message(response.to_json())
                    print(f"[{self.client_id}] → Sent SessionResponse to {message.sender_id}")

                elif isinstance(message, SessionResponse):
                    print(f"[{self.client_id}] ← SessionResponse from {message.sender_id}")
                    
                    # Verify signature
                    try:
                        if not message.sender_pubkey:
                            print(f"[{self.client_id}] ✗ Missing public key in SessionResponse")
                            continue
                            
                        signable_data = message.get_signable_data()
                        is_valid = self.crypto.verify_signature(
                            message.sender_pubkey.encode('utf-8'),
                            signable_data,
                            message.signature
                        )
                        
                        if not is_valid:
                            print(f"[{self.client_id}] ✗ Invalid signature on SessionResponse from {message.sender_id}")
                            continue
                            
                        print(f"[{self.client_id}] ✓ Verified signature from {message.sender_id}")
                    except Exception as e:
                        print(f"[{self.client_id}] ✗ Error verifying signature: {e}")
                        continue

                    # Save peer's public value for key derivation
                    peer_public = self.crypto.base64_to_int(message.ephemeral_dh_public)
                    self._temp_session_data = {
                        'peer_public': peer_public,
                        'nonce_a': message.nonce_a,
                        'nonce_b': message.nonce_b
                    }

                elif isinstance(message, SessionEstablished):
                    print(f"[{self.client_id}] ← SessionEstablished: {message.session_id} ({message.participant_a} ↔ {message.participant_b})")
                    # Store session mapping
                    peer = message.participant_b if message.participant_a == self.client_id else message.participant_a
                    self.sessions[peer] = message.session_id
                    self.session_by_id[message.session_id] = peer
                    self.seq_counters[message.session_id] = 0
                    self.incoming_seq_counters[message.session_id] = 0
                    
                    try:
                        # Get saved session data
                        if not hasattr(self, '_temp_session_data'):
                            print(f"[{self.client_id}] ✗ No temporary session data found")
                            return
                        session_data = self._temp_session_data
                        
                        # Compute DH shared secret
                        peer_public = session_data['peer_public']
                        shared_secret = self.crypto.compute_dh_shared_secret(
                            self.crypto._dh_private,
                            peer_public,
                            self.crypto.dh_prime
                        )
                        
                        # Create salt from session data
                        salt = self.crypto.hash_data(
                            f"{message.session_id}{session_data['nonce_a']}{session_data['nonce_b']}"
                        )
                        
                        # Derive and store session keys
                        k_enc, k_mac = self.crypto.derive_session_keys(shared_secret, salt)
                        self.crypto._session_keys[message.session_id] = (k_enc, k_mac)
                        print(f"[{self.client_id}] ✓ Session keys established for {message.session_id}")
                        
                        # Clean up temporary data
                        del self._temp_session_data
                    except Exception as e:
                        print(f"[{self.client_id}] ✗ Failed to establish session keys: {e}")

                elif isinstance(message, SessionResponse):
                    print(f"[{self.client_id}] ← SessionResponse from {message.sender_id}")

                elif isinstance(message, EncryptedMessage):
                    try:
                        # Get session keys
                        k_enc, k_mac = self.crypto._session_keys.get(message.session_id, (None, None))
                        if not k_enc or not k_mac:
                            print(f"[{self.client_id}] ✗ No keys for session {message.session_id}")
                            return
                        
                        # Replay protection
                        last_seq = self.incoming_seq_counters.get(message.session_id, 0)
                        if message.seq_no <= last_seq:
                            print(f"[{self.client_id}] ✗ Replay detected! Seq {message.seq_no} <= {last_seq}")
                            return
                        
                        # Verify HMAC first
                        if not self.crypto.verify_hmac(k_mac, message.get_hmac_data(), message.hmac):
                            print(f"[{self.client_id}] ✗ Invalid HMAC for message")
                            return
                            
                        # Decrypt message with sequence number
                        try:
                            plaintext = self.crypto.decrypt_message(message.ciphertext, k_enc, message.seq_no)
                            
                            # Update sequence counter only after successful decryption/verification
                            self.incoming_seq_counters[message.session_id] = message.seq_no
                            
                            print(f"\n[{self.client_id}] ← Message from {message.sender_id}:")
                            print(f"    Content: {plaintext}")
                            print(f"    Status: ✓ MAC verified | Session: {message.session_id} | Sequence: {message.seq_no}")
                            print("\n> ", end="", flush=True)  # Restore prompt
                        except ValueError as e:
                            print(f"\n[{self.client_id}] ✗ Decryption failed: {e}")
                            print("\n> ", end="", flush=True)  # Restore prompt
                    except Exception as e:
                        print(f"[{self.client_id}] ✗ Failed to process encrypted message: {e}")

                elif isinstance(message, ErrorMessage):
                    print(f"[{self.client_id}] ← Error from relay: {message.error_code} - {message.error_message}")

                else:
                    # Generic handling / debug
                    if isinstance(message, ErrorMessage):
                        print(f"[{self.client_id}] ← Error: {message.error_message}")
                    else:
                        print(f"[{self.client_id}] ← Unknown message type: {type(message)}")

            except TimeoutError:
                # continue listening
                continue
            except Exception as e:
                print(f"[{self.client_id}] Listener error: {e}")
                break

        self.listener_running = False

    # =====================================================
    # Session & Messaging API (demo)
    # =====================================================

    def send_session_request(self, receiver_id: str) -> bool:
        """Initiate a session with another client (demo)
        This sends a SessionRequest to the relay which will forward it to the receiver.
        """
        if not self.is_ready():
            print(f"[{self.client_id}] ✗ Not ready to start session")
            return False
            
        if receiver_id == self.client_id:
            print(f"[{self.client_id}] ✗ Cannot create session with yourself")
            return False

        try:
            # Generate DH keypair and nonce
            private_value, public_value = self.crypto.generate_dh_keypair(
                self.crypto.dh_prime, 
                self.crypto.dh_generator
            )
            self.crypto._dh_private = private_value  # Save for later
            nonce_a = self.crypto.generate_nonce(16)

            # Create request
            from common.protocol import SessionRequest
            req = SessionRequest(
                sender_id=self.client_id,
                receiver_id=receiver_id,
                nonce_a=nonce_a,
                ephemeral_dh_public=self.crypto.int_to_base64(public_value),
                signature="",
                timestamp=time.time(),
                sender_pubkey=self.get_public_key()
            )
            
            # Sign the request
            signable_data = req.get_signable_data()
            req.signature = self.crypto.sign_data(signable_data)
            
            self.send_message(req.to_json())
            print(f"[{self.client_id}] → Sent SessionRequest to {receiver_id}")
            return True
        except Exception as e:
            print(f"[{self.client_id}] ✗ Failed to send session request: {e}")
            return False

    def send_encrypted_message(self, peer_id: str, plaintext: str) -> bool:
        """Send an encrypted message to peer via established session"""
        session_id = self.sessions.get(peer_id)
        if not session_id:
            print(f"[{self.client_id}] ✗ No session with {peer_id}. Create a session first.")
            return False

        from common.protocol import EncryptedMessage

        # Get session keys
        if session_id not in self.crypto._session_keys:
            print(f"[{self.client_id}] ✗ No keys for session {session_id}")
            return False
        k_enc, k_mac = self.crypto._session_keys[session_id]

        # Increment sequence number
        seq = self.seq_counters.get(session_id, 0) + 1
        self.seq_counters[session_id] = seq

        # Encrypt message
        ciphertext = self.crypto.encrypt_message(plaintext, k_enc, seq)
        
        # Generate HMAC
        data = f"{session_id}{seq}{ciphertext}"
        mac = self.crypto.compute_hmac(k_mac, data)

        msg = EncryptedMessage(
            session_id=session_id,
            sender_id=self.client_id,
            seq_no=seq,
            ciphertext=ciphertext,
            hmac=mac,
            timestamp=time.time()
        )
        try:
            self.send_message(msg.to_json())
            print(f"[{self.client_id}] → Sent EncryptedMessage to {peer_id} (session {session_id})")
            return True
        except Exception as e:
            print(f"[{self.client_id}] ✗ Failed to send message: {e}")
            return False