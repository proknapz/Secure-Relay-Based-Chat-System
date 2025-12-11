"""
relay_server.py - Secure Chat Relay Server Implementation

Relay server responsibilities:
- Phase 1: Register clients and store their public keys
- Phase 2: Authenticate clients via challenge-response
- Phase 3: Forward session setup messages between clients
- Phase 4: Route encrypted messages between clients

The relay is UNTRUSTED - it cannot read message contents.
"""

import socket
import threading
import time
import json
from typing import Dict, Optional, Tuple

from client.crypto_handler import CryptoHandler
from common.protocol import (
    RegistrationMessage, RegistrationAck,
    AuthChallenge, AuthResponse, AuthVerify,
    SessionRequest, SessionResponse,
    SessionEstablished,
    EncryptedMessage, MessageAck,
    MessageType, ProtocolConstants,
    parse_message, create_error
)


class ClientConnection:
    """Represents a connected client"""
    def __init__(self, socket: socket.socket, address: Tuple[str, int]):
        self.socket = socket
        self.address = address
        self.client_id: Optional[str] = None
        self.public_key_pem: Optional[str] = None
        self.is_authenticated = False
        self.lock = threading.Lock()


class RelayServer:
    """
    Relay server that forwards messages between clients.
    Does NOT have access to message content (end-to-end encryption).
    """
    
    def __init__(self, host: str = "localhost", port: int = 5000):
        self.host = host
        self.port = port
        self.crypto = CryptoHandler()
        
        # Server state
        self.running = False
        self.server_socket: Optional[socket.socket] = None
        
        # Generate relay's own RSA keypair for authentication
        print("[Relay] Generating RSA keypair...")
        self.private_key_pem, self.public_key_pem = self.crypto.generate_rsa_keypair(
            ProtocolConstants.RSA_KEY_SIZE
        )
        self.crypto.load_private_key(self.private_key_pem)
        print("[Relay] ✓ RSA keypair generated")
        
        # Client registry: ClientID -> (PublicKey, LastSeen)
        self.registered_clients: Dict[str, Tuple[str, float]] = {}
        
        # Active connections: ClientID -> ClientConnection
        self.active_connections: Dict[str, ClientConnection] = {}

        # Active sessions: SessionID -> (participant_a, participant_b)
        self.sessions: Dict[str, Tuple[str, str]] = {}
        # Debug: forward counts for (session_id, seq_no)
        self._forward_counts: Dict[Tuple[str, int], int] = {}
        
        # Thread-safe access
        self.registry_lock = threading.Lock()
        self.connections_lock = threading.Lock()
        
        print(f"[Relay] Initialized on {host}:{port}")
    
    # =====================================================
    # Server Lifecycle
    # =====================================================
    
    def start(self):
        """Start the relay server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            
            print(f"[Relay] ✓ Server listening on {self.host}:{self.port}")
            print(f"[Relay] Relay public key:\n{self.public_key_pem.decode('utf-8')}")
            print("[Relay] Waiting for clients...\n")
            
            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    print(f"[Relay] New connection from {address}")
                    
                    # Handle each client in a separate thread
                    client_conn = ClientConnection(client_socket, address)
                    thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_conn,),
                        daemon=True
                    )
                    thread.start()
                    
                except KeyboardInterrupt:
                    print("\n[Relay] Shutting down...")
                    break
                except Exception as e:
                    if self.running:
                        print(f"[Relay] Error accepting connection: {e}")
        
        finally:
            self.stop()
    
    def stop(self):
        """Stop the relay server"""
        self.running = False
        
        # Close all client connections
        with self.connections_lock:
            for client_id, conn in self.active_connections.items():
                try:
                    conn.socket.close()
                except:
                    pass
            self.active_connections.clear()
        
        # Close server socket
        if self.server_socket:
            self.server_socket.close()
        
        print("[Relay] Server stopped")
    
    # =====================================================
    # Client Handler
    # =====================================================
    
    def handle_client(self, conn: ClientConnection):
        """Handle a client connection"""
        try:
            while self.running:
                # Receive message
                message_json = self.receive_message(conn.socket)
                if not message_json:
                    break
                
                # Parse message
                try:
                    message = parse_message(message_json)
                except Exception as e:
                    print(f"[Relay] Error parsing message: {e}")
                    error = create_error("PARSE_ERROR", str(e))
                    self.send_message(conn.socket, error.to_json())
                    continue
                
                # Route message based on type
                if isinstance(message, RegistrationMessage):
                    self.handle_registration(conn, message)
                
                elif isinstance(message, AuthChallenge):
                    self.handle_auth_challenge(conn, message)
                
                elif isinstance(message, AuthVerify):
                    self.handle_auth_verify(conn, message)
                
                elif isinstance(message, SessionRequest):
                    self.handle_session_request(conn, message)
                
                elif isinstance(message, SessionResponse):
                    self.handle_session_response(conn, message)
                
                elif isinstance(message, EncryptedMessage):
                    self.handle_encrypted_message(conn, message)
                
                else:
                    print(f"[Relay] Unknown message type: {type(message)}")
        
        except Exception as e:
            print(f"[Relay] Error handling client {conn.address}: {e}")
        
        finally:
            self.cleanup_client(conn)
    
    # =====================================================
    # Phase 1: Registration
    # =====================================================
    
    def handle_registration(self, conn: ClientConnection, msg: RegistrationMessage):
        """
        Handle client registration
        Verifies signature and stores client's public key
        """
        print(f"[Relay] Registration request from {msg.client_id}")
        # DEBUG: print received registration message and public key preview
        try:
            print(f"DEBUG: RECV_REG_MSG: {msg.to_json()}")
            pem_lines = msg.client_pubkey.splitlines()
            head = '\n'.join(pem_lines[:3])
            tail = '\n'.join(pem_lines[-3:])
            print(f"DEBUG: RECV_CLIENT_PUBKEY_HEAD:\n{head}")
            print(f"DEBUG: RECV_CLIENT_PUBKEY_TAIL:\n{tail}")
        except Exception:
            pass
        
        try:
            # Verify timestamp (replay protection)
            current_time = time.time()
            time_diff = abs(current_time - msg.timestamp)
            
            if time_diff > ProtocolConstants.MAX_TIMESTAMP_DRIFT:
                print(f"[Relay] ✗ Registration rejected: timestamp too old ({time_diff}s)")
                ack = RegistrationAck(
                    client_id=msg.client_id,
                    status="error",
                    message="Timestamp out of acceptable range"
                )
                self.send_message(conn.socket, ack.to_json())
                return
            
            # Verify signature
            public_key_bytes = msg.client_pubkey.encode('utf-8')
            signable_data = msg.get_signable_data()
            
            is_valid = self.crypto.verify_signature(
                public_key_bytes,
                signable_data,
                msg.signature
            )
            
            if not is_valid:
                print(f"[Relay] ✗ Registration rejected: invalid signature")
                ack = RegistrationAck(
                    client_id=msg.client_id,
                    status="error",
                    message="Invalid signature"
                )
                self.send_message(conn.socket, ack.to_json())
                return
            
            # Store client registration
            with self.registry_lock:
                self.registered_clients[msg.client_id] = (msg.client_pubkey, current_time)
            
            # Update connection
            conn.client_id = msg.client_id
            conn.public_key_pem = msg.client_pubkey
            
            with self.connections_lock:
                self.active_connections[msg.client_id] = conn
            
            print(f"[Relay] ✓ {msg.client_id} registered successfully")
            
            # Send acknowledgment
            ack = RegistrationAck(
                client_id=msg.client_id,
                status="success",
                message="Registration successful"
            )
            self.send_message(conn.socket, ack.to_json())
            
        except Exception as e:
            print(f"[Relay] Error during registration: {e}")
            ack = RegistrationAck(
                client_id=msg.client_id,
                status="error",
                message=f"Registration error: {str(e)}"
            )
            self.send_message(conn.socket, ack.to_json())
    
    # =====================================================
    # Phase 2: Authentication
    # =====================================================
    
    def handle_auth_challenge(self, conn: ClientConnection, msg: AuthChallenge):
        """
        Handle authentication challenge from client
        
        a) Client sends: M1 = E_PR(N_C) - encrypted nonce
        b) Relay decrypts nonce: N_C = D_SK(M1)
        c) Relay signs nonce: M2 = Sign_SK(N_C)
        d) Relay returns signed nonce
        """
        print(f"[Relay] Authentication challenge from {msg.client_id}")
        # DEBUG: show incoming auth challenge contents
        try:
            print(f"DEBUG: RECV_AUTH_CHALLENGE_JSON: {json.dumps(msg.to_dict())}")
            print(f"DEBUG: RECV_AUTH_CLIENT_ID: {msg.client_id}")
            print(f"DEBUG: RECV_AUTH_ENCRYPTED_NONCE: {msg.encrypted_nonce}")
        except Exception:
            pass
        
        try:
            # Verify client is registered
            if msg.client_id not in self.registered_clients:
                print(f"[Relay] ✗ Authentication rejected: client not registered")
                error = create_error("NOT_REGISTERED", "Client must register first")
                self.send_message(conn.socket, error.to_json())
                return
            
            # Decrypt the nonce with relay's private key
            nonce = self.crypto.decrypt_with_private_key(msg.encrypted_nonce)
            print(f"[Relay] ✓ Decrypted challenge nonce")
            # DEBUG: print decrypted nonce
            try:
                print(f"DEBUG: DECRYPTED_NONCE: {nonce.decode('utf-8')}")
            except Exception:
                pass
            
            # Sign the nonce with relay's private key
            signed_nonce = self.crypto.sign_data(nonce.decode('utf-8'))
            print(f"[Relay] ✓ Signed nonce")
            
            # Send signed nonce back to client
            response = AuthResponse(signed_nonce=signed_nonce)
            # DEBUG: print signed nonce being sent
            try:
                print(f"DEBUG: SIGNED_NONCE: {signed_nonce}")
                print(f"DEBUG: AUTH_RESPONSE_JSON: {response.to_json()}")
            except Exception:
                pass
            self.send_message(conn.socket, response.to_json())
            print(f"[Relay] → Sent signed nonce to {msg.client_id}")
            
        except Exception as e:
            print(f"[Relay] Error during authentication: {e}")
            error = create_error("AUTH_ERROR", str(e))
            self.send_message(conn.socket, error.to_json())
    
    def handle_auth_verify(self, conn: ClientConnection, msg: AuthVerify):
        """Handle authentication verification from client"""
        if msg.status == "success":
            conn.is_authenticated = True
            print(f"[Relay] ✓ {msg.client_id} authenticated successfully")
        else:
            print(f"[Relay] ✗ {msg.client_id} authentication failed")
    
    # =====================================================
    # Phase 3: Session Setup (Forwarding)
    # =====================================================
    
    def handle_session_request(self, conn: ClientConnection, msg: SessionRequest):
        """
        Forward session request from sender to receiver
        Relay just forwards - it cannot read the DH values or derive keys
        """
        print(f"[Relay] Session request: {msg.sender_id} → {msg.receiver_id}")
        # DEBUG: show incoming session request JSON and a short preview of DH/nonce
        try:
            print(f"DEBUG: RECV_SESSION_REQUEST_JSON: {json.dumps(msg.to_dict())}")
            print(f"DEBUG: RECV_SESSION_SENDER_PUBKEY:\n{msg.sender_pubkey}")
            print(f"DEBUG: RECV_SESSION_EPHEMERAL_DH: {msg.ephemeral_dh_public}")
            print(f"DEBUG: RECV_SESSION_NONCE_A: {msg.nonce_a}")
        except Exception:
            pass
        
        if not conn.is_authenticated:
            print(f"[Relay] ✗ Client not authenticated")
            error = create_error("NOT_AUTHENTICATED", "Must authenticate first")
            self.send_message(conn.socket, error.to_json())
            return
            
        # Verify sender identity
        if msg.sender_id != conn.client_id:
            print(f"[Relay] ✗ Client {conn.client_id} attempting to spoof {msg.sender_id}")
            error = create_error("IDENTITY_MISMATCH", "Sender ID does not match authenticated client")
            self.send_message(conn.socket, error.to_json())
            return

        if msg.sender_id == msg.receiver_id:
            print(f"[Relay] ✗ Client attempting to create session with self")
            error = create_error("INVALID_RECEIVER", "Cannot create session with yourself")
            self.send_message(conn.socket, error.to_json())
            return
        
        # Find receiver's connection
        with self.connections_lock:
            receiver_conn = self.active_connections.get(msg.receiver_id)
        
        if not receiver_conn:
            print(f"[Relay] ✗ Receiver {msg.receiver_id} not connected")
            error = create_error("RECEIVER_OFFLINE", f"{msg.receiver_id} is not online")
            self.send_message(conn.socket, error.to_json())
            return
        
        # Forward the request
        self.send_message(receiver_conn.socket, json.dumps(msg.to_dict()))
        print(f"[Relay] → Forwarded session request to {msg.receiver_id}")
    
    def handle_session_response(self, conn: ClientConnection, msg: SessionResponse):
        """Forward session response from receiver back to sender"""
        print(f"[Relay] Session response: {msg.sender_id} → {msg.receiver_id}")
        # DEBUG: show incoming session response JSON and previews
        try:
            print(f"DEBUG: RECV_SESSION_RESPONSE_JSON: {json.dumps(msg.to_dict())}")
            print(f"DEBUG: RECV_SESSION_RESPONSE_SENDER_PUBKEY:\n{msg.sender_pubkey}")
            print(f"DEBUG: RECV_SESSION_RESPONSE_EPHEMERAL_DH: {msg.ephemeral_dh_public}")
            print(f"DEBUG: RECV_SESSION_RESPONSE_NONCES: nonce_a={msg.nonce_a}, nonce_b={msg.nonce_b}")
        except Exception:
            pass
        
        if not conn.is_authenticated:
            print(f"[Relay] ✗ Client not authenticated")
            return
            
        # Verify sender identity
        if msg.sender_id != conn.client_id:
            print(f"[Relay] ✗ Client {conn.client_id} attempting to spoof {msg.sender_id}")
            return
        
        # Find sender's connection
        with self.connections_lock:
            sender_conn = self.active_connections.get(msg.receiver_id)
        
        if not sender_conn:
            print(f"[Relay] ✗ Sender {msg.receiver_id} not connected")
            return
        
        # Forward the response
        self.send_message(sender_conn.socket, json.dumps(msg.to_dict()))
        print(f"[Relay] → Forwarded session response to {msg.receiver_id}")
        # Create a session and notify both participants
        try:
            # Generate a simple session id
            session_id = f"{msg.receiver_id}_{msg.sender_id}_{int(time.time())}"
            self.sessions[session_id] = (msg.receiver_id, msg.sender_id)

            # Notify both participants that the session is established
            established = SessionEstablished(
                session_id=session_id,
                participant_a=msg.receiver_id,
                participant_b=msg.sender_id
            )

            # Send to original sender (msg.receiver_id)
            if sender_conn:
                self.send_message(sender_conn.socket, established.to_json())

            # Send to responder (conn) -- conn is the responder's connection
            self.send_message(conn.socket, established.to_json())
            print(f"[Relay] → Session {session_id} established between {msg.receiver_id} and {msg.sender_id}")
        except Exception as e:
            print(f"[Relay] Error creating session: {e}")
    
    # =====================================================
    # Phase 4: Message Routing
    # =====================================================
    
    def handle_encrypted_message(self, conn: ClientConnection, msg: EncryptedMessage):
        """
        Route encrypted message to recipient
        Relay cannot decrypt - messages are end-to-end encrypted
        """
        # Use connection info for sender identity (do not trust on-wire sender fields)
        sender_id = conn.client_id if conn.client_id else "unknown"
        print(f"[Relay] Encrypted message from {sender_id} (session: {msg.session_id}, seq: {msg.seq_no})")
        
        if not conn.is_authenticated:
            print(f"[Relay] ✗ Client not authenticated")
            return
        
        # Note: In a real implementation, you'd need to track which clients
        # are in which session. For now, we'll need to add session tracking.
        # This is a simplified version that just forwards based on sender_id
        
        print(f"[Relay] → Forwarding encrypted message (relay cannot read content)")

        # Route based on session mapping
        try:
            participants = self.sessions.get(msg.session_id)
            if not participants:
                print(f"[Relay] ✗ Unknown session: {msg.session_id}")
                return

            # Determine recipient using authenticated connection identity
            a, b = participants
            sender = conn.client_id
            recipient_id = b if a == sender else a

            with self.connections_lock:
                recipient_conn = self.active_connections.get(recipient_id)

            if not recipient_conn:
                print(f"[Relay] ✗ Recipient {recipient_id} not connected for session {msg.session_id}")
                return

            # Forward encrypted message JSON
            self.send_message(recipient_conn.socket, msg.to_json())
            # Debugging: count forwards per session+seq
            key = (msg.session_id, msg.seq_no)
            prev = self._forward_counts.get(key, 0) + 1
            self._forward_counts[key] = prev
            print(f"[Relay] → Forwarded encrypted message to {recipient_id} (forward_count={prev})")
        except Exception as e:
            print(f"[Relay] Error forwarding encrypted message: {e}")
    
    # =====================================================
    # Network Utilities
    # =====================================================
    
    def send_message(self, sock: socket.socket, message: str):
        """Send message with length prefix"""
        try:
            msg_bytes = message.encode('utf-8')
            length_prefix = len(msg_bytes).to_bytes(4, byteorder='big')
            sock.sendall(length_prefix + msg_bytes)
        except Exception as e:
            print(f"[Relay] Error sending message: {e}")
    
    def receive_message(self, sock: socket.socket) -> Optional[str]:
        """Receive message with length prefix"""
        try:
            # Read length prefix
            length_bytes = sock.recv(4)
            if not length_bytes:
                return None
            
            msg_length = int.from_bytes(length_bytes, byteorder='big')
            
            # Read message
            msg_bytes = b""
            while len(msg_bytes) < msg_length:
                chunk = sock.recv(msg_length - len(msg_bytes))
                if not chunk:
                    return None
                msg_bytes += chunk
            
            return msg_bytes.decode('utf-8')
        except Exception as e:
            print(f"[Relay] Error receiving message: {e}")
            return None
    
    # =====================================================
    # Cleanup
    # =====================================================
    
    def cleanup_client(self, conn: ClientConnection):
        """Clean up disconnected client"""
        if conn.client_id:
            print(f"[Relay] Client {conn.client_id} disconnected")
            with self.connections_lock:
                if conn.client_id in self.active_connections:
                    del self.active_connections[conn.client_id]
        else:
            print(f"[Relay] Client {conn.address} disconnected (never registered)")
        
        try:
            conn.socket.close()
        except:
            pass
    
    # =====================================================
    # Utilities
    # =====================================================
    
    def get_registered_clients(self) -> list:
        """Get list of registered client IDs"""
        with self.registry_lock:
            return list(self.registered_clients.keys())
    
    def get_active_clients(self) -> list:
        """Get list of currently connected client IDs"""
        with self.connections_lock:
            return list(self.active_connections.keys())
    
    def get_relay_public_key(self) -> str:
        """Get relay's public key for distribution to clients"""
        return self.public_key_pem.decode('utf-8')