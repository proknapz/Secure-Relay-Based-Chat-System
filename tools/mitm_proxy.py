"""
mitm_proxy.py - Man-in-the-Middle Proxy for Security Demo

This script acts as a proxy between a Client and the Relay Server.
It allows you to:
1. Inspect traffic (proving encryption)
2. Replay messages (proving replay protection)
3. Tamper with messages (proving integrity checks)

Usage:
    python tools/mitm_proxy.py --listen-port 5001 --relay-port 5000
"""

import socket
import threading
import sys
import os
import json
import time
import argparse

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.protocol import MessageType
from config import Config

class MitmProxy:
    def __init__(self, listen_host, listen_port, relay_host, relay_port):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.relay_host = relay_host
        self.relay_port = relay_port
        
        self.client_socket = None
        self.relay_socket = None
        self.running = False
        
        # Captured data
        self.last_encrypted_msg_raw = None
        self.last_encrypted_msg_json = None
        
        # Track what we've sent to avoid interference
        self.attack_counter = 0
        
        self.lock = threading.Lock()

    def start(self):
        # Setup listener
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.listen_host, self.listen_port))
        self.server_socket.listen(1)
        
        print(f"[Proxy] Listening on {self.listen_host}:{self.listen_port}")
        print(f"[Proxy] Forwarding to {self.relay_host}:{self.relay_port}")
        print("[Proxy] Waiting for client connection...")
        
        try:
            while True:
                # Accept a client connection
                self.client_socket, addr = self.server_socket.accept()
                print(f"[Proxy] Client connected from {addr}")

                # Try to connect to the relay with retries so proxy can start before relay
                relay_connected = False
                max_attempts = 5
                attempt = 0
                last_exc = None
                while attempt < max_attempts:
                    try:
                        self.relay_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        self.relay_socket.settimeout(3.0)
                        self.relay_socket.connect((self.relay_host, self.relay_port))
                        relay_connected = True
                        break
                    except Exception as e:
                        last_exc = e
                        attempt += 1
                        print(f"[Proxy] Attempt {attempt}/{max_attempts} - cannot connect to relay {self.relay_host}:{self.relay_port}: {e}")
                        time.sleep(1.0)

                if not relay_connected:
                    print(f"[Proxy] ✗ Failed to connect to relay after {max_attempts} attempts. Closing client connection.")
                    try:
                        # Informative message to client (optional) then close
                        self.client_socket.close()
                    except Exception:
                        pass
                    # Clean up relay_socket if partially created
                    try:
                        if self.relay_socket:
                            self.relay_socket.close()
                    except Exception:
                        pass
                    # Continue listening for next client
                    continue

                # Connected to relay successfully
                print(f"[Proxy] Connected to relay {self.relay_host}:{self.relay_port}")
                # Make sockets blocking again
                try:
                    self.relay_socket.settimeout(None)
                except Exception:
                    pass

                self.running = True

                # Start forwarding threads
                t1 = threading.Thread(target=self.forward_client_to_relay)
                t2 = threading.Thread(target=self.forward_relay_to_client)
                t1.daemon = True
                t2.daemon = True
                t1.start()
                t2.start()

                # Command loop (blocks until user quits or connection breaks)
                try:
                    # Print the prompt after client connects and before command loop starts
                    print("\nProxy> ", end="", flush=True)
                    self.command_loop()
                finally:
                    # Clean up after command loop exits
                    self.running = False
                    try:
                        if self.client_socket:
                            self.client_socket.close()
                    except Exception:
                        pass
                    try:
                        if self.relay_socket:
                            self.relay_socket.close()
                    except Exception:
                        pass

        except KeyboardInterrupt:
            print("\n[Proxy] Stopping...")
        except Exception as e:
            print(f"[Proxy] Error: {e}")
        finally:
            self.running = False
            try:
                if self.client_socket: self.client_socket.close()
            except Exception:
                pass
            try:
                if self.relay_socket: self.relay_socket.close()
            except Exception:
                pass
            try:
                if self.server_socket: self.server_socket.close()
            except Exception:
                pass

    def receive_framed_message(self, sock):
        """Read a length-prefixed message from socket"""
        try:
            length_bytes = sock.recv(4)
            if not length_bytes:
                return None
            
            msg_length = int.from_bytes(length_bytes, byteorder='big')
            
            msg_bytes = b""
            while len(msg_bytes) < msg_length:
                chunk = sock.recv(msg_length - len(msg_bytes))
                if not chunk:
                    return None
                msg_bytes += chunk
            
            return length_bytes + msg_bytes
        except:
            return None

    def forward_client_to_relay(self):
        while self.running:
            try:
                # Read full message
                raw_msg = self.receive_framed_message(self.client_socket)
                if not raw_msg:
                    print("[Proxy] Client disconnected")
                    self.running = False
                    break
                
                # Parse for inspection
                try:
                    # Skip 4 bytes length prefix
                    payload = raw_msg[4:]
                    msg_json = json.loads(payload.decode('utf-8'))
                    msg_type = msg_json.get('msg_type')
                    
                    if msg_type == MessageType.ENCRYPTED_MESSAGE.value:
                        with self.lock:
                            self.last_encrypted_msg_raw = raw_msg
                            self.last_encrypted_msg_json = msg_json
                        print(f"[Proxy] >> Captured ENCRYPTED_MESSAGE (Seq: {msg_json.get('seq_no')})")
                    else:
                        print(f"[Proxy] >> Forwarding {msg_type}")
                        
                except Exception as e:
                    print(f"[Proxy] Error parsing message: {e}")

                # Forward to relay
                self.relay_socket.sendall(raw_msg)
                
            except Exception as e:
                if self.running:
                    print(f"[Proxy] Forwarding error (C->R): {e}")
                break

    def forward_relay_to_client(self):
        while self.running:
            try:
                # Read full message
                raw_msg = self.receive_framed_message(self.relay_socket)
                if not raw_msg:
                    print("[Proxy] Relay disconnected")
                    self.running = False
                    break
                
                # Just forward
                self.client_socket.sendall(raw_msg)
                
            except Exception as e:
                if self.running:
                    print(f"[Proxy] Forwarding error (R->C): {e}")
                break

    def command_loop(self):
        """Non-blocking command loop that allows message forwarding to continue"""
        def print_help():
            print("\nCommands:")
            print("  s - Show last captured message (prove encryption)")
            print("  r - Replay last captured message (attack)")  
            print("  t - Tamper and replay last message (attack)")
            print("  c - Clear captured message (to capture a new one)")
            print("  h - Show this help message")
            print("  q - Quit")
            print("\nType commands and press Enter. Normal message forwarding continues in background.")

        print_help()
        
        # Use a separate thread for input to avoid blocking message forwarding
        input_thread = threading.Thread(target=self._input_thread, daemon=True)
        input_thread.start()
        
        # Main loop just waits and handles shutdown
        try:
            while self.running:
                time.sleep(0.1)
        except KeyboardInterrupt:
            print("\n[Proxy] Ctrl+C detected, shutting down...")
            self.running = False
    
    def _input_thread(self):
        """Separate thread to handle user input without blocking forwarding"""
        while self.running:
            try:
                print("\nProxy> ", end="", flush=True)
                cmd = input().strip().lower()
                
                if cmd == 'q':
                    self.running = False
                    break
                elif cmd in ['s', 'r', 't', 'c', 'h']:
                    self.process_command(cmd)
                elif cmd == '':
                    continue  # Just pressed enter
                else:
                    print(f"Unknown command: {cmd}. Type 'h' for help.")
                    
            except EOFError:
                # Input stream closed
                break
            except Exception as e:
                print(f"[Proxy] Input error: {e}")
                time.sleep(0.1)
    
    def process_command(self, cmd):
        """Process a single character command"""
        try:
            if cmd == 'q':
                self.running = False
            elif cmd == 'h':
                print("\nCommands:")
                print("  s - Show last captured message (prove encryption)")
                print("  r - Replay last captured message (attack)")
                print("  t - Tamper and replay last message (attack)")
                print("  c - Clear captured message (to capture a new one)")
                print("  h - Show this help message")
                print("  q - Quit")
                
            elif cmd == 's':
                with self.lock:
                    if self.last_encrypted_msg_json:
                        print("\n[Last Captured Message]")
                        print(json.dumps(self.last_encrypted_msg_json, indent=2))
                        print("\n[Analysis]")
                        print(f"Session ID: {self.last_encrypted_msg_json.get('session_id')}")
                        print(f"Ciphertext: {self.last_encrypted_msg_json.get('ciphertext')[:30]}...")
                        print(f"HMAC:       {self.last_encrypted_msg_json.get('hmac')}")
                        print("Status:     ENCRYPTED (Content not visible)")
                    else:
                        print("\n[Proxy] No encrypted message captured yet.")

            elif cmd == 'r':
                with self.lock:
                    if not self.last_encrypted_msg_raw:
                        print("\n[Proxy] No message to replay.")
                    else:
                        seq = self.last_encrypted_msg_json.get('seq_no')
                        print(f"\n[Proxy] Replaying message seq {seq}...")
                        try:
                            # Send the raw framed message
                            self.relay_socket.sendall(self.last_encrypted_msg_raw)
                            print("[Proxy] Replay sent!")
                            # Log the actual JSON that was sent for auditing
                            try:
                                print("\n[Proxy] [REPLAYED MESSAGE JSON]")
                                print(json.dumps(self.last_encrypted_msg_json, indent=2))
                            except Exception:
                                print("[Proxy] (Unable to pretty-print replayed JSON)")
                        except Exception as e:
                            print(f"[Proxy] Send error: {e}")

            elif cmd == 't':
                with self.lock:
                    if self.last_encrypted_msg_json:
                        print(f"\n[Proxy] Tampering with message...")
                        msg = self.last_encrypted_msg_json.copy()
                        
                        # Tamper with ciphertext - change it enough to fail HMAC
                        orig_cipher = msg['ciphertext']
                        if len(orig_cipher) > 0:
                            # Flip multiple characters to ensure HMAC fails
                            tampered_cipher = orig_cipher[:-3] + ('XYZ' if orig_cipher[-3:] != 'XYZ' else 'ABC')
                            msg['ciphertext'] = tampered_cipher
                            print(f"[Proxy] Changed ciphertext: ...{orig_cipher[-5:]} -> ...{tampered_cipher[-5:]}")
                        
                        # Use a higher sequence number to bypass replay detection and show HMAC failure
                        original_seq = msg['seq_no']
                        self.attack_counter += 1
                        msg['seq_no'] = original_seq + 10 + self.attack_counter  # Use sequence that's definitely higher
                        print(f"[Proxy] Changed seq_no: {original_seq} -> {msg['seq_no']} (to bypass replay detection and test HMAC)")
                        
                        # Re-serialize
                        msg_bytes = json.dumps(msg).encode('utf-8')
                        length_prefix = len(msg_bytes).to_bytes(4, byteorder='big')
                        
                        try:
                            self.relay_socket.sendall(length_prefix + msg_bytes)
                            print("[Proxy] Tampered message sent!")
                            # Log the actual tampered JSON that was sent for auditing
                            try:
                                print("\n[Proxy] [TAMPERED MESSAGE JSON]")
                                print(json.dumps(msg, indent=2))
                            except Exception:
                                print("[Proxy] (Unable to pretty-print tampered JSON)")
                        except Exception as e:
                            print(f"[Proxy] Send error: {e}")
                    else:
                        print("\n[Proxy] No message to tamper.")
            
            elif cmd == 'c':
                with self.lock:
                    self.last_encrypted_msg_raw = None
                    self.last_encrypted_msg_json = None
                    print("\n[Proxy] Captured message cleared. Send a new message to capture.")
                    
        except Exception as e:
            print(f"\n[Proxy] Command processing error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Secure Chat MITM Proxy')
    parser.add_argument('--listen-port', type=int, default=5001, help='Port to listen on')
    parser.add_argument('--relay-host', default=Config.RELAY_HOST, help='Relay host')
    parser.add_argument('--relay-port', type=int, default=Config.RELAY_PORT, help='Relay port')
    args = parser.parse_args()
    
    proxy = MitmProxy('localhost', args.listen_port, args.relay_host, args.relay_port)
    proxy.start()
