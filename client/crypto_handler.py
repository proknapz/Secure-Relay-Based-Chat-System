"""
crypto_handler.py - Cryptographic Operations for Secure Chat

Handles all cryptographic operations:
- RSA key generation, signing, verification, encryption/decryption
- Diffie-Hellman key exchange
- HKDF key derivation
- HMAC generation and verification
- Symmetric encryption (XOR with KDF stream)
"""

import os
import base64
import hashlib
import hmac
from typing import Tuple, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


class CryptoHandler:
    """Handles all cryptographic operations for the secure chat system"""
    
    def __init__(self):
        self.backend = default_backend()
        self.private_key = None
        self.public_key = None
    
    # =====================================================
    # RSA Operations (Phase 1 & 2)
    # =====================================================
    
    def generate_rsa_keypair(self, key_size: int = 2048) -> Tuple[bytes, bytes]:
        """
        Generate RSA key pair for signing and encryption
        
        Returns:
            (private_key_pem, public_key_pem)
        """
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=self.backend
        )
        self.public_key = self.private_key.public_key()
        
        # Serialize to PEM format
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem
    
    def load_private_key(self, private_key_pem: bytes):
        """Load private key from PEM format"""
        self.private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None,
            backend=self.backend
        )
        self.public_key = self.private_key.public_key()
    
    def load_public_key(self, public_key_pem: bytes):
        """Load public key from PEM format (for verifying others' signatures)"""
        return serialization.load_pem_public_key(
            public_key_pem,
            backend=self.backend
        )
    
    def sign_data(self, data: str) -> str:
        """
        Sign data with private key (Phase 1: Registration)
        
        Args:
            data: String data to sign
            
        Returns:
            Base64-encoded signature
        """
        if not self.private_key:
            raise ValueError("Private key not loaded")
        
        signature = self.private_key.sign(
            data.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return base64.b64encode(signature).decode('utf-8')
    
    def verify_signature(self, public_key_pem: bytes, data: str, signature_b64: str) -> bool:
        """
        Verify signature with public key
        
        Args:
            public_key_pem: Public key in PEM format
            data: Original data that was signed
            signature_b64: Base64-encoded signature
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            public_key = self.load_public_key(public_key_pem)
            signature = base64.b64decode(signature_b64)
            
            public_key.verify(
                signature,
                data.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            print(f"Signature verification error: {e}")
            return False
    
    def encrypt_with_public_key(self, public_key_pem: bytes, data: bytes) -> str:
        """
        Encrypt data with RSA public key (Phase 2: Auth Challenge)
        
        Args:
            public_key_pem: Recipient's public key
            data: Data to encrypt (e.g., nonce)
            
        Returns:
            Base64-encoded ciphertext
        """
        public_key = self.load_public_key(public_key_pem)
        
        ciphertext = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return base64.b64encode(ciphertext).decode('utf-8')
    
    def decrypt_with_private_key(self, ciphertext_b64: str) -> bytes:
        """
        Decrypt data with RSA private key (Phase 2: Auth Response)
        
        Args:
            ciphertext_b64: Base64-encoded ciphertext
            
        Returns:
            Decrypted data
        """
        if not self.private_key:
            raise ValueError("Private key not loaded")
        
        ciphertext = base64.b64decode(ciphertext_b64)
        
        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return plaintext
    
    # =====================================================
    # Diffie-Hellman Operations (Phase 3)
    # =====================================================
    
    def generate_dh_keypair(self, prime: int, generator: int) -> Tuple[int, int]:
        """
        Generate Diffie-Hellman ephemeral key pair
        
        Args:
            prime: DH prime modulus (p)
            generator: DH generator (g)
            
        Returns:
            (private_value, public_value) where public = g^private mod p
        """
        # Generate random private value (a or b)
        private_value = int.from_bytes(os.urandom(32), byteorder='big')
        
        # Compute public value: g^a mod p
        public_value = pow(generator, private_value, prime)
        
        return private_value, public_value
    
    def compute_dh_shared_secret(self, private_value: int, peer_public_value: int, prime: int) -> int:
        """
        Compute DH shared secret
        
        Args:
            private_value: Own private DH value (a or b)
            peer_public_value: Peer's public DH value (g^b or g^a)
            prime: DH prime modulus (p)
            
        Returns:
            Shared secret K = (g^b)^a mod p = (g^a)^b mod p
        """
        shared_secret = pow(peer_public_value, private_value, prime)
        return shared_secret
    
    # =====================================================
    # Key Derivation (Phase 3 & 4)
    # =====================================================
    
    def derive_session_keys(self, shared_secret: int, salt: bytes, 
                           context_enc: str = "encryption", 
                           context_mac: str = "authentication") -> Tuple[bytes, bytes]:
        """
        Derive session keys from shared secret using HKDF
        
        Args:
            shared_secret: DH shared secret (integer)
            salt: Salt value (Hash(SessionID || Nonce_A || Nonce_B))
            context_enc: Context for encryption key
            context_mac: Context for MAC key
            
        Returns:
            (K_enc, K_mac) - 32-byte keys for encryption and authentication
        """
        # Convert shared secret to bytes
        secret_bytes = shared_secret.to_bytes(256, byteorder='big')
        
        # Derive encryption key
        k_enc = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=context_enc.encode('utf-8'),
            backend=self.backend
        ).derive(secret_bytes)
        
        # Derive MAC key
        k_mac = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=context_mac.encode('utf-8'),
            backend=self.backend
        ).derive(secret_bytes)
        
        return k_enc, k_mac
    
    def create_salt(self, session_id: str, nonce_a: str, nonce_b: str) -> bytes:
        """
        Create salt for key derivation
        Salt = Hash(SessionID || Nonce_A || Nonce_B)
        """
        data = f"{session_id}{nonce_a}{nonce_b}".encode('utf-8')
        return hashlib.sha256(data).digest()
    
    # =====================================================
    # Symmetric Encryption (Phase 4)
    # =====================================================
    
    def kdf_stream(self, key: bytes, seq_no: int, length: int) -> bytes:
        """
        Generate keystream for XOR encryption using KDF
        KDF(K_enc, SeqNo) - deterministic stream based on sequence number
        
        Args:
            key: Encryption key (K_enc)
            seq_no: Sequence number
            length: Length of keystream needed
            
        Returns:
            Keystream bytes
        """
        # Use HKDF with seq_no as info parameter
        info = str(seq_no).encode('utf-8')
        
        keystream = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=None,
            info=info,
            backend=self.backend
        ).derive(key)
        
        return keystream
    
    def encrypt_message(self, plaintext: str, key: bytes, seq_no: int) -> str:
        """
        Encrypt message using XOR with KDF keystream
        Ciphertext = XOR(Plaintext, KDF(K_enc, SeqNo))
        
        Args:
            plaintext: Message to encrypt
            key: Encryption key (K_enc)
            seq_no: Sequence number
            
        Returns:
            Base64-encoded ciphertext
        """
        plaintext_bytes = plaintext.encode('utf-8')
        keystream = self.kdf_stream(key, seq_no, len(plaintext_bytes))
        
        # XOR plaintext with keystream
        ciphertext = bytes(p ^ k for p, k in zip(plaintext_bytes, keystream))
        
        return base64.b64encode(ciphertext).decode('utf-8')
    
    def decrypt_message(self, ciphertext_b64: str, key: bytes, seq_no: int) -> str:
        """
        Decrypt message using XOR with KDF keystream
        Plaintext = XOR(Ciphertext, KDF(K_enc, SeqNo))
        
        Args:
            ciphertext_b64: Base64-encoded ciphertext
            key: Encryption key (K_enc)
            seq_no: Sequence number
            
        Returns:
            Decrypted plaintext
        """
        ciphertext = base64.b64decode(ciphertext_b64)
        keystream = self.kdf_stream(key, seq_no, len(ciphertext))
        
        # XOR ciphertext with keystream (same operation as encryption)
        plaintext_bytes = bytes(c ^ k for c, k in zip(ciphertext, keystream))
        
        return plaintext_bytes.decode('utf-8')
    
    # =====================================================
    # HMAC Operations (Phase 4)
    # =====================================================
    
    def compute_hmac(self, key: bytes, data: str) -> str:
        """
        Compute HMAC for message integrity
        HMAC(K_mac, SessionID || SeqNo || Ciphertext)
        
        Args:
            key: MAC key (K_mac)
            data: Data to authenticate
            
        Returns:
            Base64-encoded HMAC
        """
        mac = hmac.new(key, data.encode('utf-8'), hashlib.sha256).digest()
        return base64.b64encode(mac).decode('utf-8')
    
    def verify_hmac(self, key: bytes, data: str, hmac_b64: str) -> bool:
        """
        Verify HMAC
        
        Args:
            key: MAC key (K_mac)
            data: Data that was authenticated
            hmac_b64: Base64-encoded HMAC to verify
            
        Returns:
            True if HMAC is valid, False otherwise
        """
        try:
            expected_mac = base64.b64decode(hmac_b64)
            computed_mac = hmac.new(key, data.encode('utf-8'), hashlib.sha256).digest()
            return hmac.compare_digest(expected_mac, computed_mac)
        except Exception as e:
            print(f"HMAC verification error: {e}")
            return False
    
    # =====================================================
    # Utility Functions
    # =====================================================
    
    def generate_nonce(self, size: int = 16) -> str:
        """
        Generate random nonce
        
        Args:
            size: Size in bytes
            
        Returns:
            Base64-encoded nonce
        """
        nonce = os.urandom(size)
        return base64.b64encode(nonce).decode('utf-8')
    
    def hash_data(self, data: str) -> bytes:
        """Hash data using SHA-256"""
        return hashlib.sha256(data.encode('utf-8')).digest()
    
    def int_to_base64(self, value: int) -> str:
        """Convert integer to base64 string (for DH public values)"""
        # Convert to bytes (256 bytes for 2048-bit numbers)
        value_bytes = value.to_bytes(256, byteorder='big')
        return base64.b64encode(value_bytes).decode('utf-8')
    
    def base64_to_int(self, value_b64: str) -> int:
        """Convert base64 string to integer (for DH public values)"""
        value_bytes = base64.b64decode(value_b64)
        return int.from_bytes(value_bytes, byteorder='big')


# Example usage and testing
if __name__ == "__main__":
    print("=== Testing CryptoHandler ===\n")
    
    # Test RSA key generation and signing
    print("1. Testing RSA Operations...")
    crypto = CryptoHandler()
    priv_pem, pub_pem = crypto.generate_rsa_keypair()
    print(f"   ✓ Generated RSA keypair")
    
    # Test signing
    test_data = "Hello, World!"
    signature = crypto.sign_data(test_data)
    print(f"   ✓ Created signature")
    
    # Test verification
    is_valid = crypto.verify_signature(pub_pem, test_data, signature)
    print(f"   ✓ Signature valid: {is_valid}")
    
    # Test DH key exchange
    print("\n2. Testing Diffie-Hellman...")
    from common.protocol import ProtocolConstants
    
    # Alice generates DH keypair
    alice_priv, alice_pub = crypto.generate_dh_keypair(
        ProtocolConstants.DH_PRIME, 
        ProtocolConstants.DH_GENERATOR
    )
    print(f"   ✓ Alice generated DH keypair")
    
    # Bob generates DH keypair
    bob_priv, bob_pub = crypto.generate_dh_keypair(
        ProtocolConstants.DH_PRIME,
        ProtocolConstants.DH_GENERATOR
    )
    print(f"   ✓ Bob generated DH keypair")
    
    # Both compute shared secret
    alice_secret = crypto.compute_dh_shared_secret(alice_priv, bob_pub, ProtocolConstants.DH_PRIME)
    bob_secret = crypto.compute_dh_shared_secret(bob_priv, alice_pub, ProtocolConstants.DH_PRIME)
    print(f"   ✓ Shared secrets match: {alice_secret == bob_secret}")
    
    # Test key derivation
    print("\n3. Testing Key Derivation...")
    salt = crypto.create_salt("session123", "nonceA", "nonceB")
    k_enc, k_mac = crypto.derive_session_keys(alice_secret, salt)
    print(f"   ✓ Derived K_enc: {len(k_enc)} bytes")
    print(f"   ✓ Derived K_mac: {len(k_mac)} bytes")
    
    # Test symmetric encryption
    print("\n4. Testing Message Encryption...")
    plaintext = "This is a secret message!"
    ciphertext = crypto.encrypt_message(plaintext, k_enc, seq_no=1)
    print(f"   ✓ Encrypted message")
    
    decrypted = crypto.decrypt_message(ciphertext, k_enc, seq_no=1)
    print(f"   ✓ Decrypted: {decrypted}")
    print(f"   ✓ Match: {plaintext == decrypted}")
    
    # Test HMAC
    print("\n5. Testing HMAC...")
    data = "session123" + "1" + ciphertext
    mac = crypto.compute_hmac(k_mac, data)
    print(f"   ✓ Computed HMAC")
    
    is_valid = crypto.verify_hmac(k_mac, data, mac)
    print(f"   ✓ HMAC valid: {is_valid}")
    
    print("\n=== All tests passed! ===")