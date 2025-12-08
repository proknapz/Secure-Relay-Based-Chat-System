"""
protocol.py - Secure Relay-Based Chat System Protocol Definitions

Defines all message formats and types for the 4-phase protocol:
- Phase 1: Registration
- Phase 2: Authentication  
- Phase 3: Session Setup
- Phase 4: Message Exchange
"""

import json
import time
from enum import Enum
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict


class MessageType(Enum):
    """Message type identifiers for each protocol phase"""
    # Phase 1: Registration
    REGISTRATION = "REGISTRATION"
    REGISTRATION_ACK = "REGISTRATION_ACK"
    
    # Phase 2: Authentication
    AUTH_CHALLENGE = "AUTH_CHALLENGE"
    AUTH_RESPONSE = "AUTH_RESPONSE"
    AUTH_VERIFY = "AUTH_VERIFY"
    
    # Phase 3: Session Setup
    SESSION_REQUEST = "SESSION_REQUEST"
    SESSION_RESPONSE = "SESSION_RESPONSE"
    SESSION_ESTABLISHED = "SESSION_ESTABLISHED"
    
    # Phase 4: Messaging
    ENCRYPTED_MESSAGE = "ENCRYPTED_MESSAGE"
    MESSAGE_ACK = "MESSAGE_ACK"
    
    # General
    ERROR = "ERROR"


@dataclass
class RegistrationMessage:
    """
    Phase 1: Client → Relay
    { ClientID, ClientPubKey, Timestamp, Signature_Client }
    Signature_Client = Sign{ClientPriv}(ClientID || ClientPubKey || Timestamp)
    """
    msg_type: str = MessageType.REGISTRATION.value
    client_id: str = ""
    client_pubkey: str = ""  # PEM format
    timestamp: float = 0.0
    signature: str = ""  # Base64 encoded
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RegistrationMessage':
        return cls(**data)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'RegistrationMessage':
        return cls.from_dict(json.loads(json_str))
    
    def get_signable_data(self) -> str:
        """Returns the data that should be signed: ClientID || ClientPubKey || Timestamp"""
        return f"{self.client_id}{self.client_pubkey}{self.timestamp}"


@dataclass
class RegistrationAck:
    """Relay → Client acknowledgment of successful registration"""
    msg_type: str = MessageType.REGISTRATION_ACK.value
    client_id: str = ""
    status: str = "success"  # or "error"
    message: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RegistrationAck':
        return cls(**data)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'RegistrationAck':
        return cls.from_dict(json.loads(json_str))


@dataclass
class AuthChallenge:
    """
    Phase 2a: Client → Relay
    M1 = E_PR(N_C) - Encrypted nonce with Relay's public key
    """
    msg_type: str = MessageType.AUTH_CHALLENGE.value
    client_id: str = ""
    encrypted_nonce: str = ""  # Base64 encoded encrypted nonce
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AuthChallenge':
        return cls(**data)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'AuthChallenge':
        return cls.from_dict(json.loads(json_str))


@dataclass
class AuthResponse:
    """
    Phase 2b: Relay → Client
    M2 = Sign_SK(N_C) - Signed nonce
    """
    msg_type: str = MessageType.AUTH_RESPONSE.value
    signed_nonce: str = ""  # Base64 encoded signature
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AuthResponse':
        return cls(**data)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'AuthResponse':
        return cls.from_dict(json.loads(json_str))


@dataclass
class AuthVerify:
    """Client → Relay confirmation that authentication succeeded"""
    msg_type: str = MessageType.AUTH_VERIFY.value
    client_id: str = ""
    status: str = "success"  # or "failed"
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AuthVerify':
        return cls(**data)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'AuthVerify':
        return cls.from_dict(json.loads(json_str))


@dataclass
class SessionRequest:
    """
    Phase 3a: C_a → Relay
    {SessionRequest, ReceiverID, Nonce_A, Ephemeral_DHa, Signature_Ca}
    Ephemeral_DHa = g^a mod p
    """
    msg_type: str = MessageType.SESSION_REQUEST.value
    sender_id: str = ""
    receiver_id: str = ""
    nonce_a: str = ""  # Base64 encoded
    ephemeral_dh_public: str = ""  # Base64 encoded g^a mod p
    signature: str = ""  # Base64 encoded signature of entire message
    timestamp: float = 0.0
    sender_pubkey: str = ""  # PEM format
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SessionRequest':
        return cls(**data)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'SessionRequest':
        return cls.from_dict(json.loads(json_str))
    
    def get_signable_data(self) -> str:
        """Data to sign: everything except the signature itself"""
        return f"{self.sender_id}{self.receiver_id}{self.nonce_a}{self.ephemeral_dh_public}{self.timestamp}{self.sender_pubkey}"


@dataclass
class SessionResponse:
    """
    Phase 3c: C_b → Relay
    {SessionResponse, SenderID, Nonce_A, Nonce_B, Ephemeral_DHb, Signature_Cb}
    Ephemeral_DHb = g^b mod p
    """
    msg_type: str = MessageType.SESSION_RESPONSE.value
    sender_id: str = ""
    receiver_id: str = ""
    nonce_a: str = ""  # Echo back from request
    nonce_b: str = ""  # Base64 encoded
    ephemeral_dh_public: str = ""  # Base64 encoded g^b mod p
    signature: str = ""  # Base64 encoded
    timestamp: float = 0.0
    sender_pubkey: str = ""  # PEM format
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SessionResponse':
        return cls(**data)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'SessionResponse':
        return cls.from_dict(json.loads(json_str))
    
    def get_signable_data(self) -> str:
        """Data to sign: everything except the signature itself"""
        return f"{self.sender_id}{self.receiver_id}{self.nonce_a}{self.nonce_b}{self.ephemeral_dh_public}{self.timestamp}{self.sender_pubkey}"


@dataclass
class SessionEstablished:
    """Confirmation that session keys have been derived"""
    msg_type: str = MessageType.SESSION_ESTABLISHED.value
    session_id: str = ""
    participant_a: str = ""
    participant_b: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SessionEstablished':
        return cls(**data)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'SessionEstablished':
        return cls.from_dict(json.loads(json_str))


@dataclass
class EncryptedMessage:
    """
    Phase 4: Secure Message Exchange
    {SessionID, SeqNo, Ciphertext, HMAC}
    Ciphertext: XOR(Plaintext, KDF(K_enc, SeqNo))
    HMAC: HMAC(K_mac, SessionID || SeqNo || Ciphertext)
    """
    msg_type: str = MessageType.ENCRYPTED_MESSAGE.value
    session_id: str = ""
    sender_id: str = ""
    seq_no: int = 0
    ciphertext: str = ""  # Base64 encoded
    hmac: str = ""  # Base64 encoded
    timestamp: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EncryptedMessage':
        return cls(**data)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'EncryptedMessage':
        return cls.from_dict(json.loads(json_str))
    
    def get_hmac_data(self) -> str:
        """Data to HMAC: SessionID || SeqNo || Ciphertext"""
        return f"{self.session_id}{self.seq_no}{self.ciphertext}"


@dataclass
class MessageAck:
    """Acknowledgment of received message"""
    msg_type: str = MessageType.MESSAGE_ACK.value
    session_id: str = ""
    seq_no: int = 0
    status: str = "received"
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MessageAck':
        return cls(**data)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'MessageAck':
        return cls.from_dict(json.loads(json_str))


@dataclass
class ErrorMessage:
    """Generic error message"""
    msg_type: str = MessageType.ERROR.value
    error_code: str = ""
    error_message: str = ""
    context: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ErrorMessage':
        return cls(**data)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'ErrorMessage':
        return cls.from_dict(json.loads(json_str))


# Protocol Constants
class ProtocolConstants:
    """Configuration constants for the protocol"""
    
    # DH Parameters (using a 2048-bit safe prime)
    DH_PRIME = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
    )
    DH_GENERATOR = 2
    
    # Key sizes
    RSA_KEY_SIZE = 2048
    AES_KEY_SIZE = 32  # 256 bits
    HMAC_KEY_SIZE = 32  # 256 bits
    NONCE_SIZE = 16  # 128 bits
    
    # Timeouts
    REGISTRATION_TIMEOUT = 30  # seconds
    AUTH_TIMEOUT = 30
    SESSION_TIMEOUT = 60
    MESSAGE_TIMEOUT = 10
    
    # Replay protection
    MAX_TIMESTAMP_DRIFT = 300  # 5 minutes
    
    # Key refresh
    KEY_REFRESH_INTERVAL = 3600  # 1 hour


def parse_message(json_str: str) -> Any:
    """
    Parse a JSON message and return the appropriate message object
    """
    data = json.loads(json_str)
    msg_type = data.get('msg_type', '')
    
    message_map = {
        MessageType.REGISTRATION.value: RegistrationMessage,
        MessageType.REGISTRATION_ACK.value: RegistrationAck,
        MessageType.AUTH_CHALLENGE.value: AuthChallenge,
        MessageType.AUTH_RESPONSE.value: AuthResponse,
        MessageType.AUTH_VERIFY.value: AuthVerify,
        MessageType.SESSION_REQUEST.value: SessionRequest,
        MessageType.SESSION_RESPONSE.value: SessionResponse,
        MessageType.SESSION_ESTABLISHED.value: SessionEstablished,
        MessageType.ENCRYPTED_MESSAGE.value: EncryptedMessage,
        MessageType.MESSAGE_ACK.value: MessageAck,
        MessageType.ERROR.value: ErrorMessage,
    }
    
    message_class = message_map.get(msg_type)
    if message_class:
        return message_class.from_dict(data)
    else:
        raise ValueError(f"Unknown message type: {msg_type}")


def create_error(code: str, message: str, context: str = "") -> ErrorMessage:
    """Helper to create error messages"""
    return ErrorMessage(
        error_code=code,
        error_message=message,
        context=context
    )