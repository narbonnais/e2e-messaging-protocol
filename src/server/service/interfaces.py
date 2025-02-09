from abc import ABC, abstractmethod
from typing import Tuple, List

class MessageServiceInterface(ABC):
    """Interface for message handling operations"""
    
    @abstractmethod
    def handle_send_command(self, command_tokens: list) -> Tuple[bool, str, bytes]:
        """Handle SEND command"""
        pass
    
    @abstractmethod
    def handle_pull_command(self, command_tokens: list) -> Tuple[bool, str, bytes]:
        """Handle PULL command"""
        pass
    
    @abstractmethod
    def cleanup_old_messages(self, retention_days: int) -> Tuple[bool, str]:
        """Clean up old messages"""
        pass

class CryptoServiceInterface(ABC):
    """Interface for cryptographic operations"""
    
    @abstractmethod
    def verify_signature(self, public_key_pem: bytes, signature: bytes, message: bytes) -> bool:
        """Verify a signature"""
        pass
    
    @abstractmethod
    def verify_send_request(self, sender_pub: bytes, recipient_pub: bytes,
                          ciphertext: bytes, signature: bytes, nonce: bytes) -> bool:
        """Verify a send request"""
        pass
    
    @abstractmethod
    def verify_pull_request(self, requester_pub: bytes, signature: bytes, nonce: bytes) -> bool:
        """Verify a pull request"""
        pass 