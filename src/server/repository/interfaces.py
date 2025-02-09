from abc import ABC, abstractmethod
from typing import List, Tuple, Optional


class MessageRepositoryInterface(ABC):
    """Interface for message storage operations"""

    @abstractmethod
    def init_db(self) -> None:
        """Initialize the database schema"""
        pass

    @abstractmethod
    def store_message(
            self,
            recipient_pub: bytes,
            ciphertext: bytes,
            sender_pub: bytes,
            signature: bytes,
            nonce: bytes) -> bool:
        """Store a new message"""
        pass

    @abstractmethod
    def pull_messages(self, recipient_pub: bytes) -> List[Tuple]:
        """Pull all messages for a recipient"""
        pass

    @abstractmethod
    def cleanup_old_messages(self, retention_days: int) -> int:
        """Clean up old messages"""
        pass
