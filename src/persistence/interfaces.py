from typing import List, Optional
from abc import ABC, abstractmethod
from typing import List, Tuple, Optional


class MessageRepositoryInterface(ABC):
    @abstractmethod
    def init_db(self) -> None:
        """Initialize the database schema."""
        pass

    @abstractmethod
    def store_message(
        self,
        recipient_pub: bytes,
        ciphertext: bytes,
        sender_pub: bytes,
        signature: bytes,
        nonce: bytes
    ) -> bool:
        """Store a new message."""
        pass

    @abstractmethod
    def pull_messages(self, recipient_pub: bytes) -> List[Tuple]:
        """
        Pull all messages for a recipient.
        Returns a list of tuples representing the messages.
        """
        pass

    @abstractmethod
    def cleanup_old_messages(self, retention_days: int) -> int:
        """
        Clean up messages older than the retention period.
        Returns the number of deleted records.
        """
        pass


class ContactRepositoryInterface(ABC):
    @abstractmethod
    def init_db(self) -> None:
        """Initialize the contacts table."""
        pass

    @abstractmethod
    def store_contact(self, contact_id: str, public_key_pem: bytes) -> bool:
        """Store or update a contact’s public key."""
        pass

    @abstractmethod
    def get_contact(self, contact_id: str) -> Optional[bytes]:
        """Retrieve a contact’s public key."""
        pass

    @abstractmethod
    def delete_contact(self, contact_id: str) -> bool:
        """Delete a contact by ID."""
        pass

    @abstractmethod
    def list_contacts(self) -> List[str]:
        """Return a list of all contact IDs."""
        pass


class KeyRepositoryInterface(ABC):
    @abstractmethod
    def store_key(
            self,
            identifier: str,
            key_type: str,
            key_data: bytes) -> bool:
        """
        Store a key (public or private) for the given identifier.
        key_type should be either "public" or "private".
        """
        pass

    @abstractmethod
    def get_key(self, identifier: str, key_type: str) -> Optional[bytes]:
        """
        Retrieve the key data for the given identifier and key type.
        Returns the key data or None if not found.
        """
        pass

    @abstractmethod
    def delete_key(self, identifier: str, key_type: str) -> bool:
        """
        Delete the key file for the given identifier and key type.
        """
        pass

    @abstractmethod
    def list_keys(self, identifier: str) -> List[str]:
        """
        List all key file names for a given identifier.
        """
        pass
