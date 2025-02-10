from abc import ABC, abstractmethod
from typing import Optional

class AsymmetricCryptoAlgorithm(ABC):
    @abstractmethod
    def verify_signature(self, public_key, signature: bytes, message: bytes) -> bool:
        pass

    @abstractmethod
    def create_signature(self, private_key, message: bytes) -> bytes:
        pass

    @abstractmethod
    def encrypt_message(self, public_key, message: bytes) -> Optional[bytes]:
        pass

    @abstractmethod
    def decrypt_message(self, private_key, ciphertext: bytes) -> Optional[bytes]:
        pass

    @abstractmethod
    def generate_key_pair(self):
        """Returns a private key object; the public key can be derived from it."""
        pass


class KeyEncoding(ABC):
    @abstractmethod
    def load_public_key(self, key_data: bytes):
        pass

    @abstractmethod
    def load_private_key(self, key_data: bytes, password: Optional[bytes] = None):
        pass

    @abstractmethod
    def serialize_public_key(self, public_key) -> bytes:
        pass

    @abstractmethod
    def serialize_private_key(self, private_key) -> bytes:
        pass 