from cryptography.hazmat.primitives import serialization
from typing import Optional
from .interfaces import KeyEncoding


class PEMKeyEncoding(KeyEncoding):
    def load_public_key(self, key_data: bytes):
        try:
            return serialization.load_pem_public_key(key_data)
        except Exception as e:
            raise ValueError(f"Failed to load public key: {str(e)}")

    def load_private_key(
            self,
            key_data: bytes,
            password: Optional[bytes] = None):
        try:
            return serialization.load_pem_private_key(
                key_data, password=password)
        except Exception as e:
            raise ValueError(f"Failed to load private key: {str(e)}")

    def serialize_public_key(self, public_key) -> bytes:
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def serialize_private_key(self, private_key) -> bytes:
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
