import logging
from typing import Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature
from .interfaces import AsymmetricCryptoAlgorithm

class RSACryptoAlgorithm(AsymmetricCryptoAlgorithm):
    def verify_signature(self, public_key, signature: bytes, message: bytes) -> bool:
        try:
            public_key.verify(
                signature,
                message,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            logging.warning("Invalid signature detected")
            return False
        except Exception as e:
            logging.error(f"Error verifying signature: {str(e)}")
            return False

    def create_signature(self, private_key, message: bytes) -> bytes:
        return private_key.sign(
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

    def encrypt_message(self, public_key, message: bytes) -> Optional[bytes]:
        try:
            return public_key.encrypt(
                message,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            logging.error(f"Error encrypting message: {str(e)}")
            return None

    def decrypt_message(self, private_key, ciphertext: bytes) -> Optional[bytes]:
        try:
            return private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            logging.error(f"Error decrypting message: {str(e)}")
            return None

    def generate_key_pair(self):
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        ) 