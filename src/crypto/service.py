import logging
from typing import Optional, Tuple
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature
from .interfaces import AsymmetricCryptoAlgorithm, KeyEncoding


class CryptoService:
    """Service layer for cryptographic operations"""

    def __init__(self,
                 algorithm: AsymmetricCryptoAlgorithm,
                 key_encoding: KeyEncoding):
        self.algorithm = algorithm
        self.key_encoding = key_encoding

    def verify_signature(self,
                        public_key_data: bytes,
                        signature: bytes,
                        message: bytes) -> bool:
        """
        Verify a signature using a public key in PEM format.

        Args:
            public_key_data: Public key in PEM format
            signature: The signature to verify
            message: The original message that was signed

        Returns:
            bool: True if signature is valid
        """
        try:
            public_key = self.key_encoding.load_public_key(public_key_data)
            return self.algorithm.verify_signature(public_key, signature, message)
        except InvalidSignature:
            logging.warning("Invalid signature detected")
            return False
        except Exception as e:
            logging.error(f"Error verifying signature: {str(e)}")
            return False

    def create_signature(self,
                        private_key_data: bytes,
                        message: bytes,
                        password: Optional[bytes] = None) -> bytes:
        """
        Create a signature for a message using a private key.

        Args:
            private_key_data: The private key in PEM format
            message: The message to sign
            password: Optional password if the key is encrypted

        Returns:
            bytes: The signature
        """
        private_key = self.key_encoding.load_private_key(private_key_data, password)
        return self.algorithm.create_signature(private_key, message)

    def encrypt_message(self,
                       public_key_data: bytes,
                       message: bytes) -> Optional[bytes]:
        """
        Encrypt a message using a public key in PEM format.

        Args:
            public_key_data: Public key in PEM format
            message: The message to encrypt

        Returns:
            Optional[bytes]: The encrypted message or None if encryption fails
        """
        try:
            public_key = self.key_encoding.load_public_key(public_key_data)
            return self.algorithm.encrypt_message(public_key, message)
        except Exception as e:
            logging.error(f"Error encrypting message: {str(e)}")
            return None

    def decrypt_message(self,
                       private_key_data: bytes,
                       ciphertext: bytes,
                       password: Optional[bytes] = None) -> Optional[bytes]:
        """
        Decrypt a message using a private key.

        Args:
            private_key_data: The private key in PEM format
            ciphertext: The encrypted message
            password: Optional password if the key is encrypted

        Returns:
            Optional[bytes]: The decrypted message or None if decryption fails
        """
        try:
            private_key = self.key_encoding.load_private_key(private_key_data, password)
            return self.algorithm.decrypt_message(private_key, ciphertext)
        except Exception as e:
            logging.error(f"Error decrypting message: {str(e)}")
            return None

    def generate_key_pair(self) -> Tuple[bytes, bytes]:
        """
        Generates a new key pair and returns a tuple:
        (serialized private key, serialized public key)
        """
        private_key = self.algorithm.generate_key_pair()
        public_key = private_key.public_key()
        return (
            self.key_encoding.serialize_private_key(private_key),
            self.key_encoding.serialize_public_key(public_key)
        )

    def verify_pull_request(self,
                           requester_pub_data: bytes,
                           signature: bytes,
                           nonce: bytes) -> bool:
        """
        Verify a pull request signature.

        Args:
            requester_pub_data: Requester's public key in PEM format
            signature: The signature to verify
            nonce: The nonce used in signing

        Returns:
            bool: True if signature is valid
        """
        message_for_sig = requester_pub_data + nonce
        return self.verify_signature(requester_pub_data, signature, message_for_sig)

    def verify_send_request(self,
                           sender_pub_data: bytes,
                           recipient_pub_data: bytes,
                           ciphertext: bytes,
                           signature: bytes,
                           nonce: bytes) -> bool:
        """
        Verify a send request signature.

        Args:
            sender_pub_data: Sender's public key in PEM format
            recipient_pub_data: Recipient's public key in PEM format
            ciphertext: The encrypted message
            signature: The signature to verify
            nonce: The nonce used in signing

        Returns:
            bool: True if signature is valid
        """
        message_for_sig = recipient_pub_data + ciphertext + nonce
        return self.verify_signature(sender_pub_data, signature, message_for_sig)

    @staticmethod
    def load_public_key(public_key_pem: bytes) -> rsa.RSAPublicKey:
        """
        Load a public key from PEM format.

        Args:
            public_key_pem: Public key in PEM format

        Returns:
            RSAPublicKey: The loaded public key object

        Raises:
            ValueError: If key loading fails
        """
        try:
            return serialization.load_pem_public_key(public_key_pem)
        except Exception as e:
            raise ValueError(f"Failed to load public key: {str(e)}")

    @staticmethod
    def load_private_key(private_key_pem: bytes,
                         password: bytes = None) -> rsa.RSAPrivateKey:
        """
        Load a private key from PEM format.

        Args:
            private_key_pem: Private key in PEM format
            password: Optional password if the key is encrypted

        Returns:
            RSAPrivateKey: The loaded private key object

        Raises:
            ValueError: If key loading fails
        """
        try:
            return serialization.load_pem_private_key(
                private_key_pem, password=password)
        except Exception as e:
            raise ValueError(f"Failed to load private key: {str(e)}")

    @staticmethod
    def serialize_private_key(private_key: rsa.RSAPrivateKey) -> bytes:
        """
        Serialize a private key to PEM format.
        """
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    @staticmethod
    def serialize_public_key(public_key) -> bytes:
        """
        Serialize a public key to PEM format.
        """
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
