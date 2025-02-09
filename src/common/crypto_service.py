import logging
from typing import Optional
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature

class CryptoService:
    """Service layer for cryptographic operations"""

    @staticmethod
    def verify_signature(public_key_pem: bytes, signature: bytes, message: bytes) -> bool:
        """
        Verify a signature using a public key in PEM format.

        Args:
            public_key_pem: Public key in PEM format
            signature: The signature to verify
            message: The original message that was signed

        Returns:
            bool: True if signature is valid
        """
        try:
            public_key = CryptoService.load_public_key(public_key_pem)
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

    @staticmethod
    def create_signature(private_key: rsa.RSAPrivateKey, message: bytes) -> bytes:
        """
        Create a signature for a message using a private key.

        Args:
            private_key: The private key object
            message: The message to sign

        Returns:
            bytes: The signature
        """
        return private_key.sign(
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

    @staticmethod
    def encrypt_message(public_key_pem: bytes, message: bytes) -> Optional[bytes]:
        """
        Encrypt a message using a public key in PEM format.

        Args:
            public_key_pem: Public key in PEM format
            message: The message to encrypt

        Returns:
            Optional[bytes]: The encrypted message or None if encryption fails
        """
        try:
            pub_key = CryptoService.load_public_key(public_key_pem)
            return pub_key.encrypt(
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

    @staticmethod
    def decrypt_message(private_key: rsa.RSAPrivateKey, ciphertext: bytes) -> Optional[bytes]:
        """
        Decrypt a message using a private key.

        Args:
            private_key: The private key object
            ciphertext: The encrypted message

        Returns:
            Optional[bytes]: The decrypted message or None if decryption fails
        """
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
    def load_private_key(private_key_pem: bytes, password: bytes = None) -> rsa.RSAPrivateKey:
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
            return serialization.load_pem_private_key(private_key_pem, password=password)
        except Exception as e:
            raise ValueError(f"Failed to load private key: {str(e)}")

    @staticmethod
    def generate_key_pair() -> rsa.RSAPrivateKey:
        """
        Generate a new 2048-bit RSA key pair.
        
        Returns:
            RSAPrivateKey: The private key (public key can be derived from this)
        """
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

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

    @staticmethod
    def verify_pull_request(requester_pub: bytes, signature: bytes, nonce: bytes) -> bool:
        """
        Verify a pull request signature.
        
        Args:
            requester_pub: Requester's public key in PEM format
            signature: The signature to verify
            nonce: The nonce used in signing
            
        Returns:
            bool: True if signature is valid
        """
        message_for_sig = requester_pub + nonce
        return CryptoService.verify_signature(requester_pub, signature, message_for_sig)

    @staticmethod
    def verify_send_request(sender_pub: bytes, recipient_pub: bytes, 
                          ciphertext: bytes, signature: bytes, nonce: bytes) -> bool:
        """
        Verify a send request signature.
        
        Args:
            sender_pub: Sender's public key in PEM format
            recipient_pub: Recipient's public key in PEM format
            ciphertext: The encrypted message
            signature: The signature to verify
            nonce: The nonce used in signing
            
        Returns:
            bool: True if signature is valid
        """
        message_for_sig = recipient_pub + ciphertext + nonce
        return CryptoService.verify_signature(sender_pub, signature, message_for_sig) 