import base64
import os
import logging
from typing import Tuple, Optional

from .crypto_service import CryptoService

crypto_service = CryptoService()


def create_send_command(
    sender_private_key,
    recipient_pub_key: bytes,
    message: str
) -> Tuple[str, bytes]:
    """
    Create a SEND command for the client-server protocol.

    Args:
        sender_private_key: The sender's private key object
        recipient_pub_key: The recipient's public key in PEM format
        message: The message to send

    Returns:
        Tuple[str, bytes]: The command string and the ciphertext
    """
    # Convert recipient pub to PEM if needed
    recipient_pub_pem = recipient_pub_key  # Already in PEM format

    # Encrypt message
    ciphertext = crypto_service.encrypt_message(
        recipient_pub_pem, message.encode('utf-8'))

    # Get sender's public key
    sender_pub_pem = crypto_service.serialize_public_key(
        sender_private_key.public_key())

    # Generate nonce and create signature
    nonce = os.urandom(32)
    data_to_sign = recipient_pub_pem + ciphertext + nonce
    signature = crypto_service.create_signature(
        sender_private_key, data_to_sign)

    # Encode everything in base64
    b64_recipient_pub = base64.b64encode(recipient_pub_pem).decode('utf-8')
    b64_ciphertext = base64.b64encode(ciphertext).decode('utf-8')
    b64_signature = base64.b64encode(signature).decode('utf-8')
    b64_sender_pub = base64.b64encode(sender_pub_pem).decode('utf-8')
    b64_nonce = base64.b64encode(nonce).decode('utf-8')

    cmd = f"SEND {b64_recipient_pub} {b64_ciphertext} {b64_signature} {b64_sender_pub} {b64_nonce}\n"
    return cmd, ciphertext


def create_pull_command(private_key) -> str:
    """
    Create a PULL command for the client-server protocol.

    Args:
        private_key: The requester's private key object

    Returns:
        str: The command string
    """
    pub_pem = crypto_service.serialize_public_key(private_key.public_key())

    # Generate nonce and signature
    nonce = os.urandom(32)
    data_to_sign = pub_pem + nonce
    signature = crypto_service.create_signature(private_key, data_to_sign)

    # Encode in base64
    b64_requester_pub = base64.b64encode(pub_pem).decode('utf-8')
    b64_signature = base64.b64encode(signature).decode('utf-8')
    b64_nonce = base64.b64encode(nonce).decode('utf-8')

    return f"PULL {b64_requester_pub} {b64_signature} {b64_nonce}\n"


def parse_pull_response(response: str, private_key) -> list:
    """
    Parse a server response to a PULL command.

    Args:
        response: The server's response string
        private_key: The private key to decrypt messages

    Returns:
        list: List of (sender_pub_pem, plaintext) tuples
    """
    if response.startswith("ERROR:"):
        raise ValueError(response)

    if response.startswith("OK: No messages"):
        return []

    # Remove "MESSAGES:" prefix if present
    if response.startswith("MESSAGES:"):
        response = response[9:].strip()

    if not response:
        return []

    messages = []
    for msg in response.split("\n"):
        if not msg:
            continue

        try:
            # Parse message parts
            parts = msg.split("::")
            if len(parts) != 2:
                logging.warning(f"Invalid message format: {msg}")
                continue

            b64_ciphertext, b64_sender_pub = parts
            ciphertext = base64.b64decode(b64_ciphertext)
            sender_pub_pem = base64.b64decode(b64_sender_pub)

            # Decrypt message
            plaintext = crypto_service.decrypt_message(
                private_key, ciphertext).decode('utf-8')
            messages.append((sender_pub_pem, plaintext))

        except Exception as e:
            logging.error(f"Error decrypting message: {str(e)}")
            continue

    return messages


def parse_send_response(response: str) -> Tuple[bool, str]:
    """
    Parse a server response to a SEND command.

    Args:
        response: The server's response string

    Returns:
        Tuple[bool, str]: Success flag and message
    """
    if response.startswith("ERROR:"):
        return False, response[7:].strip()
    if response.startswith("OK:"):
        return True, response[3:].strip()
    return False, "Unknown response format"
