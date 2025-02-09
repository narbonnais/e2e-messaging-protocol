import logging
import base64
from typing import Tuple, Optional
from ..repository.interfaces import MessageRepositoryInterface
from .interfaces import MessageServiceInterface, CryptoServiceInterface
from ...common.crypto_service import CryptoService

class MessageService(MessageServiceInterface):
    """Service layer for handling message operations"""
    
    def __init__(self, 
                 repository: MessageRepositoryInterface,
                 crypto_service: CryptoServiceInterface):
        self.repository = repository
        self.crypto = crypto_service

    def handle_send_command(self, command_tokens: list) -> Tuple[bool, str, bytes]:
        """
        Process a SEND command
        
        Args:
            command_tokens: List of command parts ["SEND", recipient_pub, ciphertext, ...]
            
        Returns:
            Tuple[bool, str, bytes]: (success, message, response_bytes)
        """
        if len(command_tokens) != 6:
            return False, "Invalid SEND command format", b"ERROR: Invalid SEND command format\n"

        try:
            # Decode base64 tokens
            _, b64_recipient_pub, b64_ciphertext, b64_signature, b64_sender_pub, b64_nonce = command_tokens
            recipient_pub = base64.b64decode(b64_recipient_pub)
            ciphertext = base64.b64decode(b64_ciphertext)
            signature = base64.b64decode(b64_signature)
            sender_pub = base64.b64decode(b64_sender_pub)
            nonce = base64.b64decode(b64_nonce)

            # Verify signature using injected crypto service
            if not self.crypto.verify_send_request(sender_pub, recipient_pub, ciphertext, signature, nonce):
                msg = f"Invalid signature in SEND from {sender_pub[:20]}..."
                logging.warning(msg)
                return False, msg, b"ERROR: Invalid signature\n"

            # Store message using injected repository
            if self.repository.store_message(recipient_pub, ciphertext, sender_pub, signature, nonce):
                msg = f"Stored message for {recipient_pub[:20]} from {sender_pub[:20]}..."
                logging.info(msg)
                return True, msg, b"OK: Message stored\n"
            
            return False, "Failed to store message", b"ERROR: Failed to store message\n"

        except Exception as e:
            error_msg = f"Error handling SEND: {str(e)}"
            logging.error(error_msg)
            return False, error_msg, f"ERROR: {str(e)}\n".encode('utf-8')

    def handle_pull_command(self, command_tokens: list) -> Tuple[bool, str, bytes]:
        """
        Process a PULL command
        
        Args:
            command_tokens: List of command parts ["PULL", requester_pub, signature, nonce]
            
        Returns:
            Tuple[bool, str, bytes]: (success, message, response_bytes)
        """
        if len(command_tokens) != 4:
            return False, "Invalid PULL command format", b"ERROR: Invalid PULL command format\n"

        try:
            # Decode base64 tokens
            _, b64_requester_pub, b64_signature, b64_nonce = command_tokens
            requester_pub = base64.b64decode(b64_requester_pub)
            signature = base64.b64decode(b64_signature)
            nonce = base64.b64decode(b64_nonce)

            # Verify signature
            if not self.crypto.verify_pull_request(requester_pub, signature, nonce):
                msg = f"Invalid signature in PULL from {requester_pub[:20]}..."
                logging.warning(msg)
                return False, msg, b"ERROR: Invalid signature\n"

            # Pull messages
            rows = self.repository.pull_messages(requester_pub)
            if not rows:
                return True, "No messages", b"OK: No messages\n"

            # Format response
            lines = []
            for row in rows:
                msg_id, ciphertext, sender_pub_data, sig, nonce, ts = row
                ciph_b64 = base64.b64encode(ciphertext).decode('utf-8')
                spub_b64 = base64.b64encode(sender_pub_data).decode('utf-8')
                lines.append(ciph_b64 + "::" + spub_b64)

            msg = f"Delivered {len(rows)} messages to {requester_pub[:20]}..."
            logging.info(msg)
            resp = "MESSAGES:\n" + "\n".join(lines) + "\n"
            return True, msg, resp.encode('utf-8')

        except Exception as e:
            error_msg = f"Error handling PULL: {str(e)}"
            logging.error(error_msg)
            return False, error_msg, f"ERROR: {str(e)}\n".encode('utf-8')

    def cleanup_old_messages(self, retention_days: int) -> Tuple[bool, str]:
        """
        Clean up old pulled messages
        
        Returns:
            Tuple[bool, str]: (success, message)
        """
        try:
            deleted = self.repository.cleanup_old_messages(retention_days)
            if deleted > 0:
                msg = f"Deleted {deleted} old pulled messages"
                logging.info(msg)
                return True, msg
            return True, "No messages to clean up"
        except Exception as e:
            error_msg = f"Error cleaning up messages: {str(e)}"
            logging.error(error_msg)
            return False, error_msg 