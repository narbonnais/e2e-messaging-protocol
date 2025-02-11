from typing import Optional, Tuple
from .client_network_interface import INetworkClient
from ..transport.tcp_client_transport import TCPClientTransport
from ...common.protocol_handler_interface import IProtocolHandler
from ...common.key_manager import IKeyManager
from ..repository.contact_repository_interface import IContactRepository


class NetworkClient(INetworkClient):
    """Implementation of the network client interface."""

    def __init__(self,
                 transport: TCPClientTransport,
                 protocol_handler: IProtocolHandler,
                 key_manager: IKeyManager,
                 contact_repo: IContactRepository,
                 user_id: str):
        """Initialize with required dependencies.

        Args:
            transport: Transport layer implementation
            protocol_handler: Protocol handler implementation
            key_manager: Key management implementation
            contact_repo: Contact repository implementation
            user_id: Current user's identifier
        """
        self._transport = transport
        self._protocol = protocol_handler
        self._key_manager = key_manager
        self._contact_repo = contact_repo
        self._user_id = user_id
        self._host: Optional[str] = None
        self._port: Optional[int] = None

    def connect(self, host: str, port: int) -> None:
        """Connect to the messaging server."""
        self._host = host
        self._port = port
        self._transport.connect(host, port)

    def send_message(self, recipient_id: str, message: str) -> str:
        """Send a message to another user."""
        try:
            # Get recipient's public key
            recipient_pub_key = self._contact_repo.get_contact(recipient_id)
            if not recipient_pub_key:
                return f"Error: No public key found for '{recipient_id}'"

            # Get sender's private key
            private_key_pem = self._key_manager.get_private_key(self._user_id)
            private_key = self._key_manager.load_private_key(private_key_pem)

            # Create and send command
            send_cmd, ciphertext = self._protocol.create_send_command(
                private_key, recipient_pub_key, message)

            resp = self._transport.send(send_cmd.encode('utf-8'))
            resp_text = resp.decode('utf-8', errors='ignore').strip()

            # Parse response
            success, msg = self._protocol.parse_send_response(resp_text)
            return msg

        except ConnectionError as e:
            self.disconnect()
            raise ConnectionError(f"Send failed: {str(e)}")
        except Exception as e:
            return f"Error sending message: {str(e)}"

    def pull_messages(self) -> Tuple[int, str]:
        """Pull pending messages from the server."""
        try:
            # Get user's private key
            private_key_pem = self._key_manager.get_private_key(self._user_id)
            private_key = self._key_manager.load_private_key(private_key_pem)

            # Create and send command
            pull_cmd = self._protocol.create_pull_command(private_key)
            resp = self._transport.send(pull_cmd.encode('utf-8'))
            resp_text = resp.decode('utf-8', errors='ignore').strip()

            # Parse and process messages
            messages = self._protocol.parse_pull_response(
                resp_text, private_key)

            if messages:
                return len(messages), f"Retrieved {len(messages)} messages"
            return 0, "No new messages"

        except ConnectionError as e:
            self.disconnect()
            raise ConnectionError(f"Pull failed: {str(e)}")
        except Exception as e:
            return 0, f"Error pulling messages: {str(e)}"

    def disconnect(self) -> None:
        """Disconnect from the server."""
        self._transport.disconnect()

    def is_connected(self) -> bool:
        """Check connection status."""
        return self._transport.is_connected()
