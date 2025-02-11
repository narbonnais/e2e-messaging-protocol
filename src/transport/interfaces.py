from abc import ABC, abstractmethod
from typing import Callable, Awaitable, Optional
import asyncio


class ClientTransportInterface(ABC):
    @abstractmethod
    def connect(self, host: str, port: int) -> None:
        """Establish a connection to a remote server."""
        pass

    @abstractmethod
    def disconnect(self) -> None:
        """Close the connection."""
        pass

    @abstractmethod
    def send(self, data: bytes) -> bytes:
        """
        Send data to the server and return the response as bytes.
        This is a synchronous method.
        """
        pass

    @abstractmethod
    def is_connected(self) -> bool:
        """Return True if a connection is established."""
        pass


# Server-side transport interface
class ServerTransportInterface(ABC):
    @abstractmethod
    async def start(self) -> None:
        """Start listening for incoming client connections."""
        pass

    @abstractmethod
    async def stop(self) -> None:
        """Stop the server and close all connections."""
        pass

    @abstractmethod
    async def handle_client(
            self,
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter) -> None:
        """
        Handle a client connection.
        This method will be passed an asyncio StreamReader and StreamWriter.
        """
        pass

    @abstractmethod
    def set_request_handler(self,
                            handler: Callable[[bytes],
                                              Awaitable[bytes]]) -> None:
        """
        Set a request handler function.
        The handler takes a bytes object (the incoming data)
        and returns an awaitable which resolves to the response bytes.
        """
        pass
