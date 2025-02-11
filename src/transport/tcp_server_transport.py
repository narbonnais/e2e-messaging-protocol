import asyncio
from typing import Callable, Awaitable, Optional
from .interfaces import ServerTransportInterface


class TCPServerTransport(ServerTransportInterface):
    def __init__(self, host: str, port: int, buffer_size: int = 4096):
        self.host = host
        self.port = port
        self.buffer_size = buffer_size
        self.server: Optional[asyncio.AbstractServer] = None
        # The request handler must be an async function: bytes ->
        # Awaitable[bytes]
        self._request_handler: Optional[Callable[[
            bytes], Awaitable[bytes]]] = None

    def set_request_handler(self,
                            handler: Callable[[bytes],
                                              Awaitable[bytes]]) -> None:
        """Set the handler function that will process incoming requests."""
        self._request_handler = handler

    async def handle_client(
            self,
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter) -> None:
        """Handle an individual client connection."""
        if self._request_handler is None:
            raise RuntimeError(
                "No request handler set for the server transport.")

        peer = writer.get_extra_info('peername')
        try:
            while True:  # Keep connection open for multiple messages
                data = await reader.read(self.buffer_size)
                if not data:  # Client closed connection
                    break

                response = await self._request_handler(data)
                writer.write(response)
                await writer.drain()

        except Exception as e:
            print(f"Error handling client {peer}: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def start(self) -> None:
        """Start the server and begin listening for connections."""
        self.server = await asyncio.start_server(
            self.handle_client,
            self.host,
            self.port
        )
        await self.server.start_serving()
        print(f"Server listening on {self.host}:{self.port}")

    async def stop(self) -> None:
        """Stop the server and close all connections."""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            print("Server stopped.")
