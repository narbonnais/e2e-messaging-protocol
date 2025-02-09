import asyncio
from typing import Optional, Tuple
import logging
from .server_interface import BaseServer, ServerConfig, Request, Response

class TCPServer(BaseServer):
    """TCP implementation of the server transport"""
    
    def __init__(self, config: ServerConfig, request_handler):
        super().__init__(config, request_handler)
        self.server: Optional[asyncio.AbstractServer] = None
    
    async def start(self) -> None:
        """Start the TCP server"""
        try:
            self.server = await asyncio.start_server(
                self.handle_client,
                self.config.host,
                self.config.port,
                backlog=self.config.max_connections
            )
            self.running = True
            self.logger.info(f"TCP server listening on {self.config.host}:{self.config.port}")
            
            async with self.server:
                await self.server.serve_forever()
                
        except Exception as e:
            self.logger.error(f"Failed to start TCP server: {str(e)}")
            raise
    
    async def stop(self) -> None:
        """Stop the TCP server"""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.running = False
            self.logger.info("TCP server stopped")
    
    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Handle a TCP client connection"""
        peer = writer.get_extra_info('peername')
        self.logger.info(f"New connection from {peer}")
        
        try:
            # Read request
            data = await reader.read(self.config.buffer_size)
            if not data:
                return
                
            # Parse and handle request
            request = self.parse_request(data, peer)
            response = await self.request_handler(request)
            
            # Send response
            writer.write(self.format_response(response))
            await writer.drain()
            
        except Exception as e:
            self.logger.error(f"Error handling client {peer}: {str(e)}")
            error_resp = Response(data=b"", status=False, error=str(e))
            writer.write(self.format_response(error_resp))
            await writer.drain()
            
        finally:
            writer.close()
            await writer.wait_closed()
            self.logger.info(f"Closed connection from {peer}") 