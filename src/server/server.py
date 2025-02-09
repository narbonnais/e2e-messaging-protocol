import logging
import asyncio
from typing import Optional
from .repository.message_repository import MessageRepository
from .service.message_service import MessageService
from .transport.server_interface import ServerConfig as TransportConfig
from .transport.tcp_server import TCPServer
from ..common.config_service import ConfigService, ConfigurationError
from ..common.crypto_service import CryptoService
from .transport.server_interface import Request, Response


class MessageServer:
    """Message server using transport abstraction"""

    def __init__(self,
                 config_service: Optional[ConfigService] = None,
                 config_path: Optional[str] = None):
        # Initialize configuration
        self.config_service = config_service or ConfigService()
        try:
            self.config_service.load_config(config_path)
        except ConfigurationError as e:
            logging.critical(f"Configuration error: {str(e)}")
            raise

        # Initialize components with config
        db_config = self.config_service.get_database_config()
        server_config = self.config_service.get_server_config()

        # Create dependencies
        self.repo = MessageRepository(db_config.get_full_path())
        self.crypto_service = CryptoService()
        self.service = MessageService(self.repo, self.crypto_service)

        # Create transport server
        transport_config = TransportConfig(
            host=server_config.host,
            port=server_config.port,
            timeout=server_config.timeout,
            max_connections=server_config.max_connections,
            buffer_size=server_config.buffer_size
        )
        self.server = TCPServer(transport_config, self.handle_request)

    async def handle_request(self, request: Request) -> Response:
        """Handle a client request"""
        try:
            if request.command == "SEND":
                success, msg, response = self.service.handle_send_command(
                    request.data.decode().split())
                return Response(
                    data=response,
                    status=success,
                    error=None if success else msg)

            elif request.command == "PULL":
                success, msg, response = self.service.handle_pull_command(
                    request.data.decode().split())
                return Response(
                    data=response,
                    status=success,
                    error=None if success else msg)

            else:
                return Response(
                    data=b"ERROR: Unknown command\n",
                    status=False,
                    error="Unknown command"
                )

        except Exception as e:
            logging.error(f"Error handling request: {str(e)}")
            return Response(
                data=b"",
                status=False,
                error=str(e)
            )

    async def start(self):
        """Start the server"""
        await self.server.start()

    async def stop(self):
        """Stop the server"""
        await self.server.stop()


def run_server(host: str = None, port: int = None, config_path: str = None):
    """Entry point to start the server"""
    try:
        server = MessageServer(config_path)

        # Override host/port if provided
        if host or port:
            config = server.config_service.get_server_config()
            transport_config = TransportConfig(
                host=host or config.host,
                port=port or config.port,
                timeout=config.timeout,
                max_connections=config.max_connections,
                buffer_size=config.buffer_size
            )
            server.server.config = transport_config

        asyncio.run(server.start())
    except KeyboardInterrupt:
        asyncio.run(server.stop())
    except Exception as e:
        logging.critical(f"Failed to start server: {str(e)}")
        raise
