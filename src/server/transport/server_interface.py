from abc import ABC, abstractmethod
from typing import Optional, Tuple, Any
import logging
from dataclasses import dataclass


@dataclass
class ServerConfig:
    """Configuration for server transport"""
    host: str
    port: int
    timeout: int = 30
    max_connections: int = 5
    buffer_size: int = 4096


@dataclass
class Request:
    """Represents a client request"""
    command: str
    data: bytes
    client_info: Tuple[str, int]  # (host, port)
    raw_data: Optional[bytes] = None


@dataclass
class Response:
    """Represents a server response"""
    data: bytes
    status: bool = True
    error: Optional[str] = None


class ServerInterface(ABC):
    """Abstract base class for server transport implementations"""

    def __init__(self, config: ServerConfig):
        self.config = config
        self.running = False
        self._setup_logging()

    def _setup_logging(self):
        self.logger = logging.getLogger(self.__class__.__name__)

    @abstractmethod
    async def start(self) -> None:
        """Start the server"""
        pass

    @abstractmethod
    async def stop(self) -> None:
        """Stop the server"""
        pass

    @abstractmethod
    async def handle_client(self, client: Any) -> None:
        """Handle a client connection"""
        pass

    @abstractmethod
    def parse_request(self,
                      data: bytes,
                      client_info: Tuple[str,
                                         int]) -> Request:
        """Parse raw request data into a Request object"""
        pass

    @abstractmethod
    def format_response(self, response: Response) -> bytes:
        """Format Response object into raw bytes"""
        pass


class BaseServer(ServerInterface):
    """Base implementation with common functionality"""

    def __init__(self, config: ServerConfig, request_handler):
        super().__init__(config)
        self.request_handler = request_handler

    def parse_request(self,
                      data: bytes,
                      client_info: Tuple[str,
                                         int]) -> Request:
        """Default request parsing"""
        try:
            decoded = data.decode('utf-8', errors='ignore').strip()
            tokens = decoded.split()
            if not tokens:
                raise ValueError("Empty request")

            command = tokens[0].upper()
            return Request(
                command=command,
                data=data,
                client_info=client_info,
                raw_data=data
            )
        except Exception as e:
            self.logger.error(f"Error parsing request: {str(e)}")
            raise

    def format_response(self, response: Response) -> bytes:
        """Default response formatting"""
        if not response.status:
            return f"ERROR: {response.error}\n".encode('utf-8')
        return response.data
