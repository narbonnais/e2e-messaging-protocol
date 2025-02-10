import socket
import logging
from typing import Optional
from .client_transport_interface import IClientTransport

class TCPClientTransport(IClientTransport):
    """TCP implementation of the client transport interface."""
    
    def __init__(self):
        self._socket: Optional[socket.socket] = None
        self._timeout: Optional[float] = 5.0  # Default 5 second timeout
        
    def connect(self, host: str, port: int) -> None:
        """Establish TCP connection to server."""
        try:
            if self.is_connected():
                self.disconnect()
                
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.settimeout(self._timeout)
            self._socket.connect((host, port))
        except socket.timeout:
            raise ConnectionError("Connection attempt timed out")
        except ConnectionRefusedError:
            raise ConnectionError("Connection refused by server")
        except socket.gaierror:
            raise ConnectionError("Could not resolve server address")
        except Exception as e:
            raise ConnectionError(f"Failed to connect: {str(e)}")
    
    def disconnect(self) -> None:
        """Close the TCP connection."""
        if self._socket:
            try:
                self._socket.close()
            except Exception as e:
                logging.warning(f"Error during disconnect: {str(e)}")
            finally:
                self._socket = None
    
    def send(self, data: bytes) -> bytes:
        """Send data and receive response over TCP."""
        if not self.is_connected():
            raise ConnectionError("Not connected to server")
            
        try:
            self._socket.sendall(data)
            return self._socket.recv(65536)
        except socket.timeout:
            raise TimeoutError("Server response timed out")
        except Exception as e:
            self.disconnect()  # Clean up socket on error
            raise ConnectionError(f"Send/receive failed: {str(e)}")
    
    def is_connected(self) -> bool:
        """Check if TCP connection is established."""
        return bool(self._socket)
    
    def set_timeout(self, timeout: Optional[float]) -> None:
        """Set socket timeout."""
        self._timeout = timeout
        if self._socket:
            self._socket.settimeout(timeout)
    
    def __del__(self):
        """Ensure socket is closed on cleanup."""
        self.disconnect() 