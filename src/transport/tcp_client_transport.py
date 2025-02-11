import socket
from typing import Optional
from .interfaces import ClientTransportInterface


class TCPClientTransport(ClientTransportInterface):
    def __init__(
            self,
            timeout: Optional[float] = 5.0,
            buffer_size: int = 4096):
        self._socket: Optional[socket.socket] = None
        self._timeout = timeout
        self._buffer_size = buffer_size

    def connect(self, host: str, port: int) -> None:
        if self.is_connected():
            self.disconnect()
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.settimeout(self._timeout)
        self._socket.connect((host, port))

    def disconnect(self) -> None:
        if self._socket:
            self._socket.close()
            self._socket = None

    def send(self, data: bytes) -> bytes:
        if not self.is_connected():
            raise ConnectionError("Not connected")
        self._socket.sendall(data)
        chunks = []
        while True:
            try:
                chunk = self._socket.recv(self._buffer_size)
            except socket.timeout:
                # Timeout reached: assume no more data
                break
            if not chunk:
                # No more data received (connection closed by server)
                break
            chunks.append(chunk)
        return b"".join(chunks)

    def is_connected(self) -> bool:
        return self._socket is not None
