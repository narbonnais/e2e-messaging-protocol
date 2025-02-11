from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


@dataclass
class ClientServerConfig:
    host: str = "193.168.195.34"
    port: int = 50000


@dataclass
class ClientWebConfig:
    host: str = "127.0.0.1"
    port: int = 8000


@dataclass
class ClientDatabaseConfig:
    name: str = "client.db"


class IClientConfigService(ABC):
    @abstractmethod
    def load_config(self) -> None:
        """Load or reload the configuration data."""
        pass

    @abstractmethod
    def get_server_config(self) -> ClientServerConfig:
        pass

    @abstractmethod
    def get_web_config(self) -> ClientWebConfig:
        pass

    @abstractmethod
    def get_data_dir(self) -> str:
        pass

    @abstractmethod
    def get_database_config(self) -> ClientDatabaseConfig:
        pass

# === Server Configuration Interfaces ===


@dataclass
class TCPServerConfig:
    host: str = "127.0.0.1"
    port: int = 50000


@dataclass
class WebServerConfig:
    host: str = "127.0.0.1"
    port: int = 8001


@dataclass
class ServerDatabaseConfig:
    path: str = ".data/server"
    name: str = "server.db"
    cleanup_interval: int = 3600
    retention_days: int = 7


class IServerConfigService(ABC):
    @abstractmethod
    def load_config(self) -> None:
        """Load or reload the configuration data."""
        pass

    @abstractmethod
    def get_tcp_server_config(self) -> TCPServerConfig:
        pass

    @abstractmethod
    def get_web_server_config(self) -> WebServerConfig:
        pass

    @abstractmethod
    def get_database_config(self) -> ServerDatabaseConfig:
        pass
