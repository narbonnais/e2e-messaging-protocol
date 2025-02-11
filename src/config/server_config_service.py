import yaml
from pathlib import Path
from dataclasses import dataclass
from typing import Optional
from .interfaces import (
    IServerConfigService,
    TCPServerConfig,
    WebServerConfig,
    ServerDatabaseConfig
)


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


class ServerConfigService(IServerConfigService):
    def __init__(self, config_path: Optional[str] = None):
        # Use provided config file or default to "config/server_default.yaml"
        self.config_file = config_path or "config/server_default.yaml"
        self.config_data = {}
        self.load_config()

    def load_config(self) -> None:
        config_path = Path(self.config_file)
        if not config_path.exists():
            raise FileNotFoundError(
                f"Server config file not found at {config_path}")
        with config_path.open("r") as f:
            self.config_data = yaml.safe_load(f) or {}

    def get_tcp_server_config(self) -> TCPServerConfig:
        tcp_conf = self.config_data.get("tcp_server", {})
        return TCPServerConfig(
            host=tcp_conf.get("host", "127.0.0.1"),
            port=tcp_conf.get("port", 50000)
        )

    def get_web_server_config(self) -> WebServerConfig:
        web_conf = self.config_data.get("web_server", {})
        return WebServerConfig(
            host=web_conf.get("host", "127.0.0.1"),
            port=web_conf.get("port", 8001)
        )

    def get_database_config(self) -> ServerDatabaseConfig:
        db_conf = self.config_data.get("database", {})
        return ServerDatabaseConfig(
            path=db_conf.get("path", ".data/server"),
            name=db_conf.get("name", "server.db"),
            cleanup_interval=db_conf.get("cleanup_interval", 3600),
            retention_days=db_conf.get("retention_days", 7)
        )
