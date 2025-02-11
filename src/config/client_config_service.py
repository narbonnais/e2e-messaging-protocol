import yaml
from pathlib import Path
from typing import Optional
from .interfaces import (
    IClientConfigService,
    ClientServerConfig,
    ClientWebConfig,
    ClientDatabaseConfig
)


class ClientConfigService(IClientConfigService):
    def __init__(self, config_path: Optional[str] = None):
        # Use provided config file or default to "config/client_default.yaml"
        self.config_file = config_path or "config/client_default.yaml"
        self.config_data = {}
        self.load_config()

    def load_config(self) -> None:
        default_path = Path(self.config_file)
        if not default_path.exists():
            raise FileNotFoundError(
                f"Client config file not found at {default_path}")
        with default_path.open("r") as f:
            self.config_data = yaml.safe_load(f) or {}

    def get_server_config(self) -> ClientServerConfig:
        server_conf = self.config_data.get("server", {})
        return ClientServerConfig(
            host=server_conf.get("host", "193.168.195.34"),
            port=server_conf.get("port", 50000)
        )

    def get_web_config(self) -> ClientWebConfig:
        web_conf = self.config_data.get("web", {})
        return ClientWebConfig(
            host=web_conf.get("host", "127.0.0.1"),
            port=web_conf.get("port", 8000)
        )

    def get_data_dir(self) -> str:
        return self.config_data.get("data_dir", ".data/client")

    def get_database_config(self) -> ClientDatabaseConfig:
        db_conf = self.config_data.get("database", {})
        return ClientDatabaseConfig(
            name=db_conf.get("name", "client.db")
        )
