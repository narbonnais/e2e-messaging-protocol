import yaml
from pathlib import Path
from typing import Any, Dict, Optional
from dataclasses import dataclass
import logging


@dataclass
class DatabaseConfig:
    """Database configuration settings"""
    path: str
    name: str = "messages.db"
    cleanup_interval: int = 3600  # 1 hour
    retention_days: int = 30
    max_connections: int = 10


@dataclass
class ServerConfig:
    """Server configuration settings"""
    host: str = "127.0.0.1"
    port: int = 50000
    timeout: int = 30
    max_connections: int = 5
    buffer_size: int = 4096


@dataclass
class LoggingConfig:
    """Logging configuration settings"""
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file: Optional[str] = None


class ConfigService:
    """Service for managing application configuration"""

    _instance = None  # Singleton instance

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not hasattr(self, 'initialized'):
            self.config_dir = Path("config")
            # Initialize with default configuration
            self.loaded_config = {
                'database': {
                    'path': '.data/server/server.db',
                    'name': 'messages.db',
                    'cleanup_interval': 3600,
                    'retention_days': 7,
                    'max_connections': 10},
                'tcp_server': {
                    'host': '127.0.0.1',
                    'port': 50000,
                    'timeout': 30,
                    'max_connections': 5,
                    'buffer_size': 4096},
                'web_server': {
                    'host': '127.0.0.1',
                    'port': 8001},
                'logging': {
                    'level': 'INFO',
                    'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    'file': None}}
            self.initialized = True
            self._setup_logging()

    def _setup_logging(self):
        self.logger = logging.getLogger(__name__)

    def load_config(self, config_path: Optional[str] = None) -> None:
        """
        Load configuration from files

        Args:
            config_path: Optional path to custom config file
        """
        try:
            # Load default config
            default_config = self.config_dir / "server_default.yaml"
            if default_config.exists():
                with open(default_config) as f:
                    custom_config = yaml.safe_load(f)
                    self._deep_update(self.loaded_config, custom_config)

            # Override with custom config if provided
            if config_path and Path(config_path).exists():
                with open(config_path) as f:
                    custom_config = yaml.safe_load(f)
                    self._deep_update(self.loaded_config, custom_config)

            # Validate configuration
            self._validate_config()

            # Setup logging based on config
            self._configure_logging()

        except Exception as e:
            raise ConfigurationError(f"Error loading configuration: {str(e)}")

    def _deep_update(self, base_dict: dict, update_dict: dict) -> None:
        """Recursively update a dictionary"""
        for key, value in update_dict.items():
            if (
                key in base_dict
                and isinstance(base_dict[key], dict)
                and isinstance(value, dict)
            ):
                self._deep_update(base_dict[key], value)
            else:
                base_dict[key] = value

    def _validate_config(self) -> None:
        """Validate configuration values"""
        # Validate database config
        db_config = self.loaded_config['database']
        if not db_config.get('path'):
            db_config['path'] = 'data/messages.db'

        # Validate server config
        server_config = self.loaded_config['tcp_server']
        if 'port' in server_config:
            port = server_config['port']
            if not isinstance(port, int) or port < 1 or port > 65535:
                raise ConfigurationError(f"Invalid port number: {port}")

    def _configure_logging(self) -> None:
        """Configure logging based on settings"""
        log_config = self.loaded_config.get('logging', {})
        logging.basicConfig(
            level=getattr(
                logging,
                log_config.get(
                    'level',
                    'INFO')),
            format=log_config.get(
                'format',
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'),
            filename=log_config.get('file'))

    def get_database_config(self) -> DatabaseConfig:
        """Get database configuration"""
        db_config = self.loaded_config.get('database', {})
        return DatabaseConfig(
            path=db_config.get('path', 'data/messages.db'),
            name=db_config.get('name', 'messages.db'),
            cleanup_interval=db_config.get('cleanup_interval', 3600),
            retention_days=db_config.get('retention_days', 30),
            max_connections=db_config.get('max_connections', 10)
        )

    def get_server_config(self) -> ServerConfig:
        """Get server configuration"""
        server_config = self.loaded_config.get('tcp_server', {})
        return ServerConfig(
            host=server_config.get('host', '127.0.0.1'),
            port=server_config.get('port', 50000),
            timeout=server_config.get('timeout', 30),
            max_connections=server_config.get('max_connections', 5),
            buffer_size=server_config.get('buffer_size', 4096)
        )

    def get_logging_config(self) -> LoggingConfig:
        """Get logging configuration"""
        log_config = self.loaded_config.get('logging', {})
        return LoggingConfig(
            level=log_config.get(
                'level',
                'INFO'),
            format=log_config.get(
                'format',
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'),
            file=log_config.get('file'))

    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value by key"""
        try:
            value = self.loaded_config
            for k in key.split('.'):
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default


class ConfigurationError(Exception):
    """Raised when there is a configuration error"""
    pass
