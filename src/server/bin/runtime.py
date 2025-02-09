import argparse
import logging
import sys
import yaml
from pathlib import Path

from ..server import run_server

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('.data/server/server.log', mode='a')
        ]
    )

def load_config(config_path: str = None) -> dict:
    """Load server configuration from YAML file"""
    default_config = Path("config/server_default.yaml")
    
    if not default_config.exists():
        raise FileNotFoundError(f"Default config not found at {default_config}")
        
    with open(default_config) as f:
        config = yaml.safe_load(f)
    
    if config_path and Path(config_path).exists():
        with open(config_path) as f:
            custom_config = yaml.safe_load(f)
            config.update(custom_config)
            
    return config

def main():
    parser = argparse.ArgumentParser(description="Raw TCP server runtime")
    parser.add_argument("--config", help="Path to config file")
    parser.add_argument("--host", help="Override host to bind")
    parser.add_argument("--port", type=int, help="Override port to bind")
    args = parser.parse_args()

    # Ensure server data directory exists
    server_dir = Path(".data/server")
    server_dir.mkdir(parents=True, exist_ok=True)

    setup_logging()
    
    config = load_config(args.config)
    tcp_config = config['tcp_server']
    
    # Command line args override config file
    host = args.host or tcp_config['host']
    port = args.port or tcp_config['port']
    
    run_server(host, port)

if __name__ == "__main__":
    main()
