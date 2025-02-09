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
        raise FileNotFoundError(
            f"Default config not found at {default_config}")

    with open(default_config) as f:
        config = yaml.safe_load(f)

    if config_path and Path(config_path).exists():
        with open(config_path) as f:
            custom_config = yaml.safe_load(f)
            config.update(custom_config)

    return config


def main():
    parser = argparse.ArgumentParser(description='Start the messaging server')
    parser.add_argument('--host', help='Server host')
    parser.add_argument('--port', type=int, help='Server port')
    args = parser.parse_args()

    run_server(args.host, args.port)


if __name__ == "__main__":
    main()
