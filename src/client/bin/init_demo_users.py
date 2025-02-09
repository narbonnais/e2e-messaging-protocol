#!/usr/bin/env python3
import os
from pathlib import Path
import shutil
import logging
from ..client import generate_keys, import_public_key, get_client_db_path, load_config


def init_data_dirs():
    """Initialize the data directory structure"""
    data_dir = Path(".data")
    client_dir = data_dir / "client"
    server_dir = data_dir / "server"

    # Clean up existing data directory if it exists
    if data_dir.exists():
        shutil.rmtree(data_dir)

    # Create new directory structure
    client_dir.mkdir(parents=True)
    server_dir.mkdir(parents=True)

    logging.info(f"Created data directories:")
    logging.info(f" - {client_dir}")
    logging.info(f" - {server_dir}")


def init_demo_users():
    """Initialize demo users local-bob and local-alice with keys and import their public keys to each other's contacts"""
    logging.basicConfig(level=logging.INFO)

    # Initialize directory structure
    init_data_dirs()

    # Generate keys for both users
    users = ["local-alice", "local-bob"]
    for user in users:
        logging.info(f"Generating keys for {user}")
        generate_keys(user)

    # Import public keys to each other's contacts
    config = load_config()
    data_dir = Path(config['data_dir'])
    for user, other_user in [
            ("local-alice", "local-bob"), ("local-bob", "local-alice")]:
        other_pub_key = data_dir / other_user / "public_key.pem"
        logging.info(
            f"Importing {other_user}'s public key to {user}'s contacts")
        import_public_key(
            other_user,
            str(other_pub_key),
            get_client_db_path(user))

    logging.info("Demo users initialized successfully!")
    logging.info("You can now use 'local-alice' or 'local-bob' as identifiers")


if __name__ == "__main__":
    init_demo_users()
