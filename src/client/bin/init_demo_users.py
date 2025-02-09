#!/usr/bin/env python3
import os
from pathlib import Path
import shutil
import logging
from ..client import generate_keys, import_public_key, get_client_db_path

def init_demo_users():
    """Initialize demo users Bob and Alice with keys and import their public keys to each other's contacts"""
    logging.basicConfig(level=logging.INFO)
    
    # Clean up existing data directory if it exists
    data_dir = Path(".data")
    if data_dir.exists():
        shutil.rmtree(data_dir)
    
    # Generate keys for both users
    users = ["alice", "bob"]
    for user in users:
        logging.info(f"Generating keys for {user}")
        generate_keys(user)
    
    # Import public keys to each other's contacts
    for user, other_user in [("alice", "bob"), ("bob", "alice")]:
        other_pub_key = data_dir / other_user / "public_key.pem"
        logging.info(f"Importing {other_user}'s public key to {user}'s contacts")
        import_public_key(other_user, str(other_pub_key), get_client_db_path(user))

    logging.info("Demo users initialized successfully!")
    logging.info("You can now use 'alice' or 'bob' as identifiers")

if __name__ == "__main__":
    init_demo_users() 