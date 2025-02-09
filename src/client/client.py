import os
import sys
import socket
import logging
import base64
import time
import sqlite3
import threading
from pathlib import Path
from typing import List, Tuple
import yaml

# Import all crypto functions we need
from ..common.crypto_service import CryptoService

# Import protocol functions
from ..common.client_server_protocol import (
    create_send_command, create_pull_command,
    parse_pull_response, parse_send_response
)

# Add this at the top level
db_lock = threading.Lock()

crypto_service = CryptoService()


def load_config(config_path: str = None) -> dict:
    """Load client configuration from YAML file"""
    default_config = Path("config/client_default.yaml")

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


config = load_config()
DATA_DIR = Path(config['data_dir'])


def generate_keys(identifier: str):
    """
    Generate a 2048-bit RSA key pair, store in .data/<identifier>/
    """
    key_dir = DATA_DIR / identifier
    key_dir.mkdir(parents=True, exist_ok=True)

    private_key = crypto_service.generate_key_pair()
    public_key = private_key.public_key()

    private_path = key_dir / "private_key.pem"
    public_path = key_dir / "public_key.pem"

    with private_path.open("wb") as f:
        f.write(crypto_service.serialize_private_key(private_key))
    with public_path.open("wb") as f:
        f.write(crypto_service.serialize_public_key(public_key))

    # Initialize the database with default config when generating new keys
    db_path = get_client_db_path(identifier)
    init_client_db(db_path)

    # Update server config from YAML defaults
    server_config = config.get('server', {})
    update_server_config(
        db_path,
        server_config.get('host', '127.0.0.1'),
        server_config.get('port', 50000)
    )

    print(f"Generated keys in {key_dir}/")
    print(f" - {private_path}")
    print(f" - {public_path}")


def import_public_key(
        identifier: str,
        public_key_path: str,
        db_path: str = None):
    """
    Import a public key for `identifier` into contacts database
    """
    try:
        with open(public_key_path, "rb") as f:
            key_data = f.read()
            # Check it's a valid public key
            crypto_service.load_public_key(key_data)

        if db_path is None:
            # Get current user's DB path from the directory structure
            data_dir = DATA_DIR
            user_dirs = [d for d in data_dir.iterdir() if d.is_dir()]
            if not user_dirs:
                raise Exception(
                    "No local user found. Generate a key pair first.")
            db_path = get_client_db_path(user_dirs[0].name)

        # Initialize database if needed
        init_client_db(db_path)

        # Store in database
        if store_contact(db_path, identifier, key_data):
            return f"Imported public key for {identifier}"
        else:
            raise Exception("Failed to store contact in database")
    except Exception as e:
        raise Exception(f"Error importing key: {str(e)}")


def get_key_path(identifier: str, private: bool = False) -> Path:
    suffix = "private_key.pem" if private else "public_key.pem"
    p = DATA_DIR / identifier / suffix
    if not p.exists():
        raise FileNotFoundError(
            f"No {'private' if private else 'public'} key for '{identifier}'")
    return p


def send_message(server: str, port: int,
                 sender_id: str, recipient_id: str,
                 message: str) -> str:
    """
    Send a message via raw TCP
    """
    try:
        # Get recipient's public key from contacts database
        db_path = get_client_db_path(sender_id)
        recipient_pub_key = get_contact_pubkey(db_path, recipient_id)

        if not recipient_pub_key:
            return f"Error: No public key found for '{recipient_id}' in contacts database. Please import their public key first."

        # Get sender's private key from filesystem
        sender_private = get_key_path(sender_id, private=True)
        with sender_private.open("rb") as f:
            private_key = crypto_service.load_private_key(f.read())

        # Create send command using protocol
        send_cmd, ciphertext = create_send_command(
            private_key, recipient_pub_key, message)

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)  # Set 5 second timeout
                s.connect((server, port))
                s.sendall(send_cmd.encode('utf-8'))
                resp = s.recv(4096).decode('utf-8', errors='ignore').strip()

                success, msg = parse_send_response(resp)
                if success:
                    # Store message locally
                    db_path = get_client_db_path(sender_id)
                    init_client_db(db_path)
                    store_decrypted_message(
                        db_path, crypto_service.serialize_public_key(
                            private_key.public_key()), recipient_pub_key, message)
                return msg

        except socket.timeout:
            return "Error: Connection to server timed out"
        except ConnectionRefusedError:
            return "Error: Connection refused"
        except socket.gaierror:
            return "Error: Could not resolve server address"
        except Exception as e:
            return f"Error connecting to server: {str(e)}"

    except Exception as e:
        logging.error(f"Error in send_message: {str(e)}")
        return f"Error sending message: {str(e)}"


def pull_messages(server: str, port: int, identifier: str) -> str:
    """Pull messages from server via raw TCP and store decrypted ones."""
    try:
        # Initialize client DB if needed
        db_path = get_client_db_path(identifier)
        init_client_db(db_path)

        # Get private key
        private_path = get_key_path(identifier, True)
        with private_path.open("rb") as f:
            private_key = crypto_service.load_private_key(f.read())

        # Create pull command using protocol
        pull_cmd = create_pull_command(private_key)

        # Send request
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((server, port))
            s.sendall(pull_cmd.encode('utf-8'))
            resp = s.recv(65536).decode('utf-8', errors='ignore').strip()

        # Parse response and store messages
        messages = parse_pull_response(resp, private_key)

        # Store decrypted messages
        pub_pem = crypto_service.serialize_public_key(private_key.public_key())
        for sender_pub_pem, plaintext in messages:
            store_decrypted_message(
                db_path, sender_pub_pem, pub_pem, plaintext)

        if messages:
            return f"Retrieved and stored {len(messages)} messages"
        return "No new messages"

    except FileNotFoundError as e:
        return f"Error: {str(e)}"
    except Exception as e:
        logging.error(f"Error pulling messages: {str(e)}")
        return f"Error pulling messages: {str(e)}"


def get_id_from_pubkey(pub_key_pem: bytes) -> str:
    """Extract identifier from a public key by checking known keys."""
    key_dir = DATA_DIR
    if not key_dir.exists():
        return "unknown"

    # Normalize the input public key by loading and re-encoding it
    try:
        pub_key = crypto_service.load_public_key(pub_key_pem)
        normalized_pem = crypto_service.serialize_public_key(pub_key)
    except Exception:
        return "unknown"

    for user_dir in key_dir.iterdir():
        if not user_dir.is_dir():
            continue
        pub_key_path = user_dir / "public_key.pem"
        if pub_key_path.exists():
            try:
                with pub_key_path.open('rb') as f:
                    stored_key = crypto_service.load_public_key(f.read())
                    stored_pem = crypto_service.serialize_public_key(
                        stored_key)
                    if stored_pem == normalized_pem:
                        return user_dir.name.lower()  # Return lowercase ID
            except Exception:
                continue
    return "unknown"


def get_client_db_path(identifier: str) -> str:
    """Get the path to a client's message database."""
    db_dir = DATA_DIR / identifier
    db_dir.mkdir(parents=True, exist_ok=True)
    return str(db_dir / config['database']['name'])


def store_decrypted_message(
        db_path: str,
        sender_pubkey: bytes,
        recipient_pubkey: bytes,
        message: str):
    """Store a decrypted message in the client's database."""
    with db_lock, sqlite3.connect(db_path) as conn:
        c = conn.cursor()
        c.execute("""
        INSERT INTO messages (sender_pubkey, recipient_pubkey, message, timestamp, received_time)
        VALUES (?, ?, ?, ?, ?)
        """, (sender_pubkey.decode('utf-8'), recipient_pubkey.decode('utf-8'),
              message, time.time(), time.time()))
        conn.commit()


def get_messages(
        db_path: str, limit: int = 100) -> List[Tuple[str, str, str, float]]:
    """Retrieve stored messages from the client database."""
    with db_lock, sqlite3.connect(db_path) as conn:
        c = conn.cursor()
        c.execute("""
        SELECT sender_pubkey, recipient_pubkey, message, timestamp
        FROM messages
        ORDER BY timestamp DESC
        LIMIT ?
        """, (limit,))
        return c.fetchall()


def init_client_db(db_path: str):
    """Initialize the client database with messages, contacts, and config tables."""
    with db_lock, sqlite3.connect(db_path) as conn:
        c = conn.cursor()
        # Messages table - store public keys instead of IDs
        c.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_pubkey TEXT NOT NULL,
            recipient_pubkey TEXT NOT NULL,
            message TEXT NOT NULL,
            timestamp REAL NOT NULL,
            received_time REAL NOT NULL
        )
        """)
        # Contacts table remains the same
        c.execute("""
        CREATE TABLE IF NOT EXISTS contacts (
            id TEXT PRIMARY KEY,
            public_key_pem TEXT NOT NULL,
            added_time REAL NOT NULL
        )
        """)
        # Add config table
        c.execute("""
        CREATE TABLE IF NOT EXISTS config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """)

        # Insert default server settings if they don't exist
        c.execute("""
        INSERT OR IGNORE INTO config (key, value)
        VALUES
            ('server_host', '127.0.0.1'),
            ('server_port', '50000')
        """)
        conn.commit()


def store_contact(
        db_path: str,
        contact_id: str,
        public_key_pem: bytes) -> bool:
    """Store or update a contact's public key in the database."""
    with db_lock, sqlite3.connect(db_path) as conn:
        c = conn.cursor()
        try:
            c.execute("""
            INSERT OR REPLACE INTO contacts (id, public_key_pem, added_time)
            VALUES (?, ?, ?)
            """, (contact_id, public_key_pem.decode('utf-8'), time.time()))
            conn.commit()
            return True
        except Exception as e:
            logging.error(f"Error storing contact: {str(e)}")
            return False


def get_contacts(db_path: str) -> List[str]:
    """Get list of contact IDs from the database."""
    with db_lock, sqlite3.connect(db_path) as conn:
        c = conn.cursor()
        c.execute("SELECT id FROM contacts ORDER BY id")
        return [row[0] for row in c.fetchall()]


def get_contact_pubkey(db_path: str, contact_id: str) -> bytes:
    """Get a contact's public key from the database."""
    with db_lock, sqlite3.connect(db_path) as conn:
        c = conn.cursor()
        # Use LOWER() for case-insensitive comparison
        c.execute(
            "SELECT public_key_pem FROM contacts WHERE LOWER(id) = LOWER(?)", (contact_id,))
        result = c.fetchone()
        if result:
            # Convert string to bytes before returning
            return result[0].encode('utf-8')
        return None


def fix_message_case(db_path: str):
    """One-time fix for message ID casing."""
    with db_lock, sqlite3.connect(db_path) as conn:
        c = conn.cursor()
        c.execute("""
        UPDATE messages
        SET sender_id = LOWER(sender_id),
            recipient_id = LOWER(recipient_id)
        """)
        conn.commit()


def get_server_config(db_path: str) -> tuple:
    """Get server host and port from config."""
    with db_lock, sqlite3.connect(db_path) as conn:
        c = conn.cursor()
        c.execute("SELECT value FROM config WHERE key = 'server_host'")
        host = c.fetchone()[0]
        c.execute("SELECT value FROM config WHERE key = 'server_port'")
        port = int(c.fetchone()[0])
        return host, port


def update_server_config(db_path: str, host: str, port: int) -> bool:
    """Update server configuration."""
    try:
        with db_lock, sqlite3.connect(db_path) as conn:
            c = conn.cursor()
            c.execute(
                "UPDATE config SET value = ? WHERE key = 'server_host'", (host,))
            c.execute(
                "UPDATE config SET value = ? WHERE key = 'server_port'", (str(port),))
            conn.commit()
        return True
    except Exception as e:
        logging.error(f"Error updating server config: {str(e)}")
        return False
