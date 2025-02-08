import os
import sys
import socket
import logging
import base64
import time
import sqlite3
from pathlib import Path
from typing import List, Tuple

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from ..common.lib import db_lock, init_client_db

def generate_keys(identifier: str):
    """
    Generate a 2048-bit RSA key pair, store in .data/<identifier>/
    """
    key_dir = Path(".data") / identifier
    key_dir.mkdir(parents=True, exist_ok=True)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    private_path = key_dir / "private_key.pem"
    public_path = key_dir / "public_key.pem"

    with private_path.open("wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    with public_path.open("wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
    print(f"Generated keys in {key_dir}/")
    print(f" - {private_path}")
    print(f" - {public_path}")

def import_public_key(identifier: str, public_key_path: str):
    """
    Import a public key for `identifier` into .data/<identifier>/public_key.pem
    """
    key_dir = Path(".data") / identifier
    key_dir.mkdir(parents=True, exist_ok=True)

    dest_path = key_dir / "public_key.pem"
    try:
        with open(public_key_path, "rb") as f:
            key_data = f.read()
            # Check it's a valid public key
            serialization.load_pem_public_key(key_data)

        with dest_path.open("wb") as f:
            f.write(key_data)
        print(f"Imported public key to {dest_path}")
    except Exception as e:
        print(f"Error importing key: {str(e)}")
        sys.exit(1)

def get_key_path(identifier: str, private: bool=False) -> Path:
    suffix = "private_key.pem" if private else "public_key.pem"
    p = Path(".data") / identifier / suffix
    if not p.exists():
        raise FileNotFoundError(f"No {'private' if private else 'public'} key for '{identifier}'")
    return p

def send_message(server: str, port: int,
                 sender_id: str, recipient_id: str,
                 message: str) -> str:
    """
    Send a message via raw TCP
    """
    try:
        sender_private = get_key_path(sender_id, private=True)
        recipient_public = get_key_path(recipient_id, private=False)

        with sender_private.open("rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with recipient_public.open("rb") as f:
            pub_key = serialization.load_pem_public_key(f.read())

        # Convert recipient pub to PEM bytes
        recipient_pub_pem = pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Encrypt
        ciphertext = pub_key.encrypt(
            message.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Sender's public key
        sender_pub_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # random nonce
        nonce = os.urandom(32)
        data_to_sign = recipient_pub_pem + ciphertext + nonce
        signature = private_key.sign(
            data_to_sign,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        b64_recipient_pub = base64.b64encode(recipient_pub_pem).decode('utf-8')
        b64_ciphertext    = base64.b64encode(ciphertext).decode('utf-8')
        b64_signature     = base64.b64encode(signature).decode('utf-8')
        b64_sender_pub    = base64.b64encode(sender_pub_pem).decode('utf-8')
        b64_nonce         = base64.b64encode(nonce).decode('utf-8')

        send_cmd = f"SEND {b64_recipient_pub} {b64_ciphertext} {b64_signature} {b64_sender_pub} {b64_nonce}\n"

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((server, port))
            s.sendall(send_cmd.encode('utf-8'))
            resp = s.recv(4096).decode('utf-8', errors='ignore').strip()
        return resp
    except FileNotFoundError as e:
        return f"Error: {str(e)}"

def pull_messages(server: str, port: int, identifier: str) -> str:
    """Pull messages from server via raw TCP and store decrypted ones."""
    try:
        # Initialize client DB if needed
        db_path = get_client_db_path(identifier)
        init_client_db(db_path)

        private_path = get_key_path(identifier, True)
        public_path = get_key_path(identifier, False)

        with private_path.open("rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with public_path.open("rb") as f:
            pub_key = serialization.load_pem_public_key(f.read())

        pub_pem = pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        signature = private_key.sign(
            pub_pem,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        b64_requester_pub = base64.b64encode(pub_pem).decode('utf-8')
        b64_signature = base64.b64encode(signature).decode('utf-8')
        pull_cmd = f"PULL {b64_requester_pub} {b64_signature}\n"

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((server, port))
            s.sendall(pull_cmd.encode('utf-8'))
            resp = s.recv(65536).decode('utf-8', errors='ignore').strip()

        # Parse and decrypt messages
        decrypted_messages = []
        if resp.startswith("ERROR:"):
            return resp
            
        # Remove "MESSAGES:" prefix if present
        if resp.startswith("MESSAGES:"):
            resp = resp[9:].strip()
            
        if resp:  # Only process if there are messages
            # Split response into individual messages
            messages = resp.split("\n")
            for msg in messages:
                if not msg:
                    continue
                try:
                    # Parse message parts
                    parts = msg.split("::")
                    if len(parts) != 2:
                        logging.warning(f"Invalid message format: {msg}")
                        continue
                        
                    b64_ciphertext, b64_sender_pub = parts
                    ciphertext = base64.b64decode(b64_ciphertext)
                    sender_pub_pem = base64.b64decode(b64_sender_pub)
                    
                    # Decrypt message
                    plaintext = private_key.decrypt(
                        ciphertext,
                        padding.OAEP(
                            mgf=padding.MGF1(hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    ).decode('utf-8')

                    # Get sender ID from their public key
                    sender_id = get_id_from_pubkey(sender_pub_pem)
                    decrypted_messages.append((sender_id, plaintext))
                    
                    # Store the decrypted message
                    store_decrypted_message(db_path, sender_id, plaintext)
                except Exception as e:
                    logging.error(f"Error decrypting message: {str(e)}")
                    continue

        if decrypted_messages:
            return f"Retrieved and stored {len(decrypted_messages)} messages"
        return "No new messages"

    except FileNotFoundError as e:
        return f"Error: {str(e)}"
    except Exception as e:
        logging.error(f"Error pulling messages: {str(e)}")
        return f"Error pulling messages: {str(e)}"

def get_id_from_pubkey(pub_key_pem: bytes) -> str:
    """Extract identifier from a public key by checking known keys."""
    key_dir = Path(".data")
    if not key_dir.exists():
        return "unknown"
    
    for user_dir in key_dir.iterdir():
        if not user_dir.is_dir():
            continue
        pub_key_path = user_dir / "public_key.pem"
        if pub_key_path.exists():
            with pub_key_path.open('rb') as f:
                if f.read() == pub_key_pem:
                    return user_dir.name
    return "unknown" 

def get_client_db_path(identifier: str) -> str:
    """Get the path to a client's message database."""
    db_dir = Path(".data") / identifier
    db_dir.mkdir(parents=True, exist_ok=True)
    return str(db_dir / "messages.db")

def store_decrypted_message(db_path: str, sender_id: str, message: str):
    """Store a decrypted message in the client's database."""
    with db_lock, sqlite3.connect(db_path) as conn:
        c = conn.cursor()
        c.execute("""
        INSERT INTO messages (sender_id, message, timestamp, received_time)
        VALUES (?, ?, ?, ?)
        """, (sender_id, message, time.time(), time.time()))
        conn.commit()

def get_messages(db_path: str, limit: int = 100) -> List[Tuple[str, str, float]]:
    """Retrieve stored messages from the client database."""
    with db_lock, sqlite3.connect(db_path) as conn:
        c = conn.cursor()
        c.execute("""
        SELECT sender_id, message, timestamp
        FROM messages
        ORDER BY timestamp DESC
        LIMIT ?
        """, (limit,))
        return c.fetchall()
