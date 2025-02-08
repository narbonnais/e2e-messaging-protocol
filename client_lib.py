# client_lib.py

import os
import sys
import socket
import logging
import base64
from pathlib import Path

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

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
    """
    Pull messages from server via raw TCP
    """
    try:
        private_path = get_key_path(identifier, True)
        public_path  = get_key_path(identifier, False)

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
        b64_signature     = base64.b64encode(signature).decode('utf-8')
        pull_cmd = f"PULL {b64_requester_pub} {b64_signature}\n"

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((server, port))
            s.sendall(pull_cmd.encode('utf-8'))
            resp = s.recv(65536).decode('utf-8', errors='ignore').strip()

        return resp
    except FileNotFoundError as e:
        return f"Error: {str(e)}"
