#!/usr/bin/env python3

import argparse
import base64
import logging
import os
import socket
import sqlite3
import sys
import threading
import time
from datetime import datetime, timedelta

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature

# =============================================================================
# Logging Setup
# =============================================================================

def setup_logging():
    """Configure logging for the server"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),       # Console handler
            logging.FileHandler('server.log', mode='a')  # File handler
        ]
    )

# =============================================================================
# Database Setup
# =============================================================================

DB_PATH = "messages.db"
db_lock = threading.Lock()

def init_db(db_path: str = DB_PATH):
    """
    Initialize the SQLite database if it doesn't exist.
    Create two tables:
        messages (unpulled)
        pulled_messages (pulled, for up to 7 days)
    """
    with db_lock, sqlite3.connect(db_path) as conn:
        c = conn.cursor()
        # Create tables if not exist
        c.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient_pub BLOB NOT NULL,
            ciphertext BLOB NOT NULL,
            sender_pub BLOB NOT NULL,
            signature BLOB NOT NULL,
            nonce BLOB NOT NULL,
            timestamp REAL NOT NULL
        );
        """)
        c.execute("""
        CREATE TABLE IF NOT EXISTS pulled_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient_pub BLOB NOT NULL,
            ciphertext BLOB NOT NULL,
            sender_pub BLOB NOT NULL,
            signature BLOB NOT NULL,
            nonce BLOB NOT NULL,
            timestamp REAL NOT NULL,
            pulled_time REAL NOT NULL
        );
        """)
        conn.commit()

def store_message(recipient_pub: bytes, ciphertext: bytes, sender_pub: bytes, signature: bytes, nonce: bytes):
    """
    Insert a new message into the 'messages' table
    """
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
        INSERT INTO messages (recipient_pub, ciphertext, sender_pub, signature, nonce, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (recipient_pub, ciphertext, sender_pub, signature, nonce, time.time()))
        conn.commit()
        conn.close()

def pull_and_move_messages(recipient_pub: bytes):
    """
    Pull all messages for `recipient_pub`, return them, and move them
    to the pulled_messages table with a 'pulled_time' set to now,
    then delete them from the 'messages' table.
    """
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        # SELECT all for that recipient
        c.execute("""
        SELECT id, ciphertext, sender_pub, signature, nonce, timestamp 
        FROM messages 
        WHERE recipient_pub = ?
        """, (recipient_pub,))
        rows = c.fetchall()

        # Move them to 'pulled_messages'
        pulled_rows = []
        for row in rows:
            msg_id, ciphertext, sender_pub, signature, nonce, msg_ts = row
            pulled_rows.append((recipient_pub, ciphertext, sender_pub, signature, nonce, msg_ts, time.time()))

        if pulled_rows:
            c.executemany("""
            INSERT INTO pulled_messages (recipient_pub, ciphertext, sender_pub, signature, nonce, timestamp, pulled_time)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, pulled_rows)
            # Delete them from messages
            message_ids = [str(r[0]) for r in rows]
            c.execute(f"DELETE FROM messages WHERE id IN ({','.join(message_ids)})")

        conn.commit()
        conn.close()

        # Return the rows we found
        return rows

def cleanup_old_pulled_messages():
    """
    Delete from 'pulled_messages' all messages older than 7 days.
    'pulled_time' + 7 days < now => delete
    """
    seven_days_ago = time.time() - (7 * 24 * 3600)
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
        DELETE FROM pulled_messages 
        WHERE pulled_time < ?
        """, (seven_days_ago,))
        deleted_count = c.rowcount
        conn.commit()
        conn.close()
    if deleted_count > 0:
        logging.info(f"Cleanup: Deleted {deleted_count} old pulled messages")

# =============================================================================
# Server Code
# =============================================================================

def verify_signature(public_key_pem: bytes, signature: bytes, message: bytes) -> None:
    """
    Verifies that 'signature' matches 'message' using the public key in PEM format.
    
    Args:
        public_key_pem: Public key in PEM format
        signature: The signature to verify
        message: The original message that was signed
        
    Raises:
        InvalidSignature: If signature verification fails
        Exception: For other cryptographic errors
    """
    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
        public_key.verify(
            signature,
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    except InvalidSignature:
        logging.warning("Invalid signature detected")
        raise
    except Exception as e:
        logging.error(f"Error verifying signature: {str(e)}")
        raise

def handle_send(data_tokens):
    """
    data_tokens: ["SEND", <recipient_pub>, <ciphertext>, <signature>, <sender_pub>, <nonce>]
    All base64-encoded strings except the "SEND" literal.
    """
    if len(data_tokens) != 6:
        logging.error(f"Invalid SEND command format. Got {len(data_tokens)} tokens instead of 6")
        return b"ERROR: Invalid SEND command format\n"

    _, b64_recipient_pub, b64_ciphertext, b64_signature, b64_sender_pub, b64_nonce = data_tokens

    try:
        recipient_pub = base64.b64decode(b64_recipient_pub)
        ciphertext    = base64.b64decode(b64_ciphertext)
        signature     = base64.b64decode(b64_signature)
        sender_pub    = base64.b64decode(b64_sender_pub)
        nonce        = base64.b64decode(b64_nonce)
    except Exception as e:
        logging.error(f"Base64 decode failed in SEND: {str(e)}")
        return b"ERROR: Base64 decode failed\n"

    # 1) Verify signature using sender_pub as the public key
    try:
        message_for_sig = recipient_pub + ciphertext + nonce
        verify_signature(sender_pub, signature, message_for_sig)
    except InvalidSignature:
        logging.warning(f"Invalid signature in SEND command from {sender_pub[:20]}...")
        return b"ERROR: Invalid signature\n"
    except Exception as e:
        logging.error(f"Error processing signature in SEND: {str(e)}")
        return f"ERROR: Signature verification failed: {str(e)}\n".encode('utf-8')

    # 2) Store the message in the DB
    store_message(recipient_pub, ciphertext, sender_pub, signature, nonce)
    logging.info(f"Stored message for recipient {recipient_pub[:20]}... from sender {sender_pub[:20]}...")
    return b"OK: Message stored\n"

def handle_pull(data_tokens):
    """
    data_tokens: ["PULL", <requester_pub>, <signature>]
    The user wants to pull messages for <requester_pub>. The signature
    must verify that the holder of the private key corresponding to
    <requester_pub> is making the request.
    """
    if len(data_tokens) != 3:
        logging.error(f"Invalid PULL command format. Got {len(data_tokens)} tokens instead of 3")
        return b"ERROR: Invalid PULL command format\n"

    _, b64_requester_pub, b64_signature = data_tokens

    try:
        requester_pub = base64.b64decode(b64_requester_pub)
        signature     = base64.b64decode(b64_signature)
    except Exception as e:
        logging.error(f"Base64 decode failed in PULL: {str(e)}")
        return b"ERROR: Base64 decode failed\n"

    # Verify the signature using requester's public key
    try:
        verify_signature(requester_pub, signature, requester_pub)
    except InvalidSignature:
        logging.warning(f"Invalid signature in PULL command from {requester_pub[:20]}...")
        return b"ERROR: Invalid signature\n"
    except Exception as e:
        logging.error(f"Error processing signature in PULL: {str(e)}")
        return f"ERROR: Signature verification failed: {str(e)}\n".encode('utf-8')

    # Pull messages from the DB
    rows = pull_and_move_messages(requester_pub)
    if not rows:
        return b"OK: No messages\n"

    # Return them as lines in base64 for ciphertext + sender_pub
    lines = []
    for row in rows:
        msg_id, ciphertext, sender_pub_data, sig, nonce, ts = row
        ciph_b64 = base64.b64encode(ciphertext).decode('utf-8')
        spub_b64 = base64.b64encode(sender_pub_data).decode('utf-8')
        lines.append(ciph_b64 + "::" + spub_b64)

    logging.info(f"Delivered {len(rows)} messages to {requester_pub[:20]}...")
    resp = "MESSAGES:\n" + "\n".join(lines) + "\n"
    return resp.encode('utf-8')

def _read_line(conn):
    """
    Read data from conn until we encounter a newline (\n) or end of stream.
    Ensures we get the full command line.
    """
    data_chunks = []
    while True:
        chunk = conn.recv(1024)
        if not chunk:
            # No more data from client
            break
        data_chunks.append(chunk)
        if b'\n' in chunk:
            break
    data = b''.join(data_chunks)
    return data.decode('utf-8', errors='ignore').strip()

def client_handler(conn: socket.socket, addr: tuple) -> None:
    """
    Handle a client connection with timeout and better error handling.
    
    Args:
        conn: Client socket connection
        addr: Client address tuple (host, port)
    """
    try:
        # Set timeout to prevent hanging connections
        conn.settimeout(30)  # 30 second timeout
        logging.info(f"New connection from {addr}")
        
        data = _read_line(conn)
        if not data:
            logging.warning(f"Empty data received from {addr}")
            conn.sendall(b"ERROR: Empty request\n")
            return
            
        logging.info(f"Raw data received: {data!r}")
        tokens = data.split()

        if not tokens:
            logging.warning(f"Empty command from {addr}")
            conn.sendall(b"ERROR: No command\n")
            return

        cmd = tokens[0].upper()
        logging.info(f"Received {cmd} command from {addr}")

        if cmd == "SEND":
            resp = handle_send(tokens)
        elif cmd == "PULL":
            resp = handle_pull(tokens)
        else:
            logging.warning(f"Unknown command '{cmd}' from {addr}")
            resp = b"ERROR: Unknown command\n"

        conn.sendall(resp)

    except socket.timeout:
        logging.error(f"Connection timeout from {addr}")
        conn.sendall(b"ERROR: Connection timeout\n")
    except Exception as e:
        logging.error(f"Error handling client {addr}: {str(e)}")
        msg = f"ERROR: Exception: {str(e)}\n".encode('utf-8')
        conn.sendall(msg)
    finally:
        conn.close()
        logging.info(f"Closed connection from {addr}")

def run_server(host: str, port: int) -> None:
    """Run the server with graceful shutdown."""
    setup_logging()
    logging.info(f"Starting server on {host}:{port}")

    # Initialize the DB
    init_db(DB_PATH)
    
    # For graceful shutdown
    shutdown_event = threading.Event()

    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((host, port))
        server_socket.listen(5)
        print(f"Server listening on {host}:{port}...")

        # Start cleanup thread
        def cleanup_loop():
            while not shutdown_event.is_set():
                time.sleep(3600)  # Every hour
                try:
                    cleanup_old_pulled_messages()
                except Exception as e:
                    logging.error(f"Error in cleanup: {str(e)}")

        cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
        cleanup_thread.start()
        logging.info("Started cleanup thread")

        while not shutdown_event.is_set():
            try:
                conn, addr = server_socket.accept()
                t = threading.Thread(target=client_handler, args=(conn, addr), daemon=True)
                t.start()
            except KeyboardInterrupt:
                logging.info("Received shutdown signal")
                shutdown_event.set()
                break

    except Exception as e:
        logging.critical(f"Fatal server error: {str(e)}")
        raise
    finally:
        logging.info("Shutting down server...")
        server_socket.close()

# =============================================================================
# Client Code
# =============================================================================

def load_private_key(filepath):
    with open(filepath, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key(filepath):
    with open(filepath, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def get_key_path(identifier, key_type="public"):
    """
    Returns path to a key file for given identifier.
    key_type can be "public" or "private"
    """
    key_dir = os.path.join(".data", identifier)
    key_path = os.path.join(key_dir, f"{key_type}_key.pem")
    if not os.path.exists(key_path):
        raise FileNotFoundError(f"No {key_type} key found for '{identifier}'. "
                                f"Did you generate or import it?")
    return key_path

def send_message(server, port, sender_id, recipient_id, message):
    """
    Send message using sender's private key and recipient's public key
    """
    try:
        sender_private_key_path    = get_key_path(sender_id, "private")
        recipient_public_key_path  = get_key_path(recipient_id, "public")
        
        # Load keys
        sender_private_key    = load_private_key(sender_private_key_path)
        recipient_public_key  = load_public_key(recipient_public_key_path)
        
        # Convert entire public key to PEM bytes
        recipient_pub_pem_bytes = recipient_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Encrypt message
        ciphertext = recipient_public_key.encrypt(
            message.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Sender's public key in PEM
        sender_public_key_pem = sender_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Generate random nonce
        nonce = os.urandom(32)  # 256 bits of randomness

        # Create signature over (recipient_pub_pem + ciphertext + nonce)
        message_for_sig = recipient_pub_pem_bytes + ciphertext + nonce
        signature = sender_private_key.sign(
            message_for_sig,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        # Base64 everything
        b64_recipient_pub = base64.b64encode(recipient_pub_pem_bytes).decode('utf-8').replace('\n', '')
        b64_ciphertext    = base64.b64encode(ciphertext).decode('utf-8').replace('\n', '')
        b64_signature     = base64.b64encode(signature).decode('utf-8').replace('\n', '')
        b64_sender_pub    = base64.b64encode(sender_public_key_pem).decode('utf-8').replace('\n', '')
        b64_nonce        = base64.b64encode(nonce).decode('utf-8').replace('\n', '')
        
        send_command = f"SEND {b64_recipient_pub} {b64_ciphertext} {b64_signature} {b64_sender_pub} {b64_nonce}\n"

        # Send to server
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((server, port))
            s.sendall(send_command.encode('utf-8'))
            response = s.recv(4096).decode('utf-8', errors='ignore').strip()
            return response  # Return raw response

    except FileNotFoundError as e:
        return f"Error: {str(e)}"  # Return error message

def pull_messages(server, port, identifier):
    """
    Pull messages using your private/public key
    """
    try:
        private_key_path = get_key_path(identifier, "private")
        public_key_path  = get_key_path(identifier, "public")
        
        private_key = load_private_key(private_key_path)
        pub_key     = load_public_key(public_key_path)
        
        # Convert public key to PEM bytes
        pub_key_pem_bytes = pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Sign raw pub_key_pem_bytes
        signature = private_key.sign(
            pub_key_pem_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        b64_requester_pub = base64.b64encode(pub_key_pem_bytes).decode('utf-8').replace('\n', '')
        b64_signature     = base64.b64encode(signature).decode('utf-8').replace('\n', '')

        pull_command = f"PULL {b64_requester_pub} {b64_signature}\n"

        # Send to server
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((server, port))
            s.sendall(pull_command.encode('utf-8'))
            response = s.recv(65536).decode('utf-8', errors='ignore').strip()

            if not response.startswith("MESSAGES:"):
                # Possibly "OK: No messages" or error
                return response

            # Process lines
            lines = response.splitlines()[1:]  # skip "MESSAGES:" line
            messages = []
            for line in lines:
                if "::" not in line:
                    continue
                ciph_b64, spub_b64 = line.split("::")
                ciphertext = base64.b64decode(ciph_b64)
                sender_pub_data = base64.b64decode(spub_b64)

                # Decrypt
                try:
                    plaintext = private_key.decrypt(
                        ciphertext,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    plaintext_str = plaintext.decode('utf-8', errors='ignore')
                except Exception as e:
                    plaintext_str = f"(Error decrypting: {str(e)})"

                messages.append({
                    'from': sender_pub_data.decode('utf-8', errors='ignore'),
                    'message': plaintext_str
                })

            if not messages:
                return "OK: No messages"
            
            # Format output
            output = []
            for msg in messages:
                output.extend([
                    "=== New Message ===",
                    f"From: {msg['from']}",
                    f"Decrypted message: {msg['message']}",
                    "==================="
                ])
            return "\n".join(output)

    except FileNotFoundError as e:
        return f"Error: {str(e)}"

def generate_keys(identifier):
    """
    Generates a 2048-bit RSA key pair, saving to
        .data/<identifier>/private_key.pem
        .data/<identifier>/public_key.pem
    """
    key_dir = os.path.join(".data", identifier)
    os.makedirs(key_dir, exist_ok=True)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    private_key_path = os.path.join(key_dir, "private_key.pem")
    with open(private_key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    public_key_path = os.path.join(key_dir, "public_key.pem")
    with open(public_key_path, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    print(f"Generated keys in {key_dir}/")
    print(f"  - {private_key_path}")
    print(f"  - {public_key_path}")

def import_public_key(identifier, public_key_path):
    """
    Imports a public key into .data/<identifier>/public_key.pem
    Verifies it's a valid public key first.
    """
    try:
        with open(public_key_path, "rb") as f:
            key_data = f.read()
            serialization.load_pem_public_key(key_data)  # verify valid

        key_dir = os.path.join(".data", identifier)
        os.makedirs(key_dir, exist_ok=True)
        
        dest_path = os.path.join(key_dir, "public_key.pem")
        with open(dest_path, "wb") as f:
            f.write(key_data)
            
        print(f"Imported public key to {dest_path}")
    except Exception as e:
        print(f"Error importing key: {str(e)}")
        sys.exit(1)

# =============================================================================
# Main Entry
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Simple E2E Encrypted Messenger with SQLite DB"
    )
    subparsers = parser.add_subparsers(dest="mode", help="Mode of operation")

    # Subparser: generate_keys
    gen_parser = subparsers.add_parser("generate_keys", help="Generate RSA key pair")
    gen_parser.add_argument("--id", required=True, help="Identifier for the key pair (e.g. 'alice')")

    # Subparser: import_key
    import_parser = subparsers.add_parser("import_key", help="Import someone's public key")
    import_parser.add_argument("--id", required=True, help="Identifier for the contact (e.g. 'bob')")
    import_parser.add_argument("--public_key", required=True, help="Path to the public key to import")

    # Subparser: server
    server_parser = subparsers.add_parser("server", help="Run in server mode")
    server_parser.add_argument("--host", default="127.0.0.1", help="Host to bind")
    server_parser.add_argument("--port", type=int, default=5000, help="Port to bind")

    # Subparser: client
    client_parser = subparsers.add_parser("client", help="Run in client mode")
    client_sub = client_parser.add_subparsers(dest="client_cmd", help="Client command")

    client_send_parser = client_sub.add_parser("send", help="Send a message")
    client_send_parser.add_argument("--server", required=True, help="Server IP or hostname")
    client_send_parser.add_argument("--port", type=int, required=True, help="Server port")
    client_send_parser.add_argument("--sender", required=True, help="Your identifier (e.g. 'alice')")
    client_send_parser.add_argument("--recipient", required=True, help="Recipient's identifier (e.g. 'bob')")
    client_send_parser.add_argument("--message", required=True, help="Message to send")

    client_pull_parser = client_sub.add_parser("pull", help="Pull messages")
    client_pull_parser.add_argument("--server", required=True, help="Server IP or hostname")
    client_pull_parser.add_argument("--port", type=int, required=True, help="Server port")
    client_pull_parser.add_argument("--id", required=True, help="Your identifier (e.g. 'alice')")

    args = parser.parse_args()

    if args.mode == "generate_keys":
        generate_keys(args.id)
    elif args.mode == "import_key":
        import_public_key(args.id, args.public_key)
    elif args.mode == "server":
        run_server(args.host, args.port)
    elif args.mode == "client":
        if args.client_cmd == "send":
            response = send_message(
                args.server, args.port,
                args.sender,
                args.recipient,
                args.message
            )
            print("Server response:", response)
        elif args.client_cmd == "pull":
            response = pull_messages(
                args.server, args.port,
                args.id
            )
            print(response)
        else:
            print("Unknown client command")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
