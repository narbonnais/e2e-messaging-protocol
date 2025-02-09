import logging
import socket
import threading
import base64
import time
import os
import sqlite3
from datetime import datetime
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
import yaml
from pathlib import Path

db_lock = threading.Lock()

def load_config(config_path: str = None) -> dict:
    """Load server configuration from YAML file"""
    default_config = Path("config/server_default.yaml")
    
    # Load default config first
    if not default_config.exists():
        raise FileNotFoundError(f"Default config not found at {default_config}")
        
    with open(default_config) as f:
        config = yaml.safe_load(f)
    
    # Override with custom config if provided
    if config_path and Path(config_path).exists():
        with open(config_path) as f:
            custom_config = yaml.safe_load(f)
            config.update(custom_config)
            
    return config

# Update global DB_PATH to be configurable
config = load_config()
DB_PATH = config['database']['path']

def handle_send(data_tokens):
    """
    data_tokens: ["SEND", <recipient_pub>, <ciphertext>, <signature>,
                  <sender_pub>, <nonce>]
    """
    if len(data_tokens) != 6:
        logging.error(
            f"Invalid SEND command format. Got {len(data_tokens)} tokens.")
        return b"ERROR: Invalid SEND command format\n"

    _, b64_recipient_pub, b64_ciphertext, b64_signature, b64_sender_pub, b64_nonce = data_tokens
    try:
        recipient_pub = base64.b64decode(b64_recipient_pub)
        ciphertext = base64.b64decode(b64_ciphertext)
        signature = base64.b64decode(b64_signature)
        sender_pub = base64.b64decode(b64_sender_pub)
        nonce = base64.b64decode(b64_nonce)
    except Exception as e:
        logging.error(f"Base64 decode failed in SEND: {str(e)}")
        return b"ERROR: Base64 decode failed\n"

    # Verify signature
    try:
        message_for_sig = recipient_pub + ciphertext + nonce
        verify_signature(sender_pub, signature, message_for_sig)
    except InvalidSignature:
        logging.warning(f"Invalid signature in SEND from {sender_pub[:20]}...")
        return b"ERROR: Invalid signature\n"
    except Exception as e:
        logging.error(f"Signature verification error in SEND: {str(e)}")
        return f"ERROR: Signature verification failed: {str(e)}\n".encode('utf-8')

    # Store
    store_message(recipient_pub, ciphertext,
                  sender_pub, signature, nonce, DB_PATH)
    logging.info(
        f"Stored message for {recipient_pub[:20]} from {sender_pub[:20]}...")
    return b"OK: Message stored\n"


def handle_pull(data_tokens):
    """
    data_tokens: ["PULL", <requester_pub>, <signature>, <nonce>]
    """
    if len(data_tokens) != 4:
        logging.error("Invalid PULL command format.")
        return b"ERROR: Invalid PULL command format\n"

    _, b64_requester_pub, b64_signature, b64_nonce = data_tokens
    try:
        requester_pub = base64.b64decode(b64_requester_pub)
        signature = base64.b64decode(b64_signature)
        nonce = base64.b64decode(b64_nonce)
    except Exception as e:
        logging.error(f"Base64 decode failed in PULL: {str(e)}")
        return b"ERROR: Base64 decode failed\n"

    # Verify signature with nonce
    try:
        message_for_sig = requester_pub + nonce
        verify_signature(requester_pub, signature, message_for_sig)
    except InvalidSignature:
        logging.warning(
            f"Invalid signature in PULL from {requester_pub[:20]}...")
        return b"ERROR: Invalid signature\n"
    except Exception as e:
        logging.error(f"Signature verification error in PULL: {str(e)}")
        return f"ERROR: Signature verification failed: {str(e)}\n".encode('utf-8')

    # Pull
    rows = pull_and_move_messages(requester_pub, DB_PATH)
    if not rows:
        return b"OK: No messages\n"

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
    data_chunks = []
    while True:
        chunk = conn.recv(1024)
        if not chunk:
            break
        data_chunks.append(chunk)
        if b'\n' in chunk:
            break
    data = b''.join(data_chunks)
    return data.decode('utf-8', errors='ignore').strip()


def client_handler(conn: socket.socket, addr: tuple):
    try:
        conn.settimeout(30)  # 30s timeout
        logging.info(f"New connection from {addr}")
        data = _read_line(conn)
        if not data:
            logging.warning(f"Empty data from {addr}")
            conn.sendall(b"ERROR: Empty request\n")
            return

        logging.info(f"Raw data: {data!r}")
        tokens = data.split()
        if not tokens:
            conn.sendall(b"ERROR: No command\n")
            return

        cmd = tokens[0].upper()
        if cmd == "SEND":
            resp = handle_send(tokens)
        elif cmd == "PULL":
            resp = handle_pull(tokens)
        else:
            logging.warning(f"Unknown command {cmd} from {addr}")
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


def run_server(host: str = None, port: int = None):
    """
    Start the TCP server with configuration
    Args can override config file values
    """
    cfg = config['tcp_server']
    server_host = host or cfg['host']
    server_port = port or cfg['port']
    
    logging.info(f"Starting raw TCP server on {server_host}:{server_port}")
    init_db(DB_PATH)

    shutdown_event = threading.Event()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((server_host, server_port))
    s.listen(5)
    print(f"Server listening on {server_host}:{server_port}...")

    # Start cleanup thread
    def cleanup_loop():
        while not shutdown_event.is_set():
            time.sleep(config['database']['cleanup_interval'])
            try:
                cleanup_old_pulled_messages(DB_PATH)
            except Exception as e:
                logging.error(f"Error in cleanup: {str(e)}")

    cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
    cleanup_thread.start()
    logging.info("Started cleanup thread")

    try:
        while not shutdown_event.is_set():
            conn, addr = s.accept()
            t = threading.Thread(target=client_handler,
                                 args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        logging.info("Shutdown signal received")
        shutdown_event.set()
    except Exception as e:
        logging.critical(f"Fatal server error: {str(e)}")
        raise
    finally:
        logging.info("Shutting down server")
        s.close()


def init_db(db_path: str = DB_PATH):
    """
    Initialize the SQLite database if it doesn't exist.
    Create two tables: messages (unpulled), pulled_messages (pulled).
    """
    with db_lock, sqlite3.connect(db_path) as conn:
        c = conn.cursor()
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


def store_message(recipient_pub: bytes, ciphertext: bytes, sender_pub: bytes,
                  signature: bytes, nonce: bytes, db_path: str = DB_PATH):
    """Insert a new message into the 'messages' table."""
    with db_lock:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("""
        INSERT INTO messages
        (recipient_pub, ciphertext, sender_pub, signature, nonce, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (recipient_pub, ciphertext, sender_pub, signature, nonce, time.time()))
        conn.commit()
        conn.close()


def pull_and_move_messages(recipient_pub: bytes, db_path: str = DB_PATH):
    """
    Pull all messages for recipient_pub and move them to pulled_messages table.
    """
    with db_lock:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("""
        SELECT id, ciphertext, sender_pub, signature, nonce, timestamp
        FROM messages
        WHERE recipient_pub = ?
        """, (recipient_pub,))
        rows = c.fetchall()

        pulled_rows = []
        for row in rows:
            msg_id, ciphertext, sender_pub, signature, nonce, msg_ts = row
            pulled_rows.append((recipient_pub, ciphertext, sender_pub,
                                signature, nonce, msg_ts, time.time()))

        if pulled_rows:
            c.executemany("""
            INSERT INTO pulled_messages
            (recipient_pub, ciphertext, sender_pub, signature,
             nonce, timestamp, pulled_time)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, pulled_rows)

            message_ids = [str(r[0]) for r in rows]
            c.execute(
                f"DELETE FROM messages WHERE id IN ({','.join(message_ids)})")

        conn.commit()
        conn.close()
        return rows


def cleanup_old_pulled_messages(db_path: str = DB_PATH):
    """Delete pulled messages older than configured retention period."""
    retention_days = config['database']['retention_days']
    cutoff_time = time.time() - (retention_days * 24 * 3600)
    
    with db_lock:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("DELETE FROM pulled_messages WHERE pulled_time < ?",
                  (cutoff_time,))
        deleted_count = c.rowcount
        conn.commit()
        conn.close()
    if deleted_count > 0:
        logging.info(f"Cleanup: Deleted {deleted_count} old pulled messages")


def verify_signature(public_key_pem: bytes, signature: bytes, message: bytes):
    """Verify signature using public key in PEM format."""
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
