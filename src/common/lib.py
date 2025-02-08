import os
import time
import sqlite3
import threading
import logging
from datetime import datetime
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

DB_PATH = "messages.db"
db_lock = threading.Lock()

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
    """
    Insert a new message into the 'messages' table.
    """
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
    Pull all messages for `recipient_pub`, return them, and move them
    to the pulled_messages table, then delete them from 'messages'.
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
            c.execute(f"DELETE FROM messages WHERE id IN ({','.join(message_ids)})")

        conn.commit()
        conn.close()

        return rows

def cleanup_old_pulled_messages(db_path: str = DB_PATH):
    """
    Delete from 'pulled_messages' all messages older than 7 days.
    """
    seven_days_ago = time.time() - (7 * 24 * 3600)
    with db_lock:
        conn = sqlite3.connect(db_path)
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
    cleanup_old_pulled_messages.last_run = datetime.now()

def verify_signature(public_key_pem: bytes, signature: bytes, message: bytes):
    """
    Verifies that 'signature' matches 'message' using the public key in PEM format.
    Raises InvalidSignature if not valid.
    """
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    try:
        public_key = load_pem_public_key(public_key_pem)
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

def init_client_db(db_path: str):
    """Initialize the client-side SQLite database for storing decrypted messages."""
    with db_lock, sqlite3.connect(db_path) as conn:
        c = conn.cursor()
        c.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id TEXT NOT NULL,
            message TEXT NOT NULL,
            timestamp REAL NOT NULL,
            received_time REAL NOT NULL
        );
        """)
        conn.commit()
