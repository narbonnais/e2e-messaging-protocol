import sqlite3
import time
import logging
import threading
from typing import List, Tuple, Optional
from pathlib import Path
from .interfaces import MessageRepositoryInterface


class MessageRepository(MessageRepositoryInterface):
    """SQLite implementation of message storage"""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.db_lock = threading.Lock()
        # Create directory if it doesn't exist
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    def init_db(self):
        """Initialize the database schema"""
        with self.db_lock, sqlite3.connect(self.db_path) as conn:
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

    def store_message(
            self,
            recipient_pub: bytes,
            ciphertext: bytes,
            sender_pub: bytes,
            signature: bytes,
            nonce: bytes) -> bool:
        """Store a new message in the messages table"""
        try:
            with self.db_lock, sqlite3.connect(self.db_path) as conn:
                c = conn.cursor()
                c.execute("""
                INSERT INTO messages
                (recipient_pub, ciphertext, sender_pub, signature, nonce, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
                """, (recipient_pub, ciphertext, sender_pub, signature, nonce, time.time()))
                conn.commit()
                return True
        except Exception as e:
            logging.error(f"Error storing message: {str(e)}")
            return False

    def pull_messages(self, recipient_pub: bytes) -> List[Tuple]:
        """Pull all messages for a recipient and move them to pulled_messages"""
        with self.db_lock, sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()

            # Get messages for recipient
            c.execute("""
            SELECT id, ciphertext, sender_pub, signature, nonce, timestamp
            FROM messages
            WHERE recipient_pub = ?
            """, (recipient_pub,))
            rows = c.fetchall()

            if rows:
                # Move messages to pulled_messages
                pulled_rows = [
                    (recipient_pub, ciphertext, sender_pub, signature,
                     nonce, msg_ts, time.time())
                    for _, ciphertext, sender_pub, signature, nonce, msg_ts
                    in rows
                ]

                c.executemany("""
                INSERT INTO pulled_messages
                (recipient_pub, ciphertext, sender_pub, signature,
                 nonce, timestamp, pulled_time)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """, pulled_rows)

                # Delete from messages
                message_ids = [str(r[0]) for r in rows]
                c.execute(
                    f"DELETE FROM messages WHERE id IN ({
                        ','.join(message_ids)})")

                conn.commit()

            return rows

    def cleanup_old_messages(self, retention_days: int) -> int:
        """Delete pulled messages older than retention period"""
        cutoff_time = time.time() - (retention_days * 24 * 3600)

        try:
            with self.db_lock, sqlite3.connect(self.db_path) as conn:
                c = conn.cursor()
                c.execute("DELETE FROM pulled_messages WHERE pulled_time < ?",
                          (cutoff_time,))
                deleted_count = c.rowcount
                conn.commit()
                return deleted_count
        except Exception as e:
            logging.error(f"Error cleaning up messages: {str(e)}")
            return 0
