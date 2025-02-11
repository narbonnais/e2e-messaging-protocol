import sqlite3
import logging
import time
from typing import Optional, List
from .contact_repository_interface import IContactRepository


class SQLiteContactRepository(IContactRepository):
    """SQLite-based implementation of contact repository."""

    def __init__(self, db_path: str, db_lock):
        """Initialize with database path and lock.

        Args:
            db_path: Path to SQLite database file
            db_lock: Threading lock for database access
        """
        self.db_path = db_path
        self.db_lock = db_lock
        self._init_db()

    def _init_db(self):
        """Initialize the contacts table if it doesn't exist."""
        with self.db_lock, sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            c.execute("""
            CREATE TABLE IF NOT EXISTS contacts (
                id TEXT PRIMARY KEY,
                public_key_pem TEXT NOT NULL,
                added_time REAL NOT NULL
            )
            """)
            conn.commit()

    def store_contact(self, contact_id: str, public_key_pem: bytes) -> bool:
        """Store or update a contact in the database."""
        try:
            with self.db_lock, sqlite3.connect(self.db_path) as conn:
                c = conn.cursor()
                c.execute("""
                INSERT OR REPLACE INTO contacts (id, public_key_pem, added_time)
                VALUES (?, ?, ?)
                """, (contact_id, public_key_pem.decode('utf-8'), time.time()))
                conn.commit()
                return True
        except Exception as e:
            logging.error(f"Error storing contact: {str(e)}")
            return False

    def get_contact(self, contact_id: str) -> Optional[bytes]:
        """Retrieve a contact's public key from the database."""
        with self.db_lock, sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            # Use case-insensitive comparison
            c.execute(
                "SELECT public_key_pem FROM contacts WHERE LOWER(id) = LOWER(?)",
                (contact_id,)
            )
            result = c.fetchone()
            if result:
                return result[0].encode('utf-8')
            return None

    def delete_contact(self, contact_id: str) -> bool:
        """Remove a contact from the database."""
        try:
            with self.db_lock, sqlite3.connect(self.db_path) as conn:
                c = conn.cursor()
                c.execute("DELETE FROM contacts WHERE LOWER(id) = LOWER(?)",
                          (contact_id,))
                conn.commit()
                return c.rowcount > 0
        except Exception as e:
            logging.error(f"Error deleting contact: {str(e)}")
            return False

    def list_contacts(self) -> List[str]:
        """Get list of contact IDs from the database."""
        with self.db_lock, sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            c.execute("SELECT id FROM contacts ORDER BY id")
            return [row[0] for row in c.fetchall()]
