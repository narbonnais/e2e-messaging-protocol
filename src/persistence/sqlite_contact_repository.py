import sqlite3
import time
from typing import List, Optional
from pathlib import Path
from .interfaces import ContactRepositoryInterface


class SQLiteContactRepository(ContactRepositoryInterface):
    def __init__(self, db_path: str):
        self.db_path = db_path
        # Ensure the directory exists
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    def init_db(self) -> None:
        """Initialize the contacts table if it doesn't exist."""
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            c.execute("""
                CREATE TABLE IF NOT EXISTS contacts (
                    id TEXT PRIMARY KEY,
                    public_key_pem TEXT NOT NULL,
                    added_time REAL NOT NULL
                );
            """)
            conn.commit()

    def store_contact(self, contact_id: str, public_key_pem: bytes) -> bool:
        """Store or update a contact."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                c = conn.cursor()
                c.execute("""
                    INSERT OR REPLACE INTO contacts (id, public_key_pem, added_time)
                    VALUES (?, ?, ?)
                """, (contact_id, public_key_pem.decode('utf-8'), time.time()))
                conn.commit()
            return True
        except Exception as e:
            print(f"Error storing contact: {str(e)}")
            return False

    def get_contact(self, contact_id: str) -> Optional[bytes]:
        """Retrieve a contact’s public key."""
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            c.execute(
                "SELECT public_key_pem FROM contacts WHERE LOWER(id) = LOWER(?)", (contact_id,))
            result = c.fetchone()
            if result:
                return result[0].encode('utf-8')
            return None

    def delete_contact(self, contact_id: str) -> bool:
        """Delete a contact."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                c = conn.cursor()
                c.execute(
                    "DELETE FROM contacts WHERE LOWER(id) = LOWER(?)", (contact_id,))
                conn.commit()
                return c.rowcount > 0
        except Exception as e:
            print(f"Error deleting contact: {str(e)}")
            return False

    def list_contacts(self) -> List[str]:
        """Return a list of all contact IDs."""
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            c.execute("SELECT id FROM contacts ORDER BY id")
            return [row[0] for row in c.fetchall()]
