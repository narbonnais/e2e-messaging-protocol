import sqlite3
from typing import Dict, List, Optional
from pathlib import Path
from .interfaces import ConfigRepositoryInterface


class SQLiteConfigRepository(ConfigRepositoryInterface):
    def __init__(self, db_path: str):
        self.db_path = db_path
        # Ensure the directory exists
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    def init_db(self) -> None:
        """Initialize the config table if it doesn't exist."""
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            c.execute("""
                CREATE TABLE IF NOT EXISTS config (
                    section TEXT NOT NULL,
                    key TEXT NOT NULL,
                    value TEXT NOT NULL,
                    updated_time REAL NOT NULL,
                    PRIMARY KEY (section, key)
                );
            """)
            conn.commit()

    def set_config(self, section: str, key: str, value: str) -> bool:
        """Store or update a configuration value."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                c = conn.cursor()
                c.execute("""
                    INSERT OR REPLACE INTO config (section, key, value, updated_time)
                    VALUES (?, ?, ?, strftime('%s', 'now'))
                """, (section, key, value))
                conn.commit()
            return True
        except Exception as e:
            print(f"Error storing config: {str(e)}")
            return False

    def get_config(self, section: str, key: str, default: str = None) -> Optional[str]:
        """Retrieve a configuration value."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                c = conn.cursor()
                c.execute(
                    "SELECT value FROM config WHERE section = ? AND key = ?",
                    (section, key)
                )
                result = c.fetchone()
                return result[0] if result else default
        except Exception as e:
            print(f"Error retrieving config: {str(e)}")
            return default

    def delete_config(self, section: str, key: str) -> bool:
        """Delete a configuration entry."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                c = conn.cursor()
                c.execute(
                    "DELETE FROM config WHERE section = ? AND key = ?",
                    (section, key)
                )
                conn.commit()
                return c.rowcount > 0
        except Exception as e:
            print(f"Error deleting config: {str(e)}")
            return False

    def list_sections(self) -> List[str]:
        """List all configuration sections."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                c = conn.cursor()
                c.execute("SELECT DISTINCT section FROM config ORDER BY section")
                return [row[0] for row in c.fetchall()]
        except Exception as e:
            print(f"Error listing sections: {str(e)}")
            return []

    def get_section_configs(self, section: str) -> Dict[str, str]:
        """Get all configurations for a section."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                c = conn.cursor()
                c.execute(
                    "SELECT key, value FROM config WHERE section = ? ORDER BY key",
                    (section,)
                )
                return dict(c.fetchall())
        except Exception as e:
            print(f"Error getting section configs: {str(e)}")
            return {} 