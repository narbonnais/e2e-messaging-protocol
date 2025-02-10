import os
from pathlib import Path
from typing import List, Optional
from .interfaces import KeyRepositoryInterface


class FileKeyRepository(KeyRepositoryInterface):
    def __init__(self, base_dir: str):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def store_key(
            self,
            identifier: str,
            key_type: str,
            key_data: bytes) -> bool:
        """
        Store the key data in a file under the user's directory.
        key_type must be either "public" or "private".
        """
        try:
            user_dir = self.base_dir / identifier
            user_dir.mkdir(parents=True, exist_ok=True)
            filename = "private_key.pem" if key_type.lower() == "private" else "public_key.pem"
            key_file = user_dir / filename
            with open(key_file, "wb") as f:
                f.write(key_data)
            return True
        except Exception as e:
            print(f"Error storing {key_type} key for '{identifier}': {e}")
            return False

    def get_key(self, identifier: str, key_type: str) -> Optional[bytes]:
        """
        Retrieve the key data from file.
        """
        try:
            user_dir = self.base_dir / identifier
            filename = "private_key.pem" if key_type.lower() == "private" else "public_key.pem"
            key_file = user_dir / filename
            if key_file.exists():
                with open(key_file, "rb") as f:
                    return f.read()
            return None
        except Exception as e:
            print(f"Error retrieving {key_type} key for '{identifier}': {e}")
            return None

    def delete_key(self, identifier: str, key_type: str) -> bool:
        """
        Delete the key file for the given identifier and key type.
        """
        try:
            user_dir = self.base_dir / identifier
            filename = "private_key.pem" if key_type.lower() == "private" else "public_key.pem"
            key_file = user_dir / filename
            if key_file.exists():
                key_file.unlink()
            return True
        except Exception as e:
            print(f"Error deleting {key_type} key for '{identifier}': {e}")
            return False

    def list_keys(self, identifier: str) -> List[str]:
        """
        List all key file names (typically "private_key.pem" and/or "public_key.pem")
        for the given identifier.
        """
        try:
            user_dir = self.base_dir / identifier
            if not user_dir.exists():
                return []
            return [f.name for f in user_dir.iterdir() if f.is_file()
                    and f.suffix == ".pem"]
        except Exception as e:
            print(f"Error listing keys for '{identifier}': {e}")
            return []
