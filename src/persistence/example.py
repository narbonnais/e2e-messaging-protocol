from pathlib import Path
from .file_key_repository import FileKeyRepository
from .sqlite_contact_repository import SQLiteContactRepository
from .sqlite_message_repository import SQLiteMessageRepository
from .sqlite_config_repository import SQLiteConfigRepository


def main():
    # Set up base directories and paths
    base_dir = Path("./data")
    base_dir.mkdir(parents=True, exist_ok=True)

    # Initialize repositories
    key_repo = FileKeyRepository(str(base_dir / "keys"))
    contact_repo = SQLiteContactRepository(str(base_dir / "contacts.db"))
    message_repo = SQLiteMessageRepository(str(base_dir / "messages.db"))

    # Initialize config repository
    config_repo = SQLiteConfigRepository(str(base_dir / "config.db"))

    # Example user and keys
    user_id = "alice"
    sample_private_key = b"-----BEGIN PRIVATE KEY-----\nMIIE...sample...key\n-----END PRIVATE KEY-----"
    sample_public_key = b"-----BEGIN PUBLIC KEY-----\nMIIB...sample...key\n-----END PUBLIC KEY-----"

    # Store keys
    print("Storing keys...")
    key_repo.store_key(user_id, "private", sample_private_key)
    key_repo.store_key(user_id, "public", sample_public_key)

    # List keys
    print(f"\nKeys for {user_id}:")
    keys = key_repo.list_keys(user_id)
    for key in keys:
        print(f"- {key}")

    # Store a contact
    contact_id = "bob"
    print(f"\nStoring contact {contact_id}...")
    contact_repo.store_contact(contact_id, sample_public_key)

    # Add Charlie as another contact
    charlie_id = "charlie"
    charlie_public_key = b"-----BEGIN PUBLIC KEY-----\nMIIB...charlie...key\n-----END PUBLIC KEY-----"
    print(f"\nStoring contact {charlie_id}...")
    contact_repo.store_contact(charlie_id, charlie_public_key)

    # List contacts
    print("\nAll contacts:")
    contacts = contact_repo.list_contacts()
    for contact in contacts:
        print(f"- {contact}")

    # Store a message
    print("\nStoring a message...")
    message_repo.store_message(
        recipient_pub=sample_public_key,
        ciphertext=b"encrypted message",
        sender_pub=sample_public_key,
        signature=b"signature",
        nonce=b"nonce"
    )

    # Pull messages
    print("\nPulling messages...")
    messages = message_repo.pull_messages(sample_public_key)
    print(f"Found {len(messages)} messages")

    # Cleanup old messages
    deleted_count = message_repo.cleanup_old_messages(retention_days=30)
    print(f"\nCleaned up {deleted_count} old messages")

    # Store some configuration values
    print("\nStoring configurations...")
    config_repo.set_config("network", "host", "localhost")
    config_repo.set_config("network", "port", "8080")
    config_repo.set_config("storage", "data_dir", "/tmp/data")
    config_repo.set_config("storage", "max_size", "1024")

    # List all sections
    print("\nConfiguration sections:")
    sections = config_repo.list_sections()
    for section in sections:
        print(f"\nSection: {section}")
        configs = config_repo.get_section_configs(section)
        for key, value in configs.items():
            print(f"  {key}: {value}")

    # Get specific config value
    host = config_repo.get_config("network", "host")
    print(f"\nNetwork host: {host}")

    # Delete a config
    config_repo.delete_config("storage", "max_size")
    print("\nDeleted storage.max_size configuration")


if __name__ == "__main__":
    main()
