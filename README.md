# Secure Messenger

A simple end-to-end encrypted messaging system with a central server that handles message storage and delivery. Messages are encrypted using RSA public key cryptography, ensuring that only the intended recipient can read them.

## Features

- End-to-end encryption using RSA-2048
- Message signing to verify sender authenticity
- Central server for message storage and delivery
- Messages are automatically deleted after 7 days
- Simple command-line interface
- Support for multiple users

## Requirements

- Python 3.7+
- cryptography library
- SQLite3 (included with Python)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/narbonnais/secure-messenger.git
cd secure-messenger
```

2. Install dependencies:
```bash
pip install cryptography
```

## Quick Start

1. Generate keys for two users:
```bash
python secure_messenger.py generate_keys --id alice
python secure_messenger.py generate_keys --id bob
```

2. Exchange public keys between users:
```bash
# Bob imports Alice's public key
python secure_messenger.py import_key --id alice --public_key .data/alice/public_key.pem

# Alice imports Bob's public key
python secure_messenger.py import_key --id bob --public_key .data/bob/public_key.pem
```

3. Start the server:
```bash
python secure_messenger.py server --host 127.0.0.1 --port 50000
```

4. Send and receive messages:
```bash
# Alice sends a message to Bob
python secure_messenger.py client send --server 127.0.0.1 --port 50000 --sender alice --recipient bob --message "Hello Bob!"

# Bob checks his messages
python secure_messenger.py client pull --server 127.0.0.1 --port 50000 --id bob
```

## Security Features

- RSA-2048 encryption for message content
- Message signing to prevent tampering
- Server never sees decrypted message content
- Automatic message cleanup after 7 days
- Signature verification for message retrieval

## For more detailed usage instructions, see [usage.md](usage.md)

## License

MIT License

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change. 