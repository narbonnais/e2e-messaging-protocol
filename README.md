# Secure Messenger

A web-based end-to-end encrypted messaging system with a central server that handles message storage and delivery. Messages are encrypted using RSA public key cryptography, ensuring that only the intended recipient can read them.

## Features

- End-to-end encryption using RSA-2048
- Message signing to verify sender authenticity
- Central server for message storage and delivery
- Web interface for easy message management
- Server dashboard for monitoring
- Messages are automatically deleted after 7 days
- Support for multiple users

## Requirements

- Python 3.7+
- cryptography library
- Flask (for web interface)
- SQLite3 (included with Python)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/narbonnais/secure-messenger.git
cd secure-messenger
```

2. Install dependencies:
```bash
pip install cryptography flask
```

## Quick Start

1. Start the message server:
```bash
python -m src.server.runtime
```

2. Start the client web interface:
```bash
python -m src.client.web
```
Access at: http://127.0.0.1:8000

3. Start the server dashboard:
```bash
python -m src.server.web
```
Access at: http://127.0.0.1:8001

## Security Features

- RSA-2048 encryption for message content
- Message signing to prevent tampering
- Server never sees decrypted message content
- Automatic message cleanup after 7 days
- Signature verification for message retrieval

## For more detailed usage instructions, see [USAGE.md](USAGE.md)

## License

MIT License

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change. 