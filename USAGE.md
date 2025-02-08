# Detailed Usage Guide

## Key Management

### Generate RSA Keys

Each user needs their own public/private key pair. Generate them using:

```bash
python secure_messenger.py generate_keys --id <username>
```

This creates two files in `.data/<username>/`:
- `private_key.pem` - Keep this secret! Never share it.
- `public_key.pem` - Share this with other users who want to send you messages.

Example:
```bash
python secure_messenger.py generate_keys --id alice
python secure_messenger.py generate_keys --id bob
```

### Import Public Keys

To send messages to someone, you need their public key. Import it using:

```bash
python secure_messenger.py import_key --id <their_username> --public_key <path_to_their_public_key>
```

Example:
```bash
# Bob imports Alice's public key
python secure_messenger.py import_key --id alice --public_key .data/alice/public_key.pem
```

## Running the Server

The server stores encrypted messages and handles delivery. Start it with:

```bash
python secure_messenger.py server --host <ip_address> --port <port_number>
```

Examples:
```bash
# Listen only on localhost
python secure_messenger.py server --host 127.0.0.1 --port 50000

# Listen on all interfaces (public)
python secure_messenger.py server --host 0.0.0.0 --port 50000
```

The server maintains two tables:
- `messages`: Stores undelivered messages
- `pulled_messages`: Stores delivered messages for up to 7 days

## Client Operations

### Sending Messages

To send a message:

```bash
python secure_messenger.py client send \
    --server <server_ip> \
    --port <server_port> \
    --sender <your_username> \
    --recipient <recipient_username> \
    --message "Your message here"
```

Example:
```bash
python secure_messenger.py client send \
    --server 127.0.0.1 \
    --port 50000 \
    --sender alice \
    --recipient bob \
    --message "Hello Bob! How are you?"
```

### Retrieving Messages

To check for and retrieve your messages:

```bash
python secure_messenger.py client pull \
    --server <server_ip> \
    --port <server_port> \
    --id <your_username>
```

Example:
```bash
python secure_messenger.py client pull \
    --server 127.0.0.1 \
    --port 50000 \
    --id bob
```

## Security Notes

1. Keep your private key secure:
   - Never share your private key
   - Back up your private key safely
   - Store it with appropriate file permissions

2. Message Security:
   - Messages are encrypted with the recipient's public key
   - Only the recipient's private key can decrypt messages
   - Messages are signed by the sender's private key
   - The server can't read message contents

3. Server Storage:
   - Messages are automatically deleted after 7 days
   - Once pulled, messages move to a separate table
   - The server only stores encrypted data

4. Network Security:
   - Consider using a firewall to restrict server access
   - For production use, run behind a reverse proxy with TLS
   - Monitor server logs for suspicious activity