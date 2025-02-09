# Secure Messenger

Secure Messenger is a web‐based end‐to‐end encrypted messaging system with a central server that handles message storage and delivery. This project uses RSA-2048 encryption to ensure that only the intended recipient can read the messages. It is built with a modular architecture that features abstraction layers for cryptography, configuration management, message handling, and transport.

## Features

- **End-to-End Encryption:** Uses RSA-2048 for encrypting messages.
- **Message Signing:** Ensures sender authenticity via digital signatures.
- **Modular Architecture:** Separates concerns via abstraction layers (crypto, repository, service, transport).
- **Centralized Server:** Handles secure storage and delivery of messages.
- **Web Interfaces:** Client web interface for messaging and a server dashboard for monitoring.
- **Automatic Cleanup:** Messages are automatically deleted after a configurable retention period.
- **Multi-User Support:** Easily manage multiple user identities and their contacts.

## Requirements

- Python 3.7+
- [cryptography](https://pypi.org/project/cryptography/)
- [Flask](https://pypi.org/project/Flask/)
- SQLite3 (bundled with Python)
- [PyYAML](https://pypi.org/project/PyYAML/)

## Installation

1. **Clone the repository:**

   ~~~bash
   git clone https://github.com/narbonnais/e2e-mesrc.ssaging-protocol.git
   cd e2e-mesrc.ssaging-protocol
   ~~~

2. **Install dependencies:**

   ~~~bash
   pip install cryptography flask pyyaml
   ~~~

## Project Structure

- **client/**  
  Contains the client-side code and web interface for key management and messaging.
  - **bin/**: Command-line utilities (e.g., initializing demo users, running the client web interface).
  - **client.py**: Core client functionality.

- **server/**  
  Contains the server-side code with a well-defined abstraction:
  - **bin/**: Scripts for running the TCP server and the server dashboard.
  - **repository/**: Data access layer (e.g., SQLite implementation for message storage).
  - **service/**: Business logic for processing SEND and PULL commands.
  - **transport/**: Communication layer abstraction (e.g., TCP server implementation).

- **common/**  
  Shared modules including:
  - **crypto_service.py:** Cryptographic operations.
  - **config_service.py:** Centralized configuration management.
  - **client_server_protocol.py:** Protocol definitions and helper functions.

## Quick Start

### Running Everything Locally

1. **Start the Message Server**  
   The TCP server handles message storage and delivery:
   
   ~~~bash
   python -m src.server.bin.server
   ~~~

2. **Start the Client Web Interface**  
   Launch the web interface for key management and messaging:
   
   ~~~bash
   python -m src.client.bin.web
   ~~~

3. **Create tests users**  
   Initialize the demo users. This will create a pair of keys for two local users local-alice and local-bob in the `.data` directory. You can then open two client tabs and send messages between the two users.

   ~~~bash
   python -m src.client.bin.init_demo_users
   ~~~

You can access the interfaces in your browser at:
- **Client Interface:** [http://127.0.0.1:8000](http://127.0.0.1:8000)

### Connecting to a Remote Server

If you already know the address of a remote Secure Messenger server, you **do not** need to run your own server to send messages. Simply:

1. **Run the Client Web Interface Locally:**

   ~~~bash
   python -m src.client.bin.web
   ~~~

2. **Open Your Browser:**  
   Navigate to [http://127.0.0.1:8000](http://127.0.0.1:8000).

3. **Update the Server Configuration:**  
   In the Settings modal of the client interface, update the server host and port to point to the remote server. This allows you to send and receive messages on the network without running your own server.

## Usage

### Client Interface Details

The client interface (provided as an HTML file with integrated JavaScript) offers:

- **Local IDs & Contacts Sidebar:**  
  - Lists locally generated IDs (user identities) and contacts (imported public keys).
  - Provides buttons for refreshing, adding, copying, and deleting local IDs and contacts.
  
- **Chat Panel:**  
  - Displays the conversation with the selected contact.
  - Provides an input area for composing and sending messages.
  
- **Settings & Key Management:**  
  - A modal for updating server configuration.
  - Functionality to display and copy public keys to the clipboard.

The HTML file includes CSS for styling and JavaScript that interacts with REST endpoints (e.g., `/api/generate_key`, `/api/import_key`, `/api/send_message`, etc.) to manage keys and messages.

### Configuration

The system employs a centralized configuration service located in `common/config_service.py`. Default settings (such as server host/port, database path, and retention days) can be overridden via YAML configuration files. For example, you can update the server port by modifying `config/server_default.yaml` or by providing a custom config file when starting the server.

## Security Notes

- **Encryption & Signing:**  
  All messages are encrypted using RSA-2048 and digitally signed to ensure integrity and authenticity. The server stores only encrypted messages.

- **Private Key Security:**  
  Keep your private key secure. Never share it or expose it in unsecured locations.

- **Data Retention:**  
  Messages are automatically purged after the configured retention period (default is 7 days).

- **Network Security:**  
  For production deployments, consider using TLS and proper firewall configurations to secure the network.
