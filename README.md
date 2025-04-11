# P2P Encrypted Chat

A secure, peer-to-peer chat application with end-to-end encryption and persistent message history.

## Features

- 🔒 End-to-end encryption using asymmetric cryptography
- 👥 Peer-to-peer communication
- 💬 Real-time messaging
- 🎨 Color-coded messages for better readability
- 📝 Persistent chat history with encrypted storage
- 🔑 Secure key management
- 🏷️ Custom user aliases
- 📊 Message history viewing and management

## Security Features

- Asymmetric encryption for message transmission
- Symmetric encryption for local message storage
- Secure key exchange protocol
- Encrypted database storage
- Automatic key management

## Requirements

- Python 3.7+
- Required Python packages:
  - cryptography
  - sqlite3 (built-in)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/p2p_chat.git
cd p2p_chat
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Starting a Chat Server

To start a chat server:
```bash
python -m src.cli --server --name YourName
```

### Connecting to a Chat Server

To connect to an existing chat server:
```bash
python -m src.cli --connect <server_ip> --name YourName
```

### Command Line Arguments

- `--server`: Start in server mode
- `--connect <ip>`: Connect to a server at the specified IP
- `--port <port>`: Specify the port number (default: 65432)
- `--name <name>`: Set your chat alias
- `--history`: View chat history
- `--history-limit <n>`: Limit the number of history entries to show
- `--clear-history`: Clear the chat history
- `--debug`: Enable debug logging

## Project Structure

```
p2p_chat/
├── src/
│   ├── __init__.py
│   ├── cli.py          # Command-line interface
│   ├── crypto.py       # Encryption/decryption handling
│   ├── network.py      # Network communication
│   └── storage.py      # Database management
├── requirements.txt
└── README.md
```

## Components

### CLI (cli.py)
- Handles user interaction
- Manages chat sessions
- Displays messages with color coding
- Processes command-line arguments

### Crypto (crypto.py)
- Manages encryption keys
- Handles message encryption/decryption
- Implements secure key exchange

### Network (network.py)
- Manages peer-to-peer connections
- Handles message transmission
- Implements connection protocols

### Storage (storage.py)
- Manages chat history
- Handles encrypted message storage
- Implements database operations

## Security Considerations

1. **Encryption**
   - Messages are encrypted during transmission using asymmetric encryption
   - Local storage uses symmetric encryption
   - Keys are securely stored in the database

2. **Key Management**
   - Automatic key generation and exchange
   - Secure storage of encryption keys
   - Unique keys for each chat session

3. **Data Storage**
   - Messages are stored in an encrypted SQLite database
   - Encryption keys are stored securely
   - Chat history can be cleared securely

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Built with Python and the cryptography library
- Inspired by the need for secure, decentralized communication
