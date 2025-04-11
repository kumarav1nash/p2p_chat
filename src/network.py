# network.py
import socket
import logging
import threading
import json
import uuid
from typing import Optional, Callable
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from . import config
from .crypto import CryptoManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class NetworkManager:
    def __init__(self, crypto: CryptoManager):
        self.crypto = crypto
        self.server_socket = None
        self.client_socket = None
        self.receive_thread = None
        self.message_callback = None
        self.running = False
        self.is_server = False
        self.name = None
        self.peer_name = None

    def set_message_callback(self, callback: Callable[[str, str], None]) -> None:
        """Set the callback function for handling incoming messages."""
        self.message_callback = callback

    def start_server(self, port: int = 65432, name: Optional[str] = None) -> None:
        """Start the server and wait for a client to connect."""
        try:
            self.is_server = True
            self.name = name or f"Server_{str(uuid.uuid4())[:8]}"
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind(('0.0.0.0', port))
            self.server_socket.listen(1)
            logger.info(f"Server listening on port {port}")

            # Accept client connection
            self.client_socket, addr = self.server_socket.accept()
            logger.info(f"Client connected from {addr}")

            # Exchange names with the client
            self._exchange_names()

            # Start message handling thread
            self.running = True
            self.receive_thread = threading.Thread(target=self._handle_messages)
            self.receive_thread.daemon = True
            self.receive_thread.start()

        except Exception as e:
            logger.error(f"Server error: {e}")
            self.cleanup()
            raise

    def connect_to_peer(self, host: str, port: int = 65432, name: Optional[str] = None) -> None:
        """Connect to a peer server."""
        try:
            self.is_server = False
            self.name = name or f"Client_{str(uuid.uuid4())[:8]}"
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((host, port))
            logger.info(f"Connected to {host}:{port}")

            # Exchange names with the server
            self._exchange_names()

            # Start message handling thread
            self.running = True
            self.receive_thread = threading.Thread(target=self._handle_messages)
            self.receive_thread.daemon = True
            self.receive_thread.start()

        except Exception as e:
            logger.error(f"Connection error: {e}")
            self.cleanup()
            raise

    def _exchange_names(self) -> None:
        """Exchange names with the peer and ensure they are unique."""
        # Send our name to the peer
        name_data = json.dumps({"name": self.name}).encode()
        self.client_socket.sendall(name_data)

        # Receive the peer's name
        peer_data = self.client_socket.recv(1024)
        peer_info = json.loads(peer_data.decode())
        self.peer_name = peer_info["name"]

        # If names are the same, append a unique identifier to our name
        if self.name == self.peer_name:
            self.name = f"{self.name}_{str(uuid.uuid4())[:8]}"
            # Send the updated name to the peer
            updated_name_data = json.dumps({"name": self.name}).encode()
            self.client_socket.sendall(updated_name_data)

        logger.info(f"Connected as {self.name} to {self.peer_name}")

    def send_message(self, message: str) -> None:
        """Send a message to the peer."""
        if not self.client_socket:
            raise Exception("Not connected to a peer")

        try:
            # Encrypt the message
            encrypted_message = self.crypto.encrypt_message(message)
            self.client_socket.sendall(encrypted_message)
            logger.debug(f"Sent message: {message}")
        except Exception as e:
            logger.error(f"Error sending message: {e}")
            raise

    def _handle_messages(self) -> None:
        """Handle incoming messages from the peer."""
        logger.info("Message handling thread started")
        while self.running:
            try:
                # Receive encrypted message
                encrypted_data = self.client_socket.recv(4096)
                if not encrypted_data:
                    logger.info("Connection closed by peer")
                    break

                # Decrypt the message
                message = self.crypto.decrypt_message(encrypted_data)
                logger.debug(f"Received message: {message}")

                # Call the message callback
                if self.message_callback:
                    self.message_callback(self.peer_name, message)

            except Exception as e:
                logger.error(f"Error handling message: {e}")
                break

        self.cleanup()

    def cleanup(self) -> None:
        """Clean up resources."""
        self.running = False
        if self.client_socket:
            try:
                self.client_socket.close()
            except Exception:
                pass
            self.client_socket = None
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
            self.server_socket = None
        if self.receive_thread:
            self.receive_thread.join(timeout=1.0)
            self.receive_thread = None