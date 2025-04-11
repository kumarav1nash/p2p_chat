# network.py
import socket
import logging
import threading
from typing import Optional, Callable, Tuple
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from . import config
from .crypto import CryptoManager

logger = logging.getLogger(__name__)

class NetworkManager:
    def __init__(self, crypto_manager: CryptoManager):
        self.crypto = crypto_manager
        self.socket: Optional[socket.socket] = None
        self.client_socket: Optional[socket.socket] = None
        self.peer_public_key = None
        self.running = False
        self.message_callback: Optional[Callable[[str, str], None]] = None
        self.receive_thread: Optional[threading.Thread] = None
        self.is_server = False

    def start_server(self, host: str = config.DEFAULT_HOST, 
                    port: int = config.DEFAULT_PORT) -> None:
        """Start the server and wait for connections."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((host, port))
            self.socket.listen(1)
            logger.info(f"Server listening on {host}:{port}")
            
            self.running = True
            self.is_server = True
            while self.running:
                try:
                    client_socket, address = self.socket.accept()
                    logger.info(f"New connection from {address}")
                    self.client_socket = client_socket
                    self._handle_connection(client_socket)
                except socket.error as e:
                    if self.running:
                        logger.error(f"Socket error: {e}")
                        break
        except Exception as e:
            logger.error(f"Server error: {e}")
            raise
        finally:
            self.cleanup()

    def connect_to_peer(self, host: str, port: int = config.DEFAULT_PORT) -> None:
        """Connect to a peer."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((host, port))
            logger.info(f"Connected to {host}:{port}")
            
            self.running = True
            self.is_server = False
            self._handle_connection(self.socket)
        except Exception as e:
            logger.error(f"Connection error: {e}")
            raise
        finally:
            self.cleanup()

    def _handle_connection(self, sock: socket.socket) -> None:
        """Handle the connection with a peer."""
        try:
            # Exchange public keys
            self._exchange_keys(sock)
            
            # Start message handling thread
            self.receive_thread = threading.Thread(target=self._receive_messages, args=(sock,))
            self.receive_thread.daemon = True
            self.receive_thread.start()
            
            # Keep the connection alive
            while self.running:
                if not self.receive_thread.is_alive():
                    logger.info("Receive thread died, ending connection")
                    break
                try:
                    # Small sleep to prevent CPU hogging
                    import time
                    time.sleep(0.1)
                except KeyboardInterrupt:
                    break
        except Exception as e:
            logger.error(f"Connection handling error: {e}")
            raise

    def _exchange_keys(self, sock: socket.socket) -> None:
        """Exchange public keys with the peer."""
        try:
            # Send our public key
            local_pubkey = self.crypto.get_public_key_bytes()
            sock.sendall(local_pubkey)
            
            # Receive peer's public key
            peer_pubkey = sock.recv(1024)
            self.peer_public_key = serialization.load_pem_public_key(
                peer_pubkey,
                backend=default_backend()
            )
            logger.info("Key exchange completed")
        except Exception as e:
            logger.error(f"Key exchange error: {e}")
            raise

    def _receive_messages(self, sock: socket.socket) -> None:
        """Receive and process messages from the peer."""
        while self.running:
            try:
                data = sock.recv(config.BUFFER_SIZE)
                if not data:
                    logger.info("Connection closed by peer")
                    break
                
                message = self.crypto.decrypt_message(data)
                logger.debug(f"Received message: {message}")
                if self.message_callback:
                    self.message_callback("Peer", message)
            except Exception as e:
                if self.running:
                    logger.error(f"Message receive error: {e}")
                break

    def send_message(self, message: str) -> None:
        """Send a message to the peer."""
        if not self.peer_public_key:
            raise ValueError("Not connected to a peer")
        
        try:
            encrypted = self.crypto.encrypt_message(message, self.peer_public_key)
            # Use the appropriate socket based on whether we're server or client
            target_socket = self.client_socket if self.is_server else self.socket
            if not target_socket:
                raise ValueError("No active connection")
            
            target_socket.sendall(encrypted)
            logger.debug(f"Sent message: {message}")
            # Don't call message_callback here, let the CLI handle it
        except Exception as e:
            logger.error(f"Message send error: {e}")
            raise

    def set_message_callback(self, callback: Callable[[str, str], None]) -> None:
        """Set the callback function for handling received messages."""
        self.message_callback = callback
        logger.debug("Message callback set")

    def cleanup(self) -> None:
        """Clean up resources."""
        self.running = False
        if self.client_socket:
            try:
                self.client_socket.close()
            except Exception as e:
                logger.error(f"Client socket cleanup error: {e}")
            self.client_socket = None
        if self.socket:
            try:
                self.socket.close()
            except Exception as e:
                logger.error(f"Socket cleanup error: {e}")
            self.socket = None