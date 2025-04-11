"""
Command-line interface for the P2P chat application.
"""
import sys
import logging
import argparse
import threading
import socket
import uuid
from typing import Optional
from .crypto import CryptoManager
from .network import NetworkManager
from .storage import DatabaseManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ANSI color codes
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class ChatCLI:
    def __init__(self, name: Optional[str] = None):
        self.crypto = CryptoManager()
        self.network = NetworkManager(self.crypto)
        self.storage = DatabaseManager()
        self.running = False
        self.input_thread = None
        self.message_lock = threading.Lock()
        self.display_lock = threading.Lock()
        self.name = name or f"User_{str(uuid.uuid4())[:8]}"
        self.peer_name = None
        # Assign colors to users
        self.my_color = Colors.GREEN
        self.peer_color = Colors.CYAN

    def get_local_ip(self) -> str:
        """Get the local IP address of the machine."""
        try:
            # Create a socket to get the local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Doesn't actually connect, just gets the local IP
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return "127.0.0.1"  # Fallback to localhost

    def display_outgoing_message(self, sender: str, message: str) -> None:
        """Display a message in a thread-safe way."""
        with self.display_lock:
            # Print the message with the sender prefix
            #print(f"\n{sender}: {message}")
            # Print the prompt for the next message
            print(f"{self.my_color}{self.name}{Colors.ENDC}: ", end="", flush=True)

    def display_incoming_message(self, sender: str, message: str) -> None:
        """Display a message in a thread-safe way."""
        with self.display_lock:
            # Print the message with the sender prefix
            print(f"\r{self.peer_color}{sender}{Colors.ENDC}: {message}", end="", flush=True)
            # Print the prompt for the next message
            print(f"\n{self.my_color}{self.name}{Colors.ENDC}: ", end="", flush=True)

    def handle_message(self, sender: str, message: str) -> None:
        """Handle incoming messages from the peer."""
        try:
            with self.message_lock:
                # Update peer name if not set
                if self.peer_name is None:
                    self.peer_name = sender
                
                # Save and display messages from the peer
                if sender == self.peer_name:
                    self.storage.save_message(sender, message)
                    self.display_incoming_message(sender, message)
        except Exception as e:
            logger.error(f"Failed to handle message: {e}")

    def show_history(self, limit: Optional[int] = None) -> None:
        """Display chat history."""
        try:
            messages = self.storage.get_history(limit)
            if not messages:
                print("No chat history available.")
                return

            print("\nChat History:")
            print("-" * 50)
            for timestamp, sender, message, is_encrypted in messages:
                encrypted_status = "[Encrypted]" if is_encrypted else ""
                color = self.my_color if sender == self.name else self.peer_color
                print(f"[{timestamp}] {color}{sender}{Colors.ENDC}: {message} {encrypted_status}")
            print("-" * 50)
        except Exception as e:
            logger.error(f"Failed to show history: {e}")

    def handle_input(self) -> None:
        """Handle user input in a separate thread."""
        while self.running:
            try:
                message = input()
                if message.strip():
                    with self.message_lock:
                        # Send the message to the peer
                        self.network.send_message(message)
                        # Save our own message
                        self.storage.save_message(self.name, message)
                        # Display our message
                        self.display_outgoing_message(self.name, message)
            except Exception as e:
                if self.running:
                    logger.error(f"Error sending message: {e}")
                    print(f"{self.my_color}{self.name}{Colors.ENDC}: ", end="", flush=True)

    def start_chat(self, connect_to: Optional[str] = None, port: int = 65432) -> None:
        """Start the chat application."""
        try:
            self.running = True
            self.network.set_message_callback(self.handle_message)

            # Start input handling thread
            self.input_thread = threading.Thread(target=self.handle_input)
            self.input_thread.daemon = True
            self.input_thread.start()

            if connect_to:
                print(f"Connecting to {connect_to}:{port} as {self.my_color}{self.name}{Colors.ENDC}...")
                self.network.connect_to_peer(connect_to, port, self.name)
            else:
                local_ip = self.get_local_ip()
                print(f"Starting server on {local_ip}:{port} as {self.my_color}{self.name}{Colors.ENDC}...")
                print(f"Other users can connect using: python -m src.cli --connect {local_ip} --port {port} --name <your_name>")
                self.network.start_server(port=port, name=self.name)

            print("\nChat started. Type your messages (Ctrl+C to quit):")
            print(f"{self.my_color}{self.name}{Colors.ENDC}: ", end="", flush=True)

            # Wait for the network thread to finish
            if self.network.receive_thread:
                self.network.receive_thread.join()

        except KeyboardInterrupt:
            print("\nEnding chat...")
            self.running = False
        except Exception as e:
            logger.error(f"Chat error: {e}")
            raise
        finally:
            self.running = False
            if self.input_thread:
                self.input_thread.join(timeout=1.0)

def main():
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(description="P2P Encrypted Chat")
    parser.add_argument("--connect", help="IP address of peer to connect to")
    parser.add_argument("--port", type=int, default=65432, help="Port number")
    parser.add_argument("--name", help="Your chat name/alias")
    parser.add_argument("--history", action="store_true", help="Show chat history")
    parser.add_argument("--history-limit", type=int, help="Limit number of history entries to show")
    parser.add_argument("--clear-history", action="store_true", help="Clear chat history")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        cli = ChatCLI(name=args.name)

        if args.clear_history:
            cli.storage.clear_history()
            print("Chat history cleared.")
            return

        if args.history:
            cli.show_history(args.history_limit)
            return

        cli.start_chat(args.connect, args.port)

    except Exception as e:
        logger.error(f"Application error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()