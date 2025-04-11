"""
Command-line interface for the P2P chat application.
"""
import sys
import logging
import argparse
import threading
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

class ChatCLI:
    def __init__(self):
        self.crypto = CryptoManager()
        self.network = NetworkManager(self.crypto)
        self.storage = DatabaseManager()
        self.running = False
        self.input_thread = None
        self.message_lock = threading.Lock()
        self.display_lock = threading.Lock()

    def display_message(self, sender: str, message: str) -> None:
        """Display a message in a thread-safe way."""
        with self.display_lock:
            # Print the message with the sender prefix
            print(f"\n{sender}: {message}")
            # Print the prompt for the next message
            print("You: ", end="", flush=True)

    def handle_message(self, sender: str, message: str) -> None:
        """Handle incoming messages from the peer."""
        try:
            with self.message_lock:
                # Only save and display messages from the peer
                if sender == "Peer":
                    self.storage.save_message(sender, message)
                    self.display_message(sender, message)
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
                print(f"[{timestamp}] {sender}: {message} {encrypted_status}")
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
                        self.storage.save_message("You", message)
                        # Display our message
                        self.display_message("You", message)
            except Exception as e:
                if self.running:
                    logger.error(f"Error sending message: {e}")
                    print("You: ", end="", flush=True)

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
                print(f"Connecting to {connect_to}:{port}...")
                self.network.connect_to_peer(connect_to, port)
            else:
                print(f"Starting server on port {port}...")
                self.network.start_server(port=port)

            print("\nChat started. Type your messages (Ctrl+C to quit):")
            print("You: ", end="", flush=True)

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
    parser.add_argument("--history", action="store_true", help="Show chat history")
    parser.add_argument("--history-limit", type=int, help="Limit number of history entries to show")
    parser.add_argument("--clear-history", action="store_true", help="Clear chat history")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        cli = ChatCLI()

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