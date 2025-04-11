# storage.py
import sqlite3
import logging
import base64
from typing import List, Tuple, Optional
from cryptography.fernet import Fernet
from .crypto import CryptoManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DatabaseManager:
    def __init__(self, crypto: Optional[CryptoManager] = None):
        """Initialize the database manager with optional crypto manager."""
        self.conn = sqlite3.connect('chat_history.db', check_same_thread=False)
        self.crypto = crypto
        # Generate a separate key for database encryption
        self.db_key = Fernet.generate_key()
        self.db_cipher = Fernet(self.db_key)
        self.create_table()

    def create_table(self) -> None:
        """Create the messages table if it doesn't exist."""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    sender TEXT NOT NULL,
                    message TEXT NOT NULL,
                    is_encrypted BOOLEAN DEFAULT 1
                )
            ''')
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to create table: {e}")
            raise

    def save_message(self, sender: str, message: str, encrypt: bool = True) -> None:
        """Save a message to the database."""
        try:
            cursor = self.conn.cursor()
            if encrypt:
                # Encrypt the message using Fernet (symmetric encryption)
                encrypted_message = self.db_cipher.encrypt(message.encode()).decode()
                cursor.execute(
                    'INSERT INTO messages (sender, message, is_encrypted) VALUES (?, ?, ?)',
                    (sender, encrypted_message, 1)
                )
            else:
                # Store the message as is
                cursor.execute(
                    'INSERT INTO messages (sender, message, is_encrypted) VALUES (?, ?, ?)',
                    (sender, message, 0)
                )
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to save message: {e}")
            raise

    def get_history(self, limit: Optional[int] = None) -> List[Tuple]:
        """Retrieve chat history."""
        try:
            cursor = self.conn.cursor()
            if limit:
                cursor.execute(
                    'SELECT timestamp, sender, message, is_encrypted FROM messages ORDER BY timestamp DESC LIMIT ?',
                    (limit,)
                )
            else:
                cursor.execute(
                    'SELECT timestamp, sender, message, is_encrypted FROM messages ORDER BY timestamp DESC'
                )
            return cursor.fetchall()
        except Exception as e:
            logger.error(f"Failed to retrieve history: {e}")
            raise

    def clear_history(self) -> None:
        """Clear all messages from the database."""
        try:
            cursor = self.conn.cursor()
            cursor.execute('DELETE FROM messages')
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to clear history: {e}")
            raise

    def __del__(self) -> None:
        """Clean up database connection."""
        try:
            self.conn.close()
        except Exception as e:
            logger.error(f"Failed to close database connection: {e}")