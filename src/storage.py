# storage.py
import sqlite3
import logging
import base64
import os
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
        self.create_tables()
        # Load or generate encryption key
        self.db_key = self._load_or_generate_key()
        self.db_cipher = Fernet(self.db_key)

    def create_tables(self) -> None:
        """Create the required tables if they don't exist."""
        try:
            cursor = self.conn.cursor()
            # Create messages table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    sender TEXT NOT NULL,
                    message TEXT NOT NULL,
                    is_encrypted BOOLEAN DEFAULT 1
                )
            ''')
            # Create encryption key table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS encryption_key (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    key_data BLOB NOT NULL
                )
            ''')
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to create tables: {e}")
            raise

    def _load_or_generate_key(self) -> bytes:
        """Load existing key from database or generate a new one."""
        try:
            cursor = self.conn.cursor()
            # Try to get existing key
            cursor.execute('SELECT key_data FROM encryption_key WHERE id = 1')
            result = cursor.fetchone()
            
            if result:
                return result[0]
            else:
                # Generate new key
                key = Fernet.generate_key()
                # Save the key in database
                cursor.execute(
                    'INSERT INTO encryption_key (id, key_data) VALUES (1, ?)',
                    (key,)
                )
                self.conn.commit()
                return key
        except Exception as e:
            logger.error(f"Failed to load/generate key: {e}")
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
            
            # Decrypt messages before returning
            messages = []
            for row in cursor.fetchall():
                timestamp, sender, message, is_encrypted = row
                if is_encrypted:
                    try:
                        # Decrypt the message
                        decrypted_message = self.db_cipher.decrypt(message.encode()).decode()
                        messages.append((timestamp, sender, decrypted_message, is_encrypted))
                    except Exception as e:
                        logger.error(f"Failed to decrypt message: {e}")
                        messages.append((timestamp, sender, "[Decryption Failed]", is_encrypted))
                else:
                    messages.append(row)
            
            return messages
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