# storage.py
import sqlite3
import logging
from typing import List, Tuple, Optional
from datetime import datetime
from contextlib import contextmanager
from . import config

logger = logging.getLogger(__name__)

class DatabaseManager:
    def __init__(self):
        self._init_db()

    @contextmanager
    def _get_connection(self):
        """Context manager for database connections."""
        conn = None
        try:
            conn = sqlite3.connect(config.DB_PATH)
            conn.row_factory = sqlite3.Row
            yield conn
        except sqlite3.Error as e:
            logger.error(f"Database error: {e}")
            raise
        finally:
            if conn:
                conn.close()

    def _init_db(self) -> None:
        """Initialize the database with required tables."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS messages (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        sender TEXT NOT NULL,
                        message TEXT NOT NULL,
                        is_encrypted BOOLEAN DEFAULT 1
                    )
                ''')
                conn.commit()
                logger.info("Database initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise

    def save_message(self, sender: str, message: str, is_encrypted: bool = True) -> None:
        """Save a message to the database."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO messages (sender, message, is_encrypted) VALUES (?, ?, ?)",
                    (sender, message, is_encrypted)
                )
                conn.commit()
                logger.debug(f"Message saved from {sender}")
        except Exception as e:
            logger.error(f"Failed to save message: {e}")
            raise

    def get_history(self, limit: Optional[int] = None) -> List[Tuple[datetime, str, str, bool]]:
        """Retrieve chat history."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                query = "SELECT timestamp, sender, message, is_encrypted FROM messages ORDER BY timestamp DESC"
                if limit:
                    query += f" LIMIT {limit}"
                cursor.execute(query)
                return [(datetime.fromisoformat(row['timestamp']), 
                        row['sender'], 
                        row['message'],
                        bool(row['is_encrypted']))
                       for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to retrieve chat history: {e}")
            raise

    def clear_history(self) -> None:
        """Clear all messages from the database."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM messages")
                conn.commit()
                logger.info("Chat history cleared")
        except Exception as e:
            logger.error(f"Failed to clear chat history: {e}")
            raise