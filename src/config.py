"""
Configuration settings for the P2P chat application.
"""
import os

# Network settings
DEFAULT_HOST = '0.0.0.0'
DEFAULT_PORT = 65432
BUFFER_SIZE = 4096

# File paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEYS_DIR = os.path.join(BASE_DIR, 'keys')
DB_PATH = os.path.join(BASE_DIR, 'chat_history.db')

# Ensure directories exist
os.makedirs(KEYS_DIR, exist_ok=True)

# Crypto settings
RSA_KEY_SIZE = 2048
RSA_PUBLIC_EXPONENT = 65537 