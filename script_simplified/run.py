import os
import sys
import argparse
import socket
import sqlite3
import threading
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

# Configuration
DEFAULT_PORT = 65432
DB_NAME = "chat_history.db"
KEYS_DIR = "keys"

class CryptoManager:
    def __init__(self):
        os.makedirs(KEYS_DIR, exist_ok=True)
        self.private_key, self.public_key = self.load_or_generate_keys()
        self.session_key = None

    def load_or_generate_keys(self):
        priv_path = os.path.join(KEYS_DIR, "private_key.pem")
        pub_path = os.path.join(KEYS_DIR, "public_key.pem")

        if not os.path.exists(priv_path):
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            with open(priv_path, 'wb') as f:
                f.write(pem)

            public_key = private_key.public_key()
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with open(pub_path, 'wb') as f:
                f.write(pem)
        else:
            with open(priv_path, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
            with open(pub_path, "rb") as f:
                public_key = serialization.load_pem_public_key(
                    f.read(),
                    backend=default_backend()
                )

        return private_key, public_key

    def encrypt_message(self, message, public_key):
        if not self.session_key:
            self.session_key = Fernet.generate_key()
        
        fernet = Fernet(self.session_key)
        encrypted_msg = fernet.encrypt(message.encode())

        encrypted_key = public_key.encrypt(
            self.session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_key + encrypted_msg

    def decrypt_message(self, encrypted_data):
        encrypted_key = encrypted_data[:256]
        encrypted_msg = encrypted_data[256:]

        session_key = self.private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        fernet = Fernet(session_key)
        return fernet.decrypt(encrypted_msg).decode()

class DatabaseManager:
    def __init__(self):
        self.conn = sqlite3.connect(DB_NAME, check_same_thread=False)
        self.create_table()

    def create_table(self):
        cursor = self.conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS messages
                         (id INTEGER PRIMARY KEY AUTOINCREMENT,
                          timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                          sender TEXT,
                          message TEXT)''')
        self.conn.commit()

    def save_message(self, sender, message):
        cursor = self.conn.cursor()
        cursor.execute("INSERT INTO messages (sender, message) VALUES (?, ?)",
                      (sender, message))
        self.conn.commit()

    def get_history(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT timestamp, sender, message FROM messages ORDER BY timestamp")
        return cursor.fetchall()

class ChatApp:
    def __init__(self):
        self.crypto = CryptoManager()
        self.db = DatabaseManager()
        self.running = True
        self.peer_public_key = None

    def start_server(self, port=DEFAULT_PORT):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('0.0.0.0', port))
        server.listen(1)
        print(f"Listening on port {port}...")

        client_sock, addr = server.accept()
        print(f"Connected to {addr}")
        self.handle_connection(client_sock)

    def connect_to_peer(self, host, port=DEFAULT_PORT):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        print(f"Connected to {host}:{port}")
        self.handle_connection(sock)

    def handle_connection(self, sock):
        # Exchange public keys
        local_pubkey = self.crypto.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        sock.sendall(local_pubkey)
        peer_pubkey = sock.recv(1024)
        self.peer_public_key = serialization.load_pem_public_key(
            peer_pubkey,
            backend=default_backend()
        )

        # Start threads
        threading.Thread(target=self.receive_messages, args=(sock,)).start()
        self.send_messages(sock)

    def receive_messages(self, sock):
        while self.running:
            try:
                data = sock.recv(4096)
                if not data:
                    break
                
                message = self.crypto.decrypt_message(data)
                self.db.save_message("Peer", message)
                print(f"\nPeer: {message}\nYou: ", end="", flush=True)
            except Exception as e:
                print(f"\nConnection error: {e}")
                break

    def send_messages(self, sock):
        try:
            while self.running:
                message = input("You: ")
                encrypted = self.crypto.encrypt_message(message, self.peer_public_key)
                sock.sendall(encrypted)
                self.db.save_message("You", message)
        except KeyboardInterrupt:
            self.running = False
            sock.close()
            print("\nChat ended")

    def show_history(self):
        messages = self.db.get_history()
        for timestamp, sender, message in messages:
            print(f"[{timestamp}] {sender}: {message}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="P2P Encrypted Chat")
    parser.add_argument("--connect", help="IP address of peer to connect to")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port number")
    parser.add_argument("--history", action="store_true", help="Show chat history")
    args = parser.parse_args()

    app = ChatApp()

    if args.history:
        app.show_history()
        sys.exit()

    if args.connect:
        app.connect_to_peer(args.connect, args.port)
    else:
        app.start_server(args.port)