"""
Cryptographic operations for the P2P chat application.
"""
import os
import logging
from typing import Tuple, Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from . import config

logger = logging.getLogger(__name__)

class CryptoManager:
    def __init__(self):
        self.private_key: Optional[rsa.RSAPrivateKey] = None
        self.public_key: Optional[rsa.RSAPublicKey] = None
        self.session_key: Optional[bytes] = None
        self._load_or_generate_keys()

    def _load_or_generate_keys(self) -> None:
        """Load existing keys or generate new ones if they don't exist."""
        priv_path = os.path.join(config.KEYS_DIR, "private_key.pem")
        pub_path = os.path.join(config.KEYS_DIR, "public_key.pem")

        if not os.path.exists(priv_path):
            logger.info("Generating new RSA key pair")
            self._generate_keys(priv_path, pub_path)
        else:
            logger.info("Loading existing RSA keys")
            self._load_keys(priv_path, pub_path)

    def _generate_keys(self, priv_path: str, pub_path: str) -> None:
        """Generate new RSA key pair and save to files."""
        try:
            private_key = rsa.generate_private_key(
                public_exponent=config.RSA_PUBLIC_EXPONENT,
                key_size=config.RSA_KEY_SIZE,
                backend=default_backend()
            )
            
            # Save private key
            with open(priv_path, 'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            # Save public key
            public_key = private_key.public_key()
            with open(pub_path, 'wb') as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))

            self.private_key = private_key
            self.public_key = public_key
        except Exception as e:
            logger.error(f"Failed to generate keys: {e}")
            raise

    def _load_keys(self, priv_path: str, pub_path: str) -> None:
        """Load existing RSA keys from files."""
        try:
            with open(priv_path, "rb") as f:
                self.private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
            with open(pub_path, "rb") as f:
                self.public_key = serialization.load_pem_public_key(
                    f.read(),
                    backend=default_backend()
                )
        except Exception as e:
            logger.error(f"Failed to load keys: {e}")
            raise

    def get_public_key_bytes(self) -> bytes:
        """Get the public key in PEM format."""
        if not self.public_key:
            raise ValueError("Public key not initialized")
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def encrypt_message(self, message: str, peer_public_key: rsa.RSAPublicKey) -> bytes:
        """Encrypt a message using hybrid encryption (RSA + Fernet)."""
        try:
            if not self.session_key:
                self.session_key = Fernet.generate_key()
            
            fernet = Fernet(self.session_key)
            encrypted_msg = fernet.encrypt(message.encode())

            encrypted_key = peer_public_key.encrypt(
                self.session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return encrypted_key + encrypted_msg
        except Exception as e:
            logger.error(f"Failed to encrypt message: {e}")
            raise

    def decrypt_message(self, encrypted_data: bytes) -> str:
        """Decrypt a message using hybrid decryption."""
        try:
            if not self.private_key:
                raise ValueError("Private key not initialized")

            encrypted_key = encrypted_data[:256]  # RSA-2048 encrypted key
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
        except Exception as e:
            logger.error(f"Failed to decrypt message: {e}")
            raise