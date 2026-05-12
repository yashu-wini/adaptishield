# security/aes_encryptor.py
"""
AES-256 Encryption Module
Encrypts sanitized output before transmission.
Uses Fernet (AES-128-CBC with HMAC) for authenticated encryption,
or raw AES-256-GCM for maximum security.
"""

import base64
import os
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class AESEncryptor:
    """
    AES-256-GCM authenticated encryption.
    - Provides confidentiality + integrity + authenticity
    - Each encryption uses a fresh random nonce
    """

    KEY_SIZE = 32  # 256-bit

    def __init__(self, key: bytes = None):
        """Initialize with a 32-byte key. Generates one if not provided."""
        if key is None:
            self.key = os.urandom(self.KEY_SIZE)
        else:
            if len(key) != self.KEY_SIZE:
                raise ValueError(f"Key must be exactly {self.KEY_SIZE} bytes (256-bit).")
            self.key = key
        self._aesgcm = AESGCM(self.key)

    @classmethod
    def from_passphrase(cls, passphrase: str, salt: bytes = None) -> "AESEncryptor":
        """Derive a key from a passphrase using PBKDF2."""
        if salt is None:
            salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=310_000,
        )
        key = kdf.derive(passphrase.encode())
        return cls(key=key)

    def encrypt(self, plaintext: str) -> dict:
        """
        Encrypt text. Returns dict with base64-encoded ciphertext and nonce.
        """
        nonce = os.urandom(12)  # 96-bit nonce for GCM
        ciphertext = self._aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

        return {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "algorithm": "AES-256-GCM",
            "key_size": self.KEY_SIZE * 8,
        }

    def decrypt(self, encrypted_payload: dict) -> str:
        """Decrypt an encrypted payload dict."""
        nonce = base64.b64decode(encrypted_payload["nonce"])
        ciphertext = base64.b64decode(encrypted_payload["ciphertext"])
        plaintext = self._aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode("utf-8")

    def get_key_b64(self) -> str:
        """Export key as base64 string (for secure storage)."""
        return base64.b64encode(self.key).decode()

    @classmethod
    def from_key_b64(cls, key_b64: str) -> "AESEncryptor":
        """Load encryptor from base64-encoded key."""
        key = base64.b64decode(key_b64)
        return cls(key=key)

    def encrypt_payload(self, data: dict) -> dict:
        """Encrypt a dict payload as JSON."""
        json_str = json.dumps(data)
        encrypted = self.encrypt(json_str)
        return encrypted

    def decrypt_payload(self, encrypted_payload: dict) -> dict:
        """Decrypt and parse a JSON dict payload."""
        json_str = self.decrypt(encrypted_payload)
        return json.loads(json_str)
