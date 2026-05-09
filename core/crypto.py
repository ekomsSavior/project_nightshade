"""
Nightshade Crypto — AES-256-GCM encryption with HKDF key derivation.
Replaces legacy AES-CBC with proper authenticated encryption.
"""
import base64
import hashlib
import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256


class NightshadeCrypto:
    """Authenticated encryption for C2 payloads using AES-256-GCM + HKDF."""

    KEY_SALT = b"nightshade_v3_salt"
    KEY_LENGTH = 32  # AES-256
    NONCE_LENGTH = 12  # GCM standard
    TAG_LENGTH = 16

    def __init__(self, passphrase: str):
        self._passphrase = passphrase
        self._derived_key = self._derive_key(passphrase)

    def _derive_key(self, passphrase: str) -> bytes:
        """HKDF-SHA256 key derivation — no hardcoded IV, no ECB padded keys."""
        return HKDF(
            master=passphrase.encode("utf-8"),
            key_len=self.KEY_LENGTH,
            salt=self.KEY_SALT,
            hashmod=SHA256,
            context=b"nightshade-c2-v3",
        )

    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext → base64(nonce + ciphertext + tag)."""
        data = plaintext.encode("utf-8")
        nonce = os.urandom(self.NONCE_LENGTH)
        cipher = AES.new(self._derived_key, AES.MODE_GCM, nonce=nonce)
        ct, tag = cipher.encrypt_and_digest(data)
        return base64.b64encode(nonce + ct + tag).decode()

    def decrypt(self, ciphertext_b64: str) -> str | None:
        """Decrypt base64(nonce + ciphertext + tag) → plaintext or None."""
        try:
            raw = base64.b64decode(ciphertext_b64)
            nonce = raw[: self.NONCE_LENGTH]
            tag = raw[-self.TAG_LENGTH :]
            ct = raw[self.NONCE_LENGTH : -self.TAG_LENGTH]
            cipher = AES.new(self._derived_key, AES.MODE_GCM, nonce=nonce)
            pt = cipher.decrypt_and_verify(ct, tag)
            return pt.decode("utf-8")
        except (ValueError, KeyError, IndexError, UnicodeDecodeError):
            return None

    @staticmethod
    def random_key(length: int = 16) -> str:
        """Generate a random printable key for campaign configs."""
        return base64.urlsafe_b64encode(os.urandom(length)).decode().rstrip("=")
