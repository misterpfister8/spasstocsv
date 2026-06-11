"""Samsung Pass .spass decryption."""

from __future__ import annotations

import base64
import binascii
from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from spasstocsv.errors import DecryptionError, SPassFormatError


class SPassDecryptor:
    """Decrypt Samsung Pass .spass files."""

    SALT_BYTES = 20
    IV_BYTES = 16
    ITERATION_COUNT = 70000
    KEY_LENGTH = 32
    BLOCK_SIZE = 128
    AES_BLOCK_BYTES = 16

    def __init__(self, password: str):
        self.password = password

    def decrypt_file(self, file_path: str | Path) -> str:
        path = Path(file_path)
        encrypted_data = self._read_base64_file(path)
        encrypted_bytes = self._decode_file_base64(encrypted_data)

        minimum_size = self.SALT_BYTES + self.IV_BYTES + self.AES_BLOCK_BYTES
        if len(encrypted_bytes) < minimum_size:
            raise DecryptionError(
                ".spass payload is too short to contain salt, IV, and ciphertext"
            )

        salt = encrypted_bytes[: self.SALT_BYTES]
        iv = encrypted_bytes[self.SALT_BYTES : self.SALT_BYTES + self.IV_BYTES]
        ciphertext = encrypted_bytes[self.SALT_BYTES + self.IV_BYTES :]

        if len(ciphertext) % self.AES_BLOCK_BYTES != 0:
            raise DecryptionError(".spass ciphertext length is not a valid AES block size")

        key = self._derive_key(salt)
        return self._decrypt_ciphertext(key, iv, ciphertext)

    @staticmethod
    def _read_base64_file(path: Path) -> str:
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")
        if path.is_dir():
            raise SPassFormatError(f"Input path is a directory, not a .spass file: {path}")
        if path.suffix.lower() != ".spass":
            raise SPassFormatError(f"Input file must have a .spass extension: {path}")

        raw_text = path.read_text(encoding="utf-8")
        return "".join(raw_text.split())

    @staticmethod
    def _decode_file_base64(base64_data: str) -> bytes:
        if not base64_data:
            raise DecryptionError(".spass file is empty")
        try:
            return base64.b64decode(base64_data, validate=True)
        except binascii.Error as exc:
            raise DecryptionError(f".spass file is not valid base64: {exc}") from exc

    def _derive_key(self, salt: bytes) -> bytes:
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.KEY_LENGTH,
                salt=salt,
                iterations=self.ITERATION_COUNT,
                backend=default_backend(),
            )
            return kdf.derive(self.password.encode("utf-8"))
        except Exception as exc:
            raise DecryptionError(f"Key derivation failed: {exc}") from exc

    def _decrypt_ciphertext(self, key: bytes, iv: bytes, ciphertext: bytes) -> str:
        try:
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded = decryptor.update(ciphertext) + decryptor.finalize()

            unpadder = padding.PKCS7(self.BLOCK_SIZE).unpadder()
            decrypted = unpadder.update(padded) + unpadder.finalize()
            text = decrypted.decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise DecryptionError(
                "Decryption failed - password is likely incorrect or file is corrupted"
            ) from exc

        if "next_table" not in text or ";" not in text:
            raise SPassFormatError("Decrypted data does not look like Samsung Pass export data")

        return text
