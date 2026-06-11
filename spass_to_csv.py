#!/usr/bin/env python3
"""
Samsung Pass to CSV Converter.

Decrypts Samsung Pass (.spass) export files and converts password entries to
Raw, Chrome, or Proton Pass compatible CSV files.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import csv
import os
import sys
from dataclasses import dataclass
from getpass import getpass
from pathlib import Path
from typing import Iterable

try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:
    print("Error: Required library 'cryptography' not found.", file=sys.stderr)
    print("Install it using: pip install -r requirements.txt", file=sys.stderr)
    sys.exit(1)


class SPassError(Exception):
    """Base error for user-facing converter failures."""


class DecryptionError(SPassError):
    """Raised when a .spass file cannot be decrypted."""


class SPassFormatError(SPassError):
    """Raised when decrypted Samsung Pass data is malformed."""


@dataclass(frozen=True)
class SPassTable:
    """One decoded Samsung Pass table."""

    type: str
    headers: list[str]
    rows: list[dict[str, str]]


@dataclass(frozen=True)
class ParsedSPass:
    """Parsed Samsung Pass export data."""

    version: str
    data_types: list[str]
    tables: list[SPassTable]

    @property
    def password_table(self) -> SPassTable | None:
        for table in self.tables:
            if table.type == "passwords":
                return table
        return None

    @property
    def passwords(self) -> list[dict[str, str]]:
        table = self.password_table
        return table.rows if table is not None else []


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


class SPassParser:
    """Parse decrypted Samsung Pass data into typed tables."""

    DEFAULT_TABLE_TYPES = ["passwords", "cards", "addresses", "notes"]
    TYPE_ALIASES = {
        "password": "passwords",
        "passwords": "passwords",
        "credential": "passwords",
        "credentials": "passwords",
        "card": "cards",
        "cards": "cards",
        "address": "addresses",
        "addresses": "addresses",
        "identity": "addresses",
        "identities": "addresses",
        "note": "notes",
        "notes": "notes",
        "secure_note": "notes",
        "secure_notes": "notes",
    }

    @classmethod
    def parse_decrypted_data(cls, decrypted_data: str) -> ParsedSPass:
        lines = [line.strip("\r") for line in decrypted_data.splitlines()]
        if len(lines) < 4:
            raise SPassFormatError("Invalid .spass data: expected header and at least one table")

        version = lines[0].strip()
        data_types = cls._parse_data_types(lines[1].strip())
        table_chunks = cls._split_table_chunks(lines[2:])
        if not table_chunks:
            raise SPassFormatError("Invalid .spass data: no data tables found")

        tables = []
        for index, chunk in enumerate(table_chunks):
            table_type = cls._table_type_for_index(index, data_types)
            tables.append(cls._parse_table(table_type, chunk, index + 1))

        return ParsedSPass(version=version, data_types=data_types, tables=tables)

    @classmethod
    def _parse_data_types(cls, line: str) -> list[str]:
        tokens = [token.strip().lower() for token in line.replace(",", ";").split(";")]
        tokens = [token for token in tokens if token]

        if tokens and all(token in {"true", "false"} for token in tokens):
            enabled = []
            for index, token in enumerate(tokens[: len(cls.DEFAULT_TABLE_TYPES)]):
                if token == "true":
                    enabled.append(cls.DEFAULT_TABLE_TYPES[index])
            return enabled

        parsed = []
        for token in tokens:
            alias = cls.TYPE_ALIASES.get(token)
            if alias is not None:
                parsed.append(alias)
        return parsed

    @staticmethod
    def _split_table_chunks(lines: Iterable[str]) -> list[list[str]]:
        tables: list[list[str]] = []
        current_table: list[str] | None = None

        for raw_line in lines:
            line = raw_line.strip()
            if not line:
                continue

            if line == "next_table":
                if current_table is not None:
                    if not current_table:
                        raise SPassFormatError("Invalid .spass data: empty table section")
                    tables.append(current_table)
                current_table = []
                continue

            if current_table is None:
                continue

            current_table.append(line)

        if current_table is not None:
            if not current_table:
                raise SPassFormatError("Invalid .spass data: trailing empty table section")
            tables.append(current_table)

        return tables

    @classmethod
    def _table_type_for_index(cls, index: int, data_types: list[str]) -> str:
        if index < len(data_types):
            return data_types[index]
        if not data_types and index < len(cls.DEFAULT_TABLE_TYPES):
            return cls.DEFAULT_TABLE_TYPES[index]
        return f"table_{index + 1}"

    @classmethod
    def _parse_table(cls, table_type: str, lines: list[str], table_number: int) -> SPassTable:
        headers = [header.strip() for header in lines[0].split(";")]
        if not headers or any(not header for header in headers):
            raise SPassFormatError(f"Table {table_number} has invalid headers")

        rows = []
        for row_number, line in enumerate(lines[1:], start=1):
            fields = line.split(";")
            if len(fields) > len(headers):
                raise SPassFormatError(
                    f"Table {table_number} row {row_number} has more fields than headers"
                )
            fields.extend([""] * (len(headers) - len(fields)))

            row = {}
            for header, field in zip(headers, fields):
                row[header] = cls._decode_field(field, table_number, row_number, header)
            rows.append(row)

        return SPassTable(type=table_type, headers=headers, rows=rows)

    @staticmethod
    def _decode_field(field: str, table_number: int, row_number: int, header: str) -> str:
        if field == "":
            return ""

        padded = field + "=" * (-len(field) % 4)
        try:
            decoded = base64.b64decode(padded, validate=True)
        except binascii.Error as exc:
            raise SPassFormatError(
                f"Invalid base64 in table {table_number}, row {row_number}, field '{header}'"
            ) from exc

        try:
            return decoded.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SPassFormatError(
                f"Invalid UTF-8 in table {table_number}, row {row_number}, field '{header}'"
            ) from exc


class CSVExporter:
    """Export parsed password entries to supported CSV formats."""

    FORMATS = {"raw", "chrome", "proton"}

    @classmethod
    def export_passwords(cls, parsed: ParsedSPass, output_path: str | Path, format_name: str) -> int:
        if format_name not in cls.FORMATS:
            raise ValueError(f"Unsupported output format: {format_name}")

        password_table = parsed.password_table
        if password_table is None:
            raise SPassFormatError("No password table found in the Samsung Pass export")

        if format_name == "raw":
            headers = password_table.headers
            rows = password_table.rows
        elif format_name == "chrome":
            headers = ["name", "url", "username", "password", "note"]
            rows = [cls._mapped_password_row(entry, include_totp=False) for entry in password_table.rows]
        else:
            headers = ["name", "url", "username", "password", "note", "totp"]
            rows = [cls._mapped_password_row(entry, include_totp=True) for entry in password_table.rows]

        cls._write_csv(Path(output_path), headers, rows)
        return len(rows)

    @classmethod
    def _mapped_password_row(cls, entry: dict[str, str], include_totp: bool) -> dict[str, str]:
        row = {
            "name": cls._first_value(entry, "title", "name", "host_url", "origin_url", "url"),
            "url": cls._first_value(entry, "host_url", "origin_url", "url"),
            "username": cls._first_value(entry, "username_value", "username", "email"),
            "password": cls._first_value(entry, "password_value", "password"),
            "note": cls._first_value(entry, "credential_memo", "note", "notes"),
        }
        if include_totp:
            row["totp"] = cls._first_value(entry, "otp", "totp")
        return row

    @staticmethod
    def _first_value(entry: dict[str, str], *keys: str) -> str:
        for key in keys:
            value = entry.get(key, "")
            if value:
                return value
        return ""

    @staticmethod
    def _write_csv(output_path: Path, headers: list[str], rows: list[dict[str, str]]) -> None:
        if output_path.parent and not output_path.parent.exists():
            raise FileNotFoundError(f"Output directory does not exist: {output_path.parent}")

        fd = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            try:
                if hasattr(os, "fchmod"):
                    os.fchmod(fd, 0o600)
            except OSError:
                pass

            with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
                fd = -1
                writer = csv.DictWriter(
                    handle,
                    fieldnames=headers,
                    extrasaction="ignore",
                    lineterminator="\n",
                )
                writer.writeheader()
                writer.writerows(rows)
        finally:
            if fd != -1:
                os.close(fd)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Decrypt a Samsung Pass .spass export and write password entries as CSV."
    )
    parser.add_argument("-i", "--input", required=True, help="Path to the Samsung Pass .spass file")
    parser.add_argument(
        "-o",
        "--output",
        help="Output CSV path. Defaults to '<input-stem>_passwords.csv'.",
    )
    parser.add_argument(
        "--format",
        choices=sorted(CSVExporter.FORMATS),
        default="raw",
        help="CSV output format. Default: raw.",
    )
    parser.add_argument(
        "--password-stdin",
        action="store_true",
        help="Read the export password from stdin instead of an interactive prompt.",
    )
    return parser


def read_password(password_stdin: bool) -> str:
    if password_stdin:
        password = sys.stdin.readline().rstrip("\r\n")
    else:
        password = getpass("Export password: ")

    if not password:
        raise SPassFormatError("Password required")
    return password


def default_output_path(input_path: Path) -> Path:
    return input_path.with_name(f"{input_path.stem}_passwords.csv")


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    input_path = Path(args.input).expanduser()
    output_path = Path(args.output).expanduser() if args.output else default_output_path(input_path)

    try:
        password = read_password(args.password_stdin)
        decrypted = SPassDecryptor(password).decrypt_file(input_path)
        parsed = SPassParser.parse_decrypted_data(decrypted)
        count = CSVExporter.export_passwords(parsed, output_path, args.format)
    except (SPassError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    table_summary = ", ".join(f"{table.type}={len(table.rows)}" for table in parsed.tables)
    print(f"Parsed Samsung Pass export version {parsed.version}: {table_summary}")
    print(f"Exported {count} password entries to {output_path}")
    print("Security: the CSV contains plaintext passwords. Delete it after import.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
