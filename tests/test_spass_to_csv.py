from __future__ import annotations

import base64
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from spass_to_csv import (
    CSVExporter,
    DecryptionError,
    SPassDecryptor,
    SPassFormatError,
    SPassParser,
    WarningCode,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
DEMO_SPASS = FIXTURES / "demo_full.spass"
DEMO_DECRYPTED = FIXTURES / "demo_decrypted.txt"
LEGACY_DECRYPTED = FIXTURES / "legacy_decrypted.txt"


def b64(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def encrypt_spass_text(plaintext: str, password: str) -> str:
    salt = b"spasstocsv-demo-salt"
    iv = b"demo-iv-12345678"
    key = SPassDecryptor(password)._derive_key(salt)
    padder = padding.PKCS7(SPassDecryptor.BLOCK_SIZE).padder()
    padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(salt + iv + ciphertext).decode("ascii")


class SPassConverterTests(unittest.TestCase):
    def test_decrypts_demo_spass_file(self) -> None:
        decrypted = SPassDecryptor("demo-password").decrypt_file(DEMO_SPASS)

        self.assertEqual(decrypted, DEMO_DECRYPTED.read_text(encoding="utf-8"))

    def test_wrong_password_fails_cleanly(self) -> None:
        with self.assertRaises(DecryptionError):
            SPassDecryptor("wrong-password").decrypt_file(DEMO_SPASS)

    def test_invalid_spass_file_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            invalid_base64 = Path(tmpdir) / "invalid.spass"
            invalid_base64.write_text("not base64!", encoding="utf-8")
            with self.assertRaises(DecryptionError):
                SPassDecryptor("demo-password").decrypt_file(invalid_base64)

            too_short = Path(tmpdir) / "too-short.spass"
            too_short.write_text(base64.b64encode(b"short").decode("ascii"), encoding="utf-8")
            with self.assertRaises(DecryptionError):
                SPassDecryptor("demo-password").decrypt_file(too_short)

    def test_parser_reads_all_v25_tables_and_password_entries(self) -> None:
        parsed = SPassParser.parse_decrypted_data(DEMO_DECRYPTED.read_text(encoding="utf-8"))

        self.assertEqual(parsed.version, "25")
        self.assertEqual([table.type for table in parsed.tables], ["passwords", "cards", "addresses", "notes"])
        self.assertEqual(len(parsed.passwords), 2)
        self.assertEqual(parsed.passwords[0]["title"], "Example Login")
        self.assertEqual(parsed.passwords[0]["username_value"], "alice@example.com")
        self.assertEqual(parsed.tables[1].rows[0]["card_number"], "4111111111111111")
        self.assertEqual(parsed.tables[2].rows[0]["country_code"], "CH")
        self.assertEqual(parsed.tables[3].rows[0]["note_title"], "Demo Note")

    def test_legacy_generator_style_format_is_supported_tolerantly(self) -> None:
        parsed = SPassParser.parse_decrypted_data(LEGACY_DECRYPTED.read_text(encoding="utf-8"))

        self.assertEqual(parsed.version, "version:1")
        self.assertEqual([table.type for table in parsed.tables], ["passwords", "cards", "addresses", "notes"])
        self.assertEqual(parsed.passwords[0]["origin_url"], "https://legacy.example.com")
        self.assertEqual(parsed.passwords[0]["username_value"], "legacy-user")
        self.assertEqual(parsed.passwords[0]["password_value"], "raw-password")
        self.assertEqual(parsed.passwords[0]["credential_memo"], "special äö note")
        self.assertGreaterEqual(len(parsed.warnings), 3)
        self.assertTrue(all("raw text" in warning.message for warning in parsed.warnings))
        self.assertTrue(all(warning.code == WarningCode.RAW_FIELD_FALLBACK for warning in parsed.warnings))

    def test_strict_mode_rejects_raw_legacy_fields(self) -> None:
        with self.assertRaises(SPassFormatError):
            SPassParser.parse_decrypted_data(
                LEGACY_DECRYPTED.read_text(encoding="utf-8"),
                strict=True,
            )

    def test_parser_handles_quoted_semicolon_fields(self) -> None:
        decrypted = "\n".join(
            [
                "25",
                "true",
                "false",
                "next_table",
                "title;host_url;username_value;password_value",
                f"\"raw;title\";{b64('https://semicolon.example.com')};{b64('semi@example.com')};{b64('not-a-real-password-semi')}",
            ]
        )

        parsed = SPassParser.parse_decrypted_data(decrypted)

        self.assertEqual(parsed.passwords[0]["title"], "raw;title")
        self.assertEqual(parsed.passwords[0]["host_url"], "https://semicolon.example.com")
        self.assertIn(WarningCode.RAW_FIELD_FALLBACK, [warning.code for warning in parsed.warnings])

    def test_parser_handles_crlf_exports(self) -> None:
        decrypted = "\r\n".join(
            [
                "25",
                "true",
                "false",
                "next_table",
                "title;host_url;username_value;password_value",
                f"{b64('CRLF Login')};{b64('https://crlf.example.com')};{b64('crlf@example.com')};{b64('not-a-real-password-crlf')}",
            ]
        )

        parsed = SPassParser.parse_decrypted_data(decrypted)

        self.assertEqual(parsed.version, "25")
        self.assertEqual(parsed.passwords[0]["title"], "CRLF Login")

    def test_unknown_table_and_extra_columns_emit_warning_codes(self) -> None:
        decrypted = "\n".join(
            [
                "25",
                "false",
                "false",
                "next_table",
                "mystery_name;mystery_value",
                f"{b64('alpha')};{b64('beta')};{b64('gamma')}",
            ]
        )

        parsed = SPassParser.parse_decrypted_data(decrypted)
        codes = [warning.code for warning in parsed.warnings]

        self.assertEqual(parsed.tables[0].type, "table_1")
        self.assertEqual(parsed.tables[0].headers, ["mystery_name", "mystery_value", "extra_3"])
        self.assertIn(WarningCode.UNKNOWN_TABLE, codes)
        self.assertIn(WarningCode.EXTRA_COLUMNS, codes)
        self.assertIn(WarningCode.EMPTY_PASSWORD_TABLE, codes)

    def test_export_snapshots(self) -> None:
        parsed = SPassParser.parse_decrypted_data(DEMO_DECRYPTED.read_text(encoding="utf-8"))

        for format_name in ("raw", "chrome", "proton"):
            with self.subTest(format=format_name):
                with tempfile.TemporaryDirectory() as tmpdir:
                    output = Path(tmpdir) / f"{format_name}.csv"
                    count = CSVExporter.export_passwords(parsed, output, format_name)

                    self.assertEqual(count, 2)
                    expected = (FIXTURES / f"expected_{format_name}.csv").read_text(encoding="utf-8")
                    self.assertEqual(output.read_text(encoding="utf-8"), expected)

    def test_bitwarden_json_contains_all_item_types(self) -> None:
        parsed = SPassParser.parse_decrypted_data(DEMO_DECRYPTED.read_text(encoding="utf-8"))

        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "bitwarden.json"
            count = CSVExporter.export(parsed, output, "bitwarden-json")
            payload = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(count, 5)
        self.assertFalse(payload["encrypted"])
        self.assertEqual([item["type"] for item in payload["items"]], [1, 1, 2, 3, 4])
        self.assertEqual(payload["items"][0]["login"]["username"], "alice@example.com")
        self.assertEqual(payload["items"][2]["secureNote"]["type"], 0)
        self.assertEqual(payload["items"][3]["card"]["number"], "4111111111111111")
        self.assertEqual(payload["items"][4]["identity"]["country"], "CH")

    def test_bitwarden_json_preserves_unknown_password_fields(self) -> None:
        decrypted = "\n".join(
            [
                "25",
                "true",
                "false",
                "next_table",
                "title;host_url;username_value;password_value;custom_tag",
                f"{b64('Custom Login')};{b64('https://custom.example.com')};{b64('custom@example.com')};{b64('not-a-real-password-custom')};{b64('migration-note')}",
            ]
        )
        parsed = SPassParser.parse_decrypted_data(decrypted)

        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "bitwarden.json"
            CSVExporter.export(parsed, output, "bitwarden-json")
            payload = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(
            payload["items"][0]["fields"],
            [{"name": "custom_tag", "value": "migration-note", "type": 0}],
        )

    def test_cli_list_formats(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "spass_to_csv.py"), "--list-formats"],
            text=True,
            capture_output=True,
            cwd=ROOT,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        for format_name in ("raw", "chrome", "proton", "bitwarden-json"):
            self.assertIn(format_name, result.stdout)

    def test_cli_password_stdin_hands_on_for_all_formats(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            for format_name in ("raw", "chrome", "proton", "bitwarden-json"):
                with self.subTest(format=format_name):
                    extension = "json" if format_name == "bitwarden-json" else "csv"
                    output = Path(tmpdir) / f"{format_name}.{extension}"
                    result = subprocess.run(
                        [
                            sys.executable,
                            str(ROOT / "spass_to_csv.py"),
                            "--password-stdin",
                            "-i",
                            str(DEMO_SPASS),
                            "-o",
                            str(output),
                            "--format",
                            format_name,
                        ],
                        input="demo-password\n",
                        text=True,
                        capture_output=True,
                        cwd=ROOT,
                        check=False,
                    )

                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("Created", result.stdout)
                    self.assertTrue(output.exists())

    def test_cli_inspect_does_not_print_secret_values(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "spass_to_csv.py"),
                "--password-stdin",
                "--inspect",
                "-i",
                str(DEMO_SPASS),
            ],
            input="demo-password\n",
            text=True,
            capture_output=True,
            cwd=ROOT,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("headers=[title, host_url", result.stdout)
        self.assertIn("passwords rows=2", result.stdout)
        self.assertNotIn("not-a-real-password", result.stdout)
        self.assertNotIn("alice@example.com", result.stdout)

    def test_cli_inspect_prints_warning_codes_without_values(self) -> None:
        decrypted = "\n".join(
            [
                "25",
                "true",
                "false",
                "next_table",
                "title;host_url;username_value;password_value",
                f"\"raw;title\";{b64('https://warning.example.com')};{b64('warning@example.com')};{b64('not-a-real-password-warning')}",
            ]
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            export_path = Path(tmpdir) / "warning.spass"
            export_path.write_text(encrypt_spass_text(decrypted, "demo-password"), encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "spass_to_csv.py"),
                    "--password-stdin",
                    "--inspect",
                    "-i",
                    str(export_path),
                ],
                input="demo-password\n",
                text=True,
                capture_output=True,
                cwd=ROOT,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(WarningCode.RAW_FIELD_FALLBACK, result.stdout)
        self.assertNotIn("raw;title", result.stdout)
        self.assertNotIn("not-a-real-password-warning", result.stdout)


if __name__ == "__main__":
    unittest.main()
