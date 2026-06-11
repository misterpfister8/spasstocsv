from __future__ import annotations

import base64
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from spass_to_csv import (
    CSVExporter,
    DecryptionError,
    SPassDecryptor,
    SPassFormatError,
    SPassParser,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
DEMO_SPASS = FIXTURES / "demo_full.spass"
DEMO_DECRYPTED = FIXTURES / "demo_decrypted.txt"


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

    def test_invalid_decrypted_table_errors(self) -> None:
        invalid_data = "25\ntrue\nfalse\nnext_table\ntitle\nnot-base64!\n"

        with self.assertRaises(SPassFormatError):
            SPassParser.parse_decrypted_data(invalid_data)

    def test_parser_reads_all_tables_and_password_entries(self) -> None:
        parsed = SPassParser.parse_decrypted_data(DEMO_DECRYPTED.read_text(encoding="utf-8"))

        self.assertEqual(parsed.version, "25")
        self.assertEqual([table.type for table in parsed.tables], ["passwords", "cards", "addresses", "notes"])
        self.assertEqual(len(parsed.passwords), 2)
        self.assertEqual(parsed.passwords[0]["title"], "Example Login")
        self.assertEqual(parsed.passwords[0]["username_value"], "alice@example.com")
        self.assertEqual(parsed.tables[1].rows[0]["card_number"], "4111111111111111")
        self.assertEqual(parsed.tables[2].rows[0]["country_code"], "CH")
        self.assertEqual(parsed.tables[3].rows[0]["note_title"], "Demo Note")

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

    def test_cli_password_stdin_hands_on_for_all_formats(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            for format_name in ("raw", "chrome", "proton"):
                with self.subTest(format=format_name):
                    output = Path(tmpdir) / f"{format_name}.csv"
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
                    expected = (FIXTURES / f"expected_{format_name}.csv").read_text(
                        encoding="utf-8"
                    )
                    self.assertEqual(output.read_text(encoding="utf-8"), expected)
                    self.assertIn("Exported 2 password entries", result.stdout)


if __name__ == "__main__":
    unittest.main()
