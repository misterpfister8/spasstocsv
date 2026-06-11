"""CSV and Bitwarden JSON exporters."""

from __future__ import annotations

import csv
import json
import os
from pathlib import Path
from typing import Any

from spasstocsv.errors import SPassFormatError
from spasstocsv.models import ParsedSPass, SPassTable


class CSVExporter:
    """Export parsed entries to supported formats."""

    FORMATS = {"raw", "chrome", "proton", "bitwarden-json"}

    @classmethod
    def export(cls, parsed: ParsedSPass, output_path: str | Path, format_name: str) -> int:
        if format_name == "bitwarden-json":
            return cls.export_bitwarden_json(parsed, output_path)
        return cls.export_passwords(parsed, output_path, format_name)

    @classmethod
    def export_passwords(cls, parsed: ParsedSPass, output_path: str | Path, format_name: str) -> int:
        if format_name not in {"raw", "chrome", "proton"}:
            raise ValueError(f"Unsupported CSV output format: {format_name}")

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

        cls._write_text_file(
            Path(output_path),
            lambda handle: cls._write_csv(handle, headers, rows),
        )
        return len(rows)

    @classmethod
    def export_bitwarden_json(cls, parsed: ParsedSPass, output_path: str | Path) -> int:
        items = []
        items.extend(cls._bitwarden_login_items(parsed.table("passwords")))
        items.extend(cls._bitwarden_note_items(parsed.table("notes")))
        items.extend(cls._bitwarden_card_items(parsed.table("cards")))
        items.extend(cls._bitwarden_identity_items(parsed.table("addresses")))

        payload = {"encrypted": False, "items": items}
        cls._write_text_file(
            Path(output_path),
            lambda handle: cls._write_json(handle, payload),
        )
        return len(items)

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

    @classmethod
    def _bitwarden_login_items(cls, table: SPassTable | None) -> list[dict[str, Any]]:
        if table is None:
            return []

        items = []
        for row in table.rows:
            url = cls._first_value(row, "host_url", "origin_url", "url")
            login: dict[str, Any] = {
                "uris": [{"uri": url}] if url else [],
                "username": cls._first_value(row, "username_value", "username", "email"),
                "password": cls._first_value(row, "password_value", "password"),
            }
            totp = cls._first_value(row, "otp", "totp")
            if totp:
                login["totp"] = totp

            item = {
                "type": 1,
                "name": cls._first_value(row, "title", "name", "host_url", "origin_url", "url"),
                "login": login,
            }
            note = cls._first_value(row, "credential_memo", "note", "notes")
            if note:
                item["notes"] = note
            items.append(item)
        return items

    @classmethod
    def _bitwarden_note_items(cls, table: SPassTable | None) -> list[dict[str, Any]]:
        if table is None:
            return []
        return [
            {
                "type": 2,
                "name": cls._first_value(row, "note_title", "title", "name") or "Secure Note",
                "notes": cls._first_value(row, "note_detail", "note", "notes"),
                "secureNote": {"type": 0},
            }
            for row in table.rows
        ]

    @classmethod
    def _bitwarden_card_items(cls, table: SPassTable | None) -> list[dict[str, Any]]:
        if table is None:
            return []
        return [
            {
                "type": 3,
                "name": cls._first_value(row, "reserved_5", "card_name", "name_on_card") or "Card",
                "card": {
                    "cardholderName": cls._first_value(row, "name_on_card", "cardholder_name"),
                    "number": cls._first_value(row, "card_number", "number"),
                    "expMonth": cls._first_value(row, "expiration_month", "exp_month"),
                    "expYear": cls._first_value(row, "expiration_year", "exp_year"),
                    "code": cls._first_value(row, "security_code", "cvv", "cvc"),
                },
            }
            for row in table.rows
        ]

    @classmethod
    def _bitwarden_identity_items(cls, table: SPassTable | None) -> list[dict[str, Any]]:
        if table is None:
            return []
        return [
            {
                "type": 4,
                "name": cls._first_value(row, "name", "full_name") or "Identity",
                "identity": {
                    "address1": cls._first_value(row, "street_address", "address1"),
                    "city": cls._first_value(row, "city"),
                    "postalCode": cls._first_value(row, "postal_code", "zip"),
                    "country": cls._first_value(row, "country_code", "country"),
                },
            }
            for row in table.rows
        ]

    @staticmethod
    def _first_value(entry: dict[str, str], *keys: str) -> str:
        for key in keys:
            value = entry.get(key, "")
            if value:
                return value
        return ""

    @staticmethod
    def _write_csv(handle: Any, headers: list[str], rows: list[dict[str, str]]) -> None:
        writer = csv.DictWriter(
            handle,
            fieldnames=headers,
            extrasaction="ignore",
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(rows)

    @staticmethod
    def _write_json(handle: Any, payload: dict[str, Any]) -> None:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
        handle.write("\n")

    @staticmethod
    def _write_text_file(output_path: Path, writer: Any) -> None:
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
                writer(handle)
        finally:
            if fd != -1:
                os.close(fd)
