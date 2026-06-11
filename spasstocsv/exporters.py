"""CSV and Bitwarden JSON exporters."""

from __future__ import annotations

import csv
import json
import os
from pathlib import Path
from typing import Any, Callable, Iterable, Optional, Union

from spasstocsv.errors import SPassFormatError
from spasstocsv.models import ParsedSPass, SPassTable

PathLike = Union[str, Path]


class BaseExporter:
    """Base helper for plaintext export files."""

    format_name = ""

    @staticmethod
    def first_value(entry: dict[str, str], *keys: str) -> str:
        for key in keys:
            value = entry.get(key, "")
            if value:
                return value
        return ""

    @staticmethod
    def write_text_file(output_path: Path, writer: Callable[[Any], None]) -> None:
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


class CsvBaseExporter(BaseExporter):
    """Base class for CSV exporters."""

    headers: list[str] = []

    @classmethod
    def export(cls, parsed: ParsedSPass, output_path: PathLike) -> int:
        path = Path(output_path)
        headers, rows = cls.rows(parsed)
        cls.validate(headers, rows)
        cls.write_text_file(path, lambda handle: cls.write_csv(handle, headers, rows))
        cls.validate_written_file(path, headers)
        return len(rows)

    @classmethod
    def rows(cls, parsed: ParsedSPass) -> tuple[list[str], list[dict[str, str]]]:
        raise NotImplementedError

    @classmethod
    def validate(cls, headers: list[str], rows: list[dict[str, str]]) -> None:
        if cls.headers and headers != cls.headers:
            raise SPassFormatError(f"{cls.format_name} exporter produced invalid headers")
        missing = [header for row in rows for header in headers if header not in row]
        if missing:
            raise SPassFormatError(f"{cls.format_name} exporter produced incomplete rows")

    @staticmethod
    def write_csv(handle: Any, headers: list[str], rows: list[dict[str, str]]) -> None:
        writer = csv.DictWriter(
            handle,
            fieldnames=headers,
            extrasaction="ignore",
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(rows)

    @classmethod
    def validate_written_file(cls, output_path: Path, headers: list[str]) -> None:
        with output_path.open("r", encoding="utf-8", newline="") as handle:
            rows = list(csv.reader(handle))

        if not rows or rows[0] != headers:
            raise SPassFormatError(f"{cls.format_name} exporter wrote invalid CSV headers")
        for row in rows[1:]:
            if len(row) != len(headers):
                raise SPassFormatError(f"{cls.format_name} exporter wrote invalid CSV row width")


class RawCsvExporter(CsvBaseExporter):
    """Export decoded Samsung Pass password table fields."""

    format_name = "raw"

    @classmethod
    def rows(cls, parsed: ParsedSPass) -> tuple[list[str], list[dict[str, str]]]:
        password_table = parsed.password_table
        if password_table is None:
            raise SPassFormatError("No password table found in the Samsung Pass export")
        return password_table.headers, password_table.rows


class ChromeCsvExporter(CsvBaseExporter):
    """Export Chrome-compatible password CSV."""

    format_name = "chrome"
    headers = ["name", "url", "username", "password", "note"]

    @classmethod
    def rows(cls, parsed: ParsedSPass) -> tuple[list[str], list[dict[str, str]]]:
        password_table = parsed.password_table
        if password_table is None:
            raise SPassFormatError("No password table found in the Samsung Pass export")
        return cls.headers, [cls.mapped_password_row(entry, include_totp=False) for entry in password_table.rows]

    @classmethod
    def mapped_password_row(cls, entry: dict[str, str], include_totp: bool) -> dict[str, str]:
        row = {
            "name": cls.first_value(entry, "title", "name", "host_url", "origin_url", "url"),
            "url": cls.first_value(entry, "host_url", "origin_url", "url"),
            "username": cls.first_value(entry, "username_value", "username", "email"),
            "password": cls.first_value(entry, "password_value", "password"),
            "note": cls.first_value(entry, "credential_memo", "note", "notes"),
        }
        if include_totp:
            row["totp"] = cls.first_value(entry, "otp", "totp")
        return row


class ProtonCsvExporter(ChromeCsvExporter):
    """Export Proton Pass compatible Generic CSV."""

    format_name = "proton"
    headers = ["name", "url", "username", "password", "note", "totp"]

    @classmethod
    def rows(cls, parsed: ParsedSPass) -> tuple[list[str], list[dict[str, str]]]:
        password_table = parsed.password_table
        if password_table is None:
            raise SPassFormatError("No password table found in the Samsung Pass export")
        return cls.headers, [cls.mapped_password_row(entry, include_totp=True) for entry in password_table.rows]


class BitwardenJsonExporter(BaseExporter):
    """Export Bitwarden JSON with all parsed Samsung Pass table types."""

    format_name = "bitwarden-json"

    LOGIN_KEYS = {
        "title",
        "name",
        "host_url",
        "origin_url",
        "url",
        "username_value",
        "username",
        "email",
        "password_value",
        "password",
        "credential_memo",
        "note",
        "notes",
        "otp",
        "totp",
    }
    NOTE_KEYS = {"note_title", "title", "name", "note_detail", "note", "notes"}
    CARD_KEYS = {
        "reserved_5",
        "card_name",
        "name_on_card",
        "cardholder_name",
        "card_number",
        "number",
        "expiration_month",
        "exp_month",
        "expiration_year",
        "exp_year",
        "security_code",
        "cvv",
        "cvc",
    }
    IDENTITY_KEYS = {
        "name",
        "full_name",
        "street_address",
        "address1",
        "city",
        "postal_code",
        "zip",
        "country_code",
        "country",
    }

    @classmethod
    def export(cls, parsed: ParsedSPass, output_path: PathLike) -> int:
        path = Path(output_path)
        items = []
        items.extend(cls.login_items(parsed.table("passwords")))
        items.extend(cls.note_items(parsed.table("notes")))
        items.extend(cls.card_items(parsed.table("cards")))
        items.extend(cls.identity_items(parsed.table("addresses")))

        payload = {"encrypted": False, "items": items}
        cls.validate(payload)
        cls.write_text_file(path, lambda handle: cls.write_json(handle, payload))
        cls.validate_written_file(path)
        return len(items)

    @classmethod
    def login_items(cls, table: Optional[SPassTable]) -> list[dict[str, Any]]:
        if table is None:
            return []

        items = []
        for row in table.rows:
            url = cls.first_value(row, "host_url", "origin_url", "url")
            login: dict[str, Any] = {
                "uris": [{"uri": url}] if url else [],
                "username": cls.first_value(row, "username_value", "username", "email"),
                "password": cls.first_value(row, "password_value", "password"),
            }
            totp = cls.first_value(row, "otp", "totp")
            if totp:
                login["totp"] = totp

            item = {
                "type": 1,
                "name": cls.first_value(row, "title", "name", "host_url", "origin_url", "url"),
                "login": login,
            }
            note = cls.first_value(row, "credential_memo", "note", "notes")
            if note:
                item["notes"] = note
            cls.add_custom_fields(item, row, cls.LOGIN_KEYS)
            items.append(item)
        return items

    @classmethod
    def note_items(cls, table: Optional[SPassTable]) -> list[dict[str, Any]]:
        if table is None:
            return []
        items = []
        for row in table.rows:
            item = {
                "type": 2,
                "name": cls.first_value(row, "note_title", "title", "name") or "Secure Note",
                "notes": cls.first_value(row, "note_detail", "note", "notes"),
                "secureNote": {"type": 0},
            }
            cls.add_custom_fields(item, row, cls.NOTE_KEYS)
            items.append(item)
        return items

    @classmethod
    def card_items(cls, table: Optional[SPassTable]) -> list[dict[str, Any]]:
        if table is None:
            return []
        items = []
        for row in table.rows:
            item = {
                "type": 3,
                "name": cls.first_value(row, "reserved_5", "card_name", "name_on_card") or "Card",
                "card": {
                    "cardholderName": cls.first_value(row, "name_on_card", "cardholder_name"),
                    "number": cls.first_value(row, "card_number", "number"),
                    "expMonth": cls.first_value(row, "expiration_month", "exp_month"),
                    "expYear": cls.first_value(row, "expiration_year", "exp_year"),
                    "code": cls.first_value(row, "security_code", "cvv", "cvc"),
                },
            }
            cls.add_custom_fields(item, row, cls.CARD_KEYS)
            items.append(item)
        return items

    @classmethod
    def identity_items(cls, table: Optional[SPassTable]) -> list[dict[str, Any]]:
        if table is None:
            return []
        items = []
        for row in table.rows:
            item = {
                "type": 4,
                "name": cls.first_value(row, "name", "full_name") or "Identity",
                "identity": {
                    "address1": cls.first_value(row, "street_address", "address1"),
                    "city": cls.first_value(row, "city"),
                    "postalCode": cls.first_value(row, "postal_code", "zip"),
                    "country": cls.first_value(row, "country_code", "country"),
                },
            }
            cls.add_custom_fields(item, row, cls.IDENTITY_KEYS)
            items.append(item)
        return items

    @staticmethod
    def add_custom_fields(item: dict[str, Any], row: dict[str, str], known_keys: Iterable[str]) -> None:
        known = set(known_keys)
        fields = [
            {"name": key, "value": value, "type": 0}
            for key, value in row.items()
            if key not in known and value
        ]
        if fields:
            item["fields"] = fields

    @staticmethod
    def validate(payload: dict[str, Any]) -> None:
        if payload.get("encrypted") is not False or not isinstance(payload.get("items"), list):
            raise SPassFormatError("Bitwarden JSON exporter produced invalid payload")
        for item in payload["items"]:
            if "type" not in item or "name" not in item:
                raise SPassFormatError("Bitwarden JSON exporter produced invalid item")

    @staticmethod
    def write_json(handle: Any, payload: dict[str, Any]) -> None:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
        handle.write("\n")

    @classmethod
    def validate_written_file(cls, output_path: Path) -> None:
        with output_path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        cls.validate(payload)


class CSVExporter:
    """Backward-compatible facade for all exporters."""

    FORMATS = {"raw", "chrome", "proton", "bitwarden-json"}
    FORMAT_DESCRIPTIONS = {
        "raw": "Decoded Samsung Pass password table CSV",
        "chrome": "Chrome/Edge password CSV: name,url,username,password,note",
        "proton": "Proton Pass Generic CSV: name,url,username,password,note,totp",
        "bitwarden-json": "Bitwarden JSON with logins, notes, cards, and identities",
    }
    EXPORTERS = {
        "raw": RawCsvExporter,
        "chrome": ChromeCsvExporter,
        "proton": ProtonCsvExporter,
        "bitwarden-json": BitwardenJsonExporter,
    }

    @classmethod
    def export(cls, parsed: ParsedSPass, output_path: PathLike, format_name: str) -> int:
        try:
            exporter = cls.EXPORTERS[format_name]
        except KeyError as exc:
            raise ValueError(f"Unsupported output format: {format_name}") from exc
        return exporter.export(parsed, output_path)

    @classmethod
    def export_passwords(cls, parsed: ParsedSPass, output_path: PathLike, format_name: str) -> int:
        if format_name == "bitwarden-json":
            raise ValueError("bitwarden-json is not a password CSV format")
        return cls.export(parsed, output_path, format_name)

    @classmethod
    def export_bitwarden_json(cls, parsed: ParsedSPass, output_path: PathLike) -> int:
        return BitwardenJsonExporter.export(parsed, output_path)
