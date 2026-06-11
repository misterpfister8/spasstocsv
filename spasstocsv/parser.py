"""Samsung Pass plaintext parser."""

from __future__ import annotations

import base64
import binascii
import csv
from io import StringIO
from typing import Optional

from spasstocsv.errors import SPassFormatError
from spasstocsv.models import ParsedSPass, SPassTable, SPassWarning, WarningCode


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
    HEADER_TYPE_HINTS = {
        "passwords": {"password_value", "username_value", "origin_url", "host_url"},
        "cards": {"card_number", "name_on_card", "expiration_month", "security_code"},
        "addresses": {"street_address", "postal_code", "country_code"},
        "notes": {"note_title", "note_detail"},
    }

    @classmethod
    def parse_decrypted_data(cls, decrypted_data: str, strict: bool = False) -> ParsedSPass:
        lines = [line.strip("\r") for line in decrypted_data.splitlines()]
        if len(lines) < 3:
            raise SPassFormatError("Invalid .spass data: expected header and table data")

        version, data_types, table_lines = cls._read_header(lines)
        table_chunks = cls._split_table_chunks(table_lines)
        if not table_chunks:
            raise SPassFormatError("Invalid .spass data: no data tables found")

        warnings: list[SPassWarning] = []
        tables = []
        for index, chunk in enumerate(table_chunks):
            table_type = cls._table_type_for_chunk(index, chunk, data_types)
            if table_type.startswith("table_"):
                warnings.append(
                    SPassWarning(
                        code=WarningCode.UNKNOWN_TABLE,
                        message="Table type could not be inferred from flags or headers",
                        table_number=index + 1,
                        table_type=table_type,
                    )
                )
            tables.append(cls._parse_table(table_type, chunk, index + 1, strict, warnings))

        password_table = next((table for table in tables if table.type == "passwords"), None)
        if password_table is None or not password_table.rows:
            warnings.append(
                SPassWarning(
                    code=WarningCode.EMPTY_PASSWORD_TABLE,
                    message="No password rows were found",
                    table_type="passwords",
                )
            )

        return ParsedSPass(
            version=version,
            data_types=data_types,
            tables=tables,
            warnings=warnings,
        )

    @classmethod
    def _read_header(cls, lines: list[str]) -> tuple[str, list[str], list[str]]:
        first = lines[0].strip()
        second = lines[1].strip() if len(lines) > 1 else ""

        if first == "samsung_pass_export" and second.lower().startswith("version:"):
            return second, [], lines[2:]

        return first, cls._parse_data_types(second), lines[2:]

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
    def _split_table_chunks(lines: list[str]) -> list[list[str]]:
        tables: list[list[str]] = []
        current_table: list[str] = []

        for raw_line in lines:
            line = raw_line.strip()
            if not line:
                continue

            if line == "next_table":
                if current_table:
                    tables.append(current_table)
                current_table = []
                continue

            # v25 currently has a non-table metadata line before first next_table.
            if not current_table and ";" not in line:
                continue

            current_table.append(line)

        if current_table:
            tables.append(current_table)

        return tables

    @classmethod
    def _table_type_for_chunk(
        cls,
        index: int,
        chunk: list[str],
        data_types: list[str],
    ) -> str:
        headers = cls._read_csv_record(chunk[0])
        inferred = cls._infer_table_type(headers)
        if inferred is not None:
            return inferred
        if index < len(data_types):
            return data_types[index]
        return f"table_{index + 1}"

    @classmethod
    def _infer_table_type(cls, headers: list[str]) -> Optional[str]:
        header_set = set(headers)
        for table_type, hints in cls.HEADER_TYPE_HINTS.items():
            if header_set.intersection(hints):
                return table_type
        return None

    @classmethod
    def _parse_table(
        cls,
        table_type: str,
        lines: list[str],
        table_number: int,
        strict: bool,
        warnings: list[SPassWarning],
    ) -> SPassTable:
        csv_rows = cls._read_csv_rows(lines, table_number)
        headers = [header.strip() for header in csv_rows[0]]
        if not headers or any(not header for header in headers):
            raise SPassFormatError(f"Table {table_number} has invalid headers")

        decoded_rows = []
        for row_number, fields in enumerate(csv_rows[1:], start=1):
            if len(fields) > len(headers):
                if strict:
                    raise SPassFormatError(
                        f"Table {table_number} row {row_number} has more fields than headers"
                    )
                extra_count = len(fields) - len(headers)
                start = len(headers) + 1
                headers.extend(f"extra_{index}" for index in range(start, start + extra_count))
                warnings.append(
                    SPassWarning(
                        code=WarningCode.EXTRA_COLUMNS,
                        message="Row had more fields than headers; extra columns were preserved",
                        table_number=table_number,
                        table_type=table_type,
                        row_number=row_number,
                    )
                )

            fields.extend([""] * (len(headers) - len(fields)))
            row = {}
            for header, field in zip(headers, fields):
                row[header] = cls._decode_field(
                    field=field,
                    strict=strict,
                    warnings=warnings,
                    table_number=table_number,
                    table_type=table_type,
                    row_number=row_number,
                    header=header,
                )
            decoded_rows.append(row)

        return SPassTable(type=table_type, headers=headers, rows=decoded_rows)

    @staticmethod
    def _read_csv_rows(lines: list[str], table_number: int) -> list[list[str]]:
        try:
            rows = list(csv.reader(StringIO("\n".join(lines)), delimiter=";"))
        except csv.Error as exc:
            raise SPassFormatError(f"Table {table_number} is not valid semicolon CSV: {exc}") from exc
        if not rows:
            raise SPassFormatError(f"Table {table_number} is empty")
        return rows

    @staticmethod
    def _read_csv_record(line: str) -> list[str]:
        return next(csv.reader([line], delimiter=";"))

    @staticmethod
    def _decode_field(
        field: str,
        strict: bool,
        warnings: list[SPassWarning],
        table_number: int,
        table_type: str,
        row_number: int,
        header: str,
    ) -> str:
        if field == "":
            return ""

        padded = field + "=" * (-len(field) % 4)
        try:
            decoded = base64.b64decode(padded, validate=True)
            decoded_text = decoded.decode("utf-8")
            if decoded_text and all(character.isprintable() or character.isspace() for character in decoded_text):
                return decoded_text
            raise UnicodeDecodeError("utf-8", decoded, 0, len(decoded), "decoded text is not printable")
        except (binascii.Error, UnicodeDecodeError) as exc:
            if strict:
                raise SPassFormatError(
                    f"Invalid base64/UTF-8 in table {table_number}, row {row_number}, field '{header}'"
                ) from exc

            warnings.append(
                SPassWarning(
                    code=WarningCode.RAW_FIELD_FALLBACK,
                    message="Field was not valid base64/UTF-8 and was kept as raw text",
                    table_number=table_number,
                    table_type=table_type,
                    row_number=row_number,
                    field=header,
                )
            )
            return field
