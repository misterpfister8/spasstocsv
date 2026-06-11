"""Shared data models."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class SPassWarning:
    """Non-fatal parser warning without secret field values."""

    message: str
    table_number: int | None = None
    table_type: str | None = None
    row_number: int | None = None
    field: str | None = None

    def describe(self) -> str:
        parts = []
        if self.table_type:
            parts.append(f"table={self.table_type}")
        elif self.table_number is not None:
            parts.append(f"table={self.table_number}")
        if self.row_number is not None:
            parts.append(f"row={self.row_number}")
        if self.field:
            parts.append(f"field={self.field}")
        location = f" ({', '.join(parts)})" if parts else ""
        return f"{self.message}{location}"


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
    warnings: list[SPassWarning] = field(default_factory=list)

    @property
    def password_table(self) -> SPassTable | None:
        return self.table("passwords")

    @property
    def passwords(self) -> list[dict[str, str]]:
        table = self.password_table
        return table.rows if table is not None else []

    def table(self, table_type: str) -> SPassTable | None:
        for table in self.tables:
            if table.type == table_type:
                return table
        return None
