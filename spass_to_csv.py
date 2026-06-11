#!/usr/bin/env python3
"""Backward-compatible wrapper for the spasstocsv command."""

from __future__ import annotations

import sys

from spasstocsv.cli import main
from spasstocsv.crypto import SPassDecryptor
from spasstocsv.errors import DecryptionError, SPassError, SPassFormatError
from spasstocsv.exporters import (
    BitwardenJsonExporter,
    CSVExporter,
    ChromeCsvExporter,
    ProtonCsvExporter,
    RawCsvExporter,
)
from spasstocsv.models import ParsedSPass, SPassTable, SPassWarning, WarningCode
from spasstocsv.parser import SPassParser

__all__ = [
    "BitwardenJsonExporter",
    "CSVExporter",
    "ChromeCsvExporter",
    "DecryptionError",
    "ProtonCsvExporter",
    "RawCsvExporter",
    "ParsedSPass",
    "SPassDecryptor",
    "SPassError",
    "SPassFormatError",
    "SPassParser",
    "SPassTable",
    "SPassWarning",
    "WarningCode",
    "main",
]


if __name__ == "__main__":
    sys.exit(main())
