"""User-facing exceptions."""

from __future__ import annotations


class SPassError(Exception):
    """Base error for converter failures."""


class DecryptionError(SPassError):
    """Raised when a .spass file cannot be decrypted."""


class SPassFormatError(SPassError):
    """Raised when decrypted Samsung Pass data is malformed."""
