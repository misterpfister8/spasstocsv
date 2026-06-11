"""Command-line interface."""

from __future__ import annotations

import argparse
import sys
from getpass import getpass
from pathlib import Path

from spasstocsv.crypto import SPassDecryptor
from spasstocsv.errors import SPassError, SPassFormatError
from spasstocsv.exporters import CSVExporter
from spasstocsv.models import ParsedSPass
from spasstocsv.parser import SPassParser


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Decrypt a Samsung Pass .spass export and convert it locally."
    )
    parser.add_argument("-i", "--input", required=True, help="Path to the Samsung Pass .spass file")
    parser.add_argument(
        "-o",
        "--output",
        help="Output path. Defaults to '<input-stem>_passwords.csv' or '<input-stem>_bitwarden.json'.",
    )
    parser.add_argument(
        "--format",
        choices=sorted(CSVExporter.FORMATS),
        default="raw",
        help="Output format. Default: raw.",
    )
    parser.add_argument(
        "--password-stdin",
        action="store_true",
        help="Read the export password from stdin instead of an interactive prompt.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail on malformed table fields instead of preserving raw field text with warnings.",
    )
    parser.add_argument(
        "--inspect",
        "--diagnose",
        dest="inspect",
        action="store_true",
        help="Print safe metadata only: version, table headers, row counts, and warnings.",
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


def default_output_path(input_path: Path, format_name: str) -> Path:
    if format_name == "bitwarden-json":
        return input_path.with_name(f"{input_path.stem}_bitwarden.json")
    return input_path.with_name(f"{input_path.stem}_passwords.csv")


def parse_export(input_path: Path, password: str, strict: bool) -> ParsedSPass:
    print("Step 1/3: decrypting .spass export")
    decrypted = SPassDecryptor(password).decrypt_file(input_path)
    print("Step 2/3: parsing Samsung Pass tables")
    return SPassParser.parse_decrypted_data(decrypted, strict=strict)


def print_inspection(parsed: ParsedSPass) -> None:
    print(f"Version: {parsed.version}")
    print(f"Tables: {len(parsed.tables)}")
    for index, table in enumerate(parsed.tables, start=1):
        headers = ", ".join(table.headers)
        print(f"- {index}: {table.type} rows={len(table.rows)} headers=[{headers}]")
    print_warnings(parsed)


def print_warnings(parsed: ParsedSPass) -> None:
    if not parsed.warnings:
        return
    print("Warnings:")
    for warning in parsed.warnings:
        print(f"- {warning.describe()}")


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    input_path = Path(args.input).expanduser()
    output_path = (
        Path(args.output).expanduser()
        if args.output
        else default_output_path(input_path, args.format)
    )

    try:
        password = read_password(args.password_stdin)
        parsed = parse_export(input_path, password, strict=args.strict)

        if args.inspect:
            print_inspection(parsed)
            return 0

        print(f"Step 3/3: writing {args.format} export")
        count = CSVExporter.export(parsed, output_path, args.format)
    except (SPassError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    table_summary = ", ".join(f"{table.type}={len(table.rows)}" for table in parsed.tables)
    print(f"Parsed Samsung Pass export version {parsed.version}: {table_summary}")
    print_warnings(parsed)
    print(f"Created {args.format} export at {output_path}")
    print(f"Exported {count} item(s)")
    print("Security: the output contains plaintext secrets. Delete it after import.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
