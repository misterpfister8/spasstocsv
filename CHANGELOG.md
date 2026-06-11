# Changelog

## 0.3.0 - Unreleased

- Add stable warning codes for parser diagnostics.
- Add `--list-formats`, `--quiet`, and `--verbose` CLI options.
- Preserve unknown Samsung Pass fields as Bitwarden custom fields.
- Expand parser compatibility tests for quoted semicolon CSV, CRLF, extra
  columns, unknown tables, and inspect warning output.
- Add real Samsung fake-export testing documentation and private fixture rules.
- Add packaging metadata and wheel/sdist CI checks.

## 0.2.0 - 2026-06-11

- Package the converter as `spasstocsv` with a console entry point.
- Keep `spass_to_csv.py` as a backward-compatible wrapper.
- Add tolerant parsing by default and `--strict` for hard validation.
- Add `--inspect` safe diagnostics.
- Add Bitwarden JSON export for passwords, notes, cards, and addresses.
- Add synthetic encrypted `.spass` demo data and unittest coverage.

## 0.1.0 - Initial

- Decrypt Samsung Pass `.spass` exports.
- Convert password entries to CSV.
