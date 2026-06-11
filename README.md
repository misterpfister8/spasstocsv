# Samsung Pass to CSV Converter

Decrypt Samsung Pass (`.spass`) exports locally and convert them for migration
to other password managers.

This tool is not affiliated with Samsung. Use it only with your own exports.

## What It Supports

- Decrypts Samsung Pass `.spass` exports protected with the export password
- Parses both known Samsung Pass v25-style exports and older generator-style layouts
- Parses passwords, cards, addresses, and notes
- Exports:
  - `raw` - decoded Samsung Pass password table fields
  - `chrome` - `name,url,username,password,note`
  - `proton` - `name,url,username,password,note,totp`
  - `bitwarden-json` - Bitwarden JSON with logins, notes, cards, and identities
- Runs fully locally; no network calls and no data collection
- Supports `--password-stdin` for terminals and IDEs where hidden password input fails
- Supports `--inspect` for safe metadata-only diagnostics
- Supports stable warning codes for compatibility reports
- Supports `--list-formats`, `--quiet`, and `--verbose`

Default parsing is intentionally tolerant for real Samsung Pass variants. Use
`--strict` when you want malformed fields to fail instead of being preserved as
raw text with warnings.

## Security Notes

- Real `.spass` exports and generated outputs contain sensitive data.
- CSV and Bitwarden JSON outputs contain plaintext secrets. Delete them after importing.
- Do not commit real `.spass`, `.csv`, or generated Bitwarden JSON files.
- Do not pass the export password as a command-line argument. It can end up in
  shell history or process listings.
- `--inspect` prints only version, table names, headers, row counts, and warnings.
  It must not print usernames, passwords, TOTP secrets, notes, or card numbers.

## Installation

Requirements:

- Python 3.9 or newer
- `cryptography`

Install for development:

```bash
git clone https://github.com/misterpfister8/spasstocsv.git
cd spasstocsv
python3 -m pip install -e .
```

Minimal dependency install without package entry point:

```bash
python3 -m pip install -r requirements.txt
```

## Usage

Export your data from Samsung Pass on your Samsung device:

1. Open Samsung Pass.
2. Go to Settings -> Export data.
3. Select the data to export.
4. Set an export password and remember it.
5. Transfer the `.spass` file to your computer.

Convert with the wrapper script:

```bash
python3 spass_to_csv.py -i /path/to/export.spass -o passwords.csv --format chrome
```

Convert with the installed CLI:

```bash
spasstocsv -i /path/to/export.spass -o passwords.csv --format chrome
```

Convert with stdin password input:

```bash
printf 'your-export-password\n' | python3 spass_to_csv.py \
  --password-stdin \
  -i /path/to/export.spass \
  -o passwords.csv \
  --format proton
```

Inspect safely without exporting secrets:

```bash
printf 'your-export-password\n' | python3 spass_to_csv.py \
  --password-stdin \
  --inspect \
  -i /path/to/export.spass
```

List supported formats without reading a password:

```bash
python3 spass_to_csv.py --list-formats
```

Strict parser mode:

```bash
python3 spass_to_csv.py -i /path/to/export.spass --format chrome --strict
```

Quiet mode for scripts:

```bash
printf 'your-export-password\n' | python3 spass_to_csv.py \
  --password-stdin \
  --quiet \
  -i /path/to/export.spass \
  -o passwords.csv \
  --format chrome
```

Verbose warning details:

```bash
printf 'your-export-password\n' | python3 spass_to_csv.py \
  --password-stdin \
  --verbose \
  -i /path/to/export.spass \
  -o passwords.csv \
  --format chrome
```

Available formats:

```bash
python3 spass_to_csv.py -i export.spass --format raw
python3 spass_to_csv.py -i export.spass --format chrome
python3 spass_to_csv.py -i export.spass --format proton
python3 spass_to_csv.py -i export.spass --format bitwarden-json
```

If `--output` is omitted, the default is:

```text
<input-stem>_passwords.csv
<input-stem>_bitwarden.json   # for --format bitwarden-json
```

## Demo Data

The repository includes synthetic test fixtures under `tests/fixtures/`.

- Demo password: `demo-password`
- Demo domains use `example.com`
- Demo credentials use fake values such as `not-a-real-password-1`
- `demo_full.spass` is encrypted with the same known `.spass` crypto layout
- `legacy_decrypted.txt` exercises tolerant parsing of older/generator-style data

Hands-on demo:

```bash
printf 'demo-password\n' | python3 spass_to_csv.py \
  --password-stdin \
  -i tests/fixtures/demo_full.spass \
  -o /tmp/spasstocsv-demo.csv \
  --format chrome
```

Inspect the generated demo CSV:

```bash
cat /tmp/spasstocsv-demo.csv
```

Preview the demo output path before deleting it:

```bash
ls -l /tmp/spasstocsv-demo.csv
```

Delete the demo output when done:

```bash
rm /tmp/spasstocsv-demo.csv
```

## Real Samsung Fake-Export Testing

There is no committed real Samsung export in this repository. For compatibility
testing, create fake entries on a Samsung device, export them from Samsung Pass,
and place the `.spass` file under `private-fixtures/`.

Read [REAL_EXPORT_TESTING.md](REAL_EXPORT_TESTING.md) before doing this. The
short version:

- Use only fake `example.com` entries.
- Keep the `.spass` file local under `private-fixtures/`.
- Run `--inspect --verbose` first and check that no values are printed.
- Export only to `/tmp` during testing and delete plaintext outputs afterwards.

## Import Notes

Chrome and Edge:

- Use `--format chrome`
- Import via the browser password manager import flow

Bitwarden:

- Preferred: `--format bitwarden-json`
- Fallback: `--format chrome` and import as Chrome CSV

Proton Pass:

- Use `--format proton`
- Import as Generic CSV

1Password:

- Use `--format chrome`
- Import as Chrome CSV

## Technical Details

Observed Samsung Pass export structure:

```text
Base64(salt[20 bytes] + IV[16 bytes] + AES-256-CBC(ciphertext))
```

Crypto parameters:

- AES-256-CBC
- PBKDF2-HMAC-SHA256
- 70,000 PBKDF2 iterations
- 20 byte salt
- 16 byte IV
- PKCS7 padding

The decrypted payload is semicolon-delimited text. Tables are separated by
`next_table`. Headers are plaintext; data row fields are normally base64-encoded
UTF-8 strings.

## Testing

Run the full test suite:

```bash
python3 -m unittest
```

Run a syntax check:

```bash
python3 -m py_compile spass_to_csv.py
```

Run the CLI smoke test:

```bash
printf 'demo-password\n' | python3 spass_to_csv.py \
  --password-stdin \
  -i tests/fixtures/demo_full.spass \
  -o /tmp/spasstocsv-demo.csv \
  --format chrome
```

The tests decrypt the synthetic `.spass` fixture, verify wrong-password failure,
parse v25 and legacy layouts, compare CSV snapshots, validate Bitwarden JSON,
verify `--inspect`, and run CLI exports for every format.

Build package artifacts:

```bash
python3 -m pip install build
python3 -m build
```

See [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md) before tagging a release.

## Warning Codes

Diagnostics use stable non-secret warning codes:

- `RAW_FIELD_FALLBACK` - a field was not valid base64/UTF-8 and was preserved as raw text.
- `EXTRA_COLUMNS` - a row had more fields than the table header.
- `UNKNOWN_TABLE` - a table type could not be inferred from flags or headers.
- `EMPTY_PASSWORD_TABLE` - no password rows were found.

Default output prints a warning summary. `--verbose` and `--inspect` print
non-secret warning locations such as table, row, and field names.

## Troubleshooting

`Error: Decryption failed - password is likely incorrect or file is corrupted`

- Check that you entered the Samsung Pass export password.
- Check that the file was transferred completely.

`Error: Input file must have a .spass extension`

- Use the original Samsung Pass export file.

`Warnings: RAW_FIELD_FALLBACK`

- Default mode preserved a field for compatibility with real-world variants.
- Re-run with `--strict` if you want this to fail hard.

`Error: Required library 'cryptography' not found`

```bash
python3 -m pip install -r requirements.txt
```

## Credits

Format and implementation references:

- [mssa2468/samsung-pass-to-bitwarden-converter](https://github.com/mssa2468/samsung-pass-to-bitwarden-converter)
- [0xdeb7ef/spass-manager](https://github.com/0xdeb7ef/spass-manager)

## License

MIT License - see [LICENSE](LICENSE).
