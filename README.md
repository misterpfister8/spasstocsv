# Samsung Pass to CSV Converter

Decrypt Samsung Pass (`.spass`) exports locally and convert password entries to
CSV files for migration to other password managers.

This tool is not affiliated with Samsung. Use it only with your own exports.

## What It Supports

- Decrypts Samsung Pass `.spass` exports protected with the export password
- Parses multi-table exports containing passwords, cards, addresses, and notes
- Exports password entries as:
  - `raw` - decoded Samsung Pass password table fields
  - `chrome` - `name,url,username,password,note`
  - `proton` - `name,url,username,password,note,totp`
- Runs fully locally; no network calls and no data collection
- Supports `--password-stdin` for terminals and IDEs where hidden password input fails

Important limitation for v1: cards, addresses, and notes are parsed and tested,
but only password entries are exported to CSV.

## Security Notes

- Real `.spass` exports and generated CSV files contain sensitive data.
- The output CSV contains plaintext passwords. Delete it after importing.
- Do not commit real `.spass` or CSV files. `.gitignore` blocks them by default.
- Do not pass the export password as a command-line argument. It can end up in
  shell history or process listings.
- Use `--password-stdin` only with trusted local input, for example from a
  password manager CLI or a temporary prompt wrapper.

## Installation

Requirements:

- Python 3.7 or newer
- `cryptography`

Install:

```bash
git clone https://github.com/misterpfister8/spasstocsv.git
cd spasstocsv
python3 -m pip install -r requirements.txt
```

## Usage

Export your data from Samsung Pass on your Samsung device:

1. Open Samsung Pass.
2. Go to Settings -> Export data.
3. Select the data to export.
4. Set an export password and remember it.
5. Transfer the `.spass` file to your computer.

Convert interactively:

```bash
python3 spass_to_csv.py -i /path/to/export.spass -o passwords.csv --format chrome
```

Convert with stdin password input:

```bash
printf 'your-export-password\n' | python3 spass_to_csv.py \
  --password-stdin \
  -i /path/to/export.spass \
  -o passwords.csv \
  --format proton
```

If `--output` is omitted, the default is:

```text
<input-stem>_passwords.csv
```

Available formats:

```bash
python3 spass_to_csv.py -i export.spass --format raw
python3 spass_to_csv.py -i export.spass --format chrome
python3 spass_to_csv.py -i export.spass --format proton
```

## Demo Data

The repository includes synthetic test fixtures under `tests/fixtures/`.

- Demo password: `demo-password`
- Demo domains use `example.com`
- Demo credentials use fake values such as `not-a-real-password-1`

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

## Import Notes

Chrome and Edge:

- Use `--format chrome`
- Import via the browser password manager import flow

Bitwarden:

- Use `--format chrome`
- Import as Chrome CSV

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

The decrypted payload is a semicolon-delimited text format. Tables are separated
by `next_table`. Field values in data rows are base64-encoded UTF-8 strings.

## Testing

Run the full test suite:

```bash
python3 -m unittest
```

Run a syntax check:

```bash
python3 -m py_compile spass_to_csv.py
```

The tests decrypt the synthetic `.spass` fixture, verify wrong-password failure,
parse all tables, compare CSV snapshots, and run the CLI with `--password-stdin`.

## Troubleshooting

`Error: Decryption failed - password is likely incorrect or file is corrupted`

- Check that you entered the Samsung Pass export password.
- Check that the file was transferred completely.

`Error: Input file must have a .spass extension`

- Use the original Samsung Pass export file.

`Error: Invalid base64 in table ...`

- The file decrypted, but the internal table data is not in the expected Samsung
  Pass format.

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
