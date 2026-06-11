# Real Export Testing

This project must never commit real Samsung Pass exports. Use this guide to
create a local fake export that has Samsung's real `.spass` syntax but no real
secrets.

## Goal

Validate compatibility against Samsung Pass itself, not only generated fixtures.
The export should contain fake data such as:

- Domains under `example.com`
- Users like `alice@example.com`
- Passwords like `not-a-real-password-1`
- Notes that clearly say `synthetic test data only`

## Create Fake Data On A Samsung Device

Use a Samsung phone or tablet with Samsung Pass available. Samsung Pass export is
normally tied to Samsung's mobile app and account flow; do not upload exports to
web tools or cloud converters.

1. Create a few fake login entries:
   - `https://login.example.com`
   - `alice@example.com`
   - `not-a-real-password-1`
2. Add one fake note, one fake address, and one fake card if Samsung Pass allows
   those categories in your region/app version.
3. Export from Samsung Pass settings.
4. Set a throwaway export password, for example `demo-password-real-export`.
5. Move the `.spass` file to this repo under `private-fixtures/`.

The `private-fixtures/` directory is ignored by Git. Still check before every
commit:

```bash
git status --short
```

## Inspect Without Printing Secrets

```bash
printf 'demo-password-real-export\n' | python3 spass_to_csv.py \
  --password-stdin \
  --inspect \
  -i private-fixtures/samsung-fake-export.spass
```

Expected output:

- Version line
- Table count
- Table types and headers
- Row counts
- Warning codes, if compatibility fallback was used

Unexpected output:

- Password values
- Usernames
- Card numbers
- Note contents
- TOTP secrets

If any value appears in inspect output, treat it as a bug.

## Export To Temporary Files

Use `/tmp` for hands-on export checks:

```bash
printf 'demo-password-real-export\n' | python3 spass_to_csv.py \
  --password-stdin \
  -i private-fixtures/samsung-fake-export.spass \
  -o /tmp/spasstocsv-real-chrome.csv \
  --format chrome
```

Check the generated file locally, then delete it after import/testing:

```bash
ls -l /tmp/spasstocsv-real-chrome.csv
rm /tmp/spasstocsv-real-chrome.csv
```

## Report Compatibility Issues

When opening an issue, include only non-secret diagnostics:

```bash
printf 'demo-password-real-export\n' | python3 spass_to_csv.py \
  --password-stdin \
  --inspect \
  --verbose \
  -i private-fixtures/samsung-fake-export.spass
```

Safe details to paste:

- App/device model and Samsung Pass version, if known
- `--inspect --verbose` output after checking that it contains no values
- The selected export categories
- The output format attempted

Never paste or upload the `.spass` file unless every entry inside it is fake and
you intentionally want to share that fixture.
