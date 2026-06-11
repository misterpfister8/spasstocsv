# Private Fixtures

Put local Samsung Pass test exports here only when debugging real compatibility.

Rules:

- Use fake entries only, for example `example.com`, `alice@example.com`, and
  `not-a-real-password-1`.
- Do not put real accounts, card numbers, notes, TOTP secrets, or addresses here.
- Files in this directory are ignored by Git except this README.
- Delete plaintext CSV or JSON outputs after checking them.

Suggested local layout:

```text
private-fixtures/
  samsung-fake-export.spass
```

Example local test:

```bash
printf 'your-export-password\n' | python3 spass_to_csv.py \
  --password-stdin \
  --inspect \
  -i private-fixtures/samsung-fake-export.spass
```
