# Release Checklist

Use this checklist before tagging a release.

## Preflight

- `git status --short` shows only intentional tracked changes.
- No real `.spass`, `.csv`, `.json`, card, TOTP, note, or password data is staged.
- `CHANGELOG.md` has a dated release section.
- `pyproject.toml` version matches the tag.

## Local Checks

```bash
python3 -m unittest
python3 -m py_compile spass_to_csv.py
printf 'demo-password\n' | python3 spass_to_csv.py \
  --password-stdin \
  -i tests/fixtures/demo_full.spass \
  -o /tmp/spasstocsv-demo.csv \
  --format chrome
python3 -m pip install build
python3 -m build
python3 -m pip install --force-reinstall dist/*.whl
spasstocsv --list-formats
```

Delete plaintext test output:

```bash
ls -l /tmp/spasstocsv-demo.csv
rm /tmp/spasstocsv-demo.csv
```

## GitHub

- Push the release commit.
- Confirm GitHub Actions is green for Python 3.9 through 3.13.
- Create an annotated tag:

```bash
git tag -a v0.3.0 -m "Release v0.3.0"
git push origin v0.3.0
```

- Create the GitHub Release from the tag.
- Paste the matching `CHANGELOG.md` section.
