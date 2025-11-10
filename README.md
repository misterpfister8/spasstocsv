# Samsung Pass to CSV Converter

A Python utility to decrypt and convert Samsung Pass (`.spass`) export files to CSV format, making it easy to migrate your passwords to other password managers.

## Features

✅ **Decrypts Samsung Pass exports** - Full support for `.spass` file format  
✅ **CSV output** - Compatible with Bitwarden, 1Password, Chrome, Edge, and more  
✅ **Secure** - Uses proper AES-256-CBC decryption with PBKDF2-HMAC-SHA256  
✅ **Easy to use** - Simple command-line interface  
✅ **No data collection** - Everything runs locally on your machine  

## Why This Tool?

Samsung Pass uses a proprietary encrypted format (`.spass`) that makes it difficult to migrate your passwords to other password managers. This tool decrypts and converts your Samsung Pass data to a standard CSV format that can be imported into virtually any password manager.

## Installation

### Requirements

- Python 3.7 or higher
- `cryptography` library

### Setup

1. Clone this repository:
```bash
git clone https://github.com/yourusername/spass-to-csv.git
cd spass-to-csv
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

Or install the cryptography library directly:
```bash
pip install cryptography
```

## Usage

### Step 1: Export from Samsung Pass

1. Open **Samsung Pass** on your Samsung device
2. Go to **Settings** → **Export data**
3. Choose the data you want to export (passwords, cards, addresses, notes)
4. **Set a password** for the export (remember this!)
5. Save the `.spass` file and transfer it to your computer

### Step 2: Convert to CSV

Run the script:
```bash
python spass_to_csv.py
```

You'll be prompted for:
- Path to your `.spass` file
- The password you set during export
- Output filename (optional)

Example:
```
======================================================================
Samsung Pass (.spass) to CSV Converter
======================================================================

Enter path to .spass file: /path/to/your/export.spass
Enter password: ********
Output file (default: export_passwords.csv): 

Processing...
----------------------------------------------------------------------
Step 1/3: Decrypting...
  ✓ Decryption successful

Step 2/3: Parsing...
  ✓ Parsed 99 entries

Step 3/3: Exporting...
  ✓ Exported 99 entries

======================================================================
✓ SUCCESS! Converted 99 passwords
Output: export_passwords.csv
======================================================================
```

### Step 3: Import to Your Password Manager

The output CSV file can be imported into most password managers:

#### **Chrome / Edge**
1. Go to `chrome://settings/passwords` or `edge://settings/passwords`
2. Click ⋮ → Import passwords
3. Select the CSV file

#### **Bitwarden**
1. Go to Tools → Import Data
2. Select "Chrome (csv)" as format
3. Choose the CSV file

#### **1Password**
1. Go to File → Import
2. Select "Chrome" as source
3. Choose the CSV file

#### **Proton Pass**
1. Go to Settings → Import
2. Select "Chrome" as provider
3. Upload the CSV file

## Security Notes

⚠️ **Important Security Considerations:**

1. **Delete the CSV file** after importing - it contains unencrypted passwords
2. **Keep your `.spass` file secure** - it's encrypted but still sensitive
3. **Use a strong export password** when creating the `.spass` file
4. **Don't commit sensitive files** to version control

## Technical Details

### Encryption Specifications

Samsung Pass uses the following encryption:

- **Outer layer**: Base64 encoding
- **Inner layer**: AES-256-CBC encryption
- **Key derivation**: PBKDF2-HMAC-SHA256 with 70,000 iterations
- **Salt size**: 20 bytes
- **IV size**: 16 bytes

File structure:
```
Base64(salt[20 bytes] + IV[16 bytes] + AES-encrypted-data)
```

### CSV Output Format

The script outputs a CSV with prioritized columns:

- `name` - Website/app name
- `url` - Website URL or app package
- `username` - Username or email
- `password` - Password
- `email` - Email address (if separate)
- `notes` - Additional notes
- `otp` - Two-factor authentication codes

## Troubleshooting

### "Decryption failed - password is likely incorrect"

- Double-check the password you entered
- Make sure you're using the password you set during the Samsung Pass export

### "File not found"

- Check the file path is correct
- Use absolute paths or ensure the file is in the current directory

### "Required library 'cryptography' not found"

- Install the cryptography library: `pip install cryptography`
- If using Python 3, try: `pip3 install cryptography`

## Contributing

Contributions are welcome! Feel free to:

- Report bugs
- Suggest new features
- Submit pull requests
- Improve documentation

## Credits

This tool was developed through reverse engineering the Samsung Pass `.spass` file format. Special thanks to:

- [mssa2468/samsung-pass-to-bitwarden-converter](https://github.com/mssa2468/samsung-pass-to-bitwarden-converter) - For encryption parameter discovery
- [0xdeb7ef/spass-manager](https://github.com/0xdeb7ef/spass-manager) - For Go implementation reference

## License

MIT License - See [LICENSE](LICENSE) file for details

## Disclaimer

This tool is not affiliated with, endorsed by, or supported by Samsung. Use at your own risk and always keep backups of your data.

---

If you find this tool helpful, please ⭐ star the repository!
