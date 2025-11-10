#!/usr/bin/env python3
"""
Samsung Pass to CSV Converter

Decrypts Samsung Pass (.spass) export files and converts them to CSV format.
Compatible with most password managers including Bitwarden, 1Password, and Chrome.

Author: https://github.com/misterpfister8/spass-to-csv
License: MIT
"""

import sys
import base64
import csv
from getpass import getpass
from pathlib import Path
from typing import List, Dict

try:
    from cryptography.hazmat.primitives import hashes, padding
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    print("Error: Required library 'cryptography' not found.")
    print("Please install it using: pip install cryptography")
    sys.exit(1)


class SPassDecryptor:
    """Decrypt Samsung Pass .spass files using correct encryption parameters"""
    
    # Samsung Pass encryption parameters (discovered through reverse engineering)
    SALT_BYTES = 20          # Salt size in bytes
    ITERATION_COUNT = 70000  # PBKDF2 iterations
    KEY_LENGTH = 32          # AES-256 key length
    BLOCK_SIZE = 128         # AES block size
    
    def __init__(self, password: str):
        """Initialize decryptor with password"""
        self.password = password
    
    def decrypt_file(self, file_path: str) -> str:
        """
        Decrypt a .spass file.
        
        File format: Base64(salt(20) + IV(16) + AES-encrypted-data)
        
        Args:
            file_path: Path to the .spass file
            
        Returns:
            Decrypted content as string
            
        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If decryption fails
        """
        # Read and decode base64
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                base64_data = f.read().strip()
        except FileNotFoundError:
            raise FileNotFoundError(f"File not found: {file_path}")
        
        print(f"  File size: {len(base64_data)} characters (base64)")
        
        try:
            encrypted_bytes = base64.b64decode(base64_data)
            print(f"  Decoded size: {len(encrypted_bytes)} bytes")
        except Exception as e:
            raise ValueError(f"Failed to decode base64: {e}")
        
        # Extract salt, IV, and ciphertext
        salt = encrypted_bytes[:self.SALT_BYTES]
        iv = encrypted_bytes[self.SALT_BYTES:self.SALT_BYTES + 16]
        ciphertext = encrypted_bytes[self.SALT_BYTES + 16:]
        
        print(f"  Salt: {len(salt)} bytes")
        print(f"  IV: {len(iv)} bytes")
        print(f"  Ciphertext: {len(ciphertext)} bytes")
        
        # Derive key using PBKDF2-HMAC-SHA256
        print(f"  Deriving key (SHA256, {self.ITERATION_COUNT} iterations)...")
        
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.KEY_LENGTH,
                salt=salt,
                iterations=self.ITERATION_COUNT,
                backend=default_backend()
            )
            key = kdf.derive(self.password.encode('utf-8'))
        except Exception as e:
            raise ValueError(f"Key derivation failed: {e}")
        
        # Decrypt with AES-256-CBC
        print(f"  Decrypting...")
        
        try:
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remove PKCS7 padding
            unpadder = padding.PKCS7(self.BLOCK_SIZE).unpadder()
            decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
            
            # Decode as UTF-8
            decrypted_text = decrypted.decode('utf-8', errors='ignore')
            
            if not (';' in decrypted_text and '\n' in decrypted_text):
                raise ValueError("Decrypted data doesn't look like valid .spass format")
            
            return decrypted_text
            
        except Exception as e:
            if "padding" in str(e).lower():
                raise ValueError("Decryption failed - password is likely incorrect")
            else:
                raise ValueError(f"Decryption failed: {e}")


class SPassParser:
    """Parse decrypted Samsung Pass data"""
    
    @staticmethod
    def parse_decrypted_data(decrypted_data: str) -> List[Dict[str, str]]:
        """
        Parse the decrypted .spass data into structured format.
        
        Args:
            decrypted_data: Decrypted content from .spass file
            
        Returns:
            List of password entry dictionaries
            
        Raises:
            ValueError: If data format is invalid
        """
        lines = decrypted_data.strip().split('\n')
        
        if len(lines) < 3:
            raise ValueError("Invalid .spass file format")
        
        version = lines[0].strip()
        data_types = lines[1].strip()
        
        print(f"  Version: {version}")
        print(f"  Data types: {data_types}")
        
        # Parse tables
        tables = []
        current_table = None
        headers = None
        
        for line in lines[2:]:
            line = line.strip()
            
            if not line:
                continue
            
            if line == "next_table":
                if current_table is not None and headers is not None:
                    tables.append({'headers': headers, 'rows': current_table})
                current_table = []
                headers = None
                continue
            
            if current_table is not None:
                if headers is None:
                    headers = [h.strip() for h in line.split(';')]
                else:
                    current_table.append(line)
        
        # Add last table
        if current_table is not None and headers is not None:
            tables.append({'headers': headers, 'rows': current_table})
        
        print(f"  Found {len(tables)} table(s)")
        
        if not tables:
            raise ValueError("No data tables found")
        
        return SPassParser._parse_password_table(tables[0])
    
    @staticmethod
    def _decode_field(field: str) -> str:
        """Decode base64-encoded field if needed"""
        if not field:
            return ""
        
        try:
            # Add padding if needed
            padded = field + '=' * (-len(field) % 4)
            decoded = base64.b64decode(padded).decode('utf-8', errors='ignore')
            # Only use decoded if it looks valid
            if decoded and all(c.isprintable() or c.isspace() for c in decoded):
                return decoded
        except:
            pass
        
        return field
    
    @staticmethod
    def _parse_password_table(table: Dict) -> List[Dict[str, str]]:
        """Parse the password table into list of entries"""
        headers = table['headers']
        entries = []
        
        print(f"  Columns: {', '.join(headers)}")
        
        for row in table['rows']:
            fields = row.split(';')
            
            entry = {}
            for i, header in enumerate(headers):
                if i < len(fields):
                    entry[header] = SPassParser._decode_field(fields[i])
                else:
                    entry[header] = ''
            
            entries.append(entry)
        
        return entries


class CSVExporter:
    """Export parsed data to CSV format"""
    
    @staticmethod
    def export_to_csv(entries: List[Dict[str, str]], output_path: str):
        """
        Export password entries to CSV file.
        
        Args:
            entries: List of password entry dictionaries
            output_path: Path for output CSV file
        """
        if not entries:
            print("Warning: No entries to export")
            return
        
        # Get all headers
        all_headers = set()
        for entry in entries:
            all_headers.update(entry.keys())
        
        # Prioritize common headers
        priority = ['name', 'url', 'username', 'password', 'email', 'notes', 'otp']
        ordered_headers = [h for h in priority if h in all_headers]
        ordered_headers.extend(sorted(all_headers - set(ordered_headers)))
        
        # Write CSV
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=ordered_headers, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(entries)
        
        print(f"  ✓ Exported {len(entries)} entries")


def main():
    """Main entry point"""
    print("=" * 70)
    print("Samsung Pass (.spass) to CSV Converter")
    print("=" * 70)
    print()
    
    # Get file path
    while True:
        file_path = input("Enter path to .spass file: ").strip().strip('"').strip("'")
        if file_path and Path(file_path).exists():
            break
        print(f"Error: File not found: {file_path}")
    
    # Get password
    password = getpass("Enter password: ")
    if not password:
        print("Error: Password required")
        sys.exit(1)
    
    # Output file
    output_file = Path(file_path).stem + "_passwords.csv"
    custom_output = input(f"Output file (default: {output_file}): ").strip()
    if custom_output:
        output_file = custom_output
    
    print()
    print("Processing...")
    print("-" * 70)
    
    try:
        # Decrypt
        print("Step 1/3: Decrypting...")
        decryptor = SPassDecryptor(password)
        decrypted = decryptor.decrypt_file(file_path)
        print("  ✓ Decryption successful")
        
        # Parse
        print("\nStep 2/3: Parsing...")
        entries = SPassParser.parse_decrypted_data(decrypted)
        print(f"  ✓ Parsed {len(entries)} entries")
        
        # Export
        print("\nStep 3/3: Exporting...")
        CSVExporter.export_to_csv(entries, output_file)
        
        print()
        print("=" * 70)
        print(f"✓ SUCCESS! Converted {len(entries)} passwords")
        print(f"Output: {output_file}")
        print("=" * 70)
        print()
        print("⚠️  Security reminder: Delete the CSV file after importing to your")
        print("   password manager, as it contains unencrypted passwords!")
        
    except (ValueError, FileNotFoundError) as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
