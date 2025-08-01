"""
portability.py - Import and export passwords in various formats
Supports CSV, JSON, and encrypted VaultKey format
"""
import csv
import json
import os
from typing import Dict, List, Any
from datetime import datetime
import base64
from io import StringIO

from .crypto import Crypto
from .generator import generate_password


class VaultImporter:
    """Import passwords from various password manager formats"""
    
    SUPPORTED_FORMATS = {
        'vaultkey': 'VaultKey encrypted backup',
        'csv': 'Generic CSV (site,username,password)',
        'lastpass': 'LastPass CSV export',
        'bitwarden': 'Bitwarden CSV export',
        '1password': '1Password CSV export',
        'chrome': 'Chrome/Edge CSV export',
        'keepass': 'KeePass CSV export'
    }
    
    def import_file(self, filepath: str, format_type: str, master_password: str = None) -> Dict[str, Dict]:
        """
        Import passwords from a file.
        
        Args:
            filepath: Path to import file
            format_type: Format type (see SUPPORTED_FORMATS)
            master_password: Required for encrypted formats
            
        Returns:
            Dictionary of passwords ready for VaultKey
        """
        if format_type not in self.SUPPORTED_FORMATS:
            raise ValueError(f"Unsupported format: {format_type}")
        
        if format_type == 'vaultkey':
            return self._import_vaultkey(filepath, master_password)
        elif format_type == 'csv':
            return self._import_generic_csv(filepath)
        elif format_type == 'lastpass':
            return self._import_lastpass(filepath)
        elif format_type == 'bitwarden':
            return self._import_bitwarden(filepath)
        elif format_type == '1password':
            return self._import_1password(filepath)
        elif format_type == 'chrome':
            return self._import_chrome(filepath)
        elif format_type == 'keepass':
            return self._import_keepass(filepath)
    
    def _import_vaultkey(self, filepath: str, master_password: str) -> Dict[str, Dict]:
        """Import VaultKey encrypted backup"""
        if not master_password:
            raise ValueError("Master password required for VaultKey import")
        
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        # Decrypt the data
        crypto = Crypto()
        
        # Use the salt from the backup
        salt_data = base64.b64decode(data['salt'])
        with open('temp_salt.bin', 'wb') as f:
            f.write(salt_data)
        
        crypto.salt_file = 'temp_salt.bin'
        crypto.create_key(master_password)
        
        try:
            decrypted = crypto.decrypt(base64.b64decode(data['encrypted_data']))
            passwords_data = json.loads(decrypted)
            
            # Clean up temp salt
            os.remove('temp_salt.bin')
            
            return passwords_data['passwords']
        except Exception as e:
            # Clean up temp salt
            if os.path.exists('temp_salt.bin'):
                os.remove('temp_salt.bin')
            raise ValueError(f"Failed to decrypt backup: {str(e)}")
    
    def _import_generic_csv(self, filepath: str) -> Dict[str, Dict]:
        """Import generic CSV format: site,username,password[,notes]"""
        passwords = {}
        
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            # Try to detect delimiter
            sample = f.read(1024)
            f.seek(0)
            
            delimiter = ','
            if '\t' in sample:
                delimiter = '\t'
            
            reader = csv.reader(f, delimiter=delimiter)
            
            # Skip header if present
            first_row = next(reader, None)
            if first_row and 'password' in first_row[0].lower():
                # It's a header, skip it
                pass
            else:
                # Process first row as data
                if first_row and len(first_row) >= 3:
                    site, username, password = first_row[0], first_row[1], first_row[2]
                    notes = first_row[3] if len(first_row) > 3 else ""
                    passwords[site] = {
                        'username': username,
                        'password': password,
                        'notes': notes,
                        'created': datetime.now().isoformat(),
                        'modified': datetime.now().isoformat()
                    }
            
            # Process remaining rows
            for row in reader:
                if len(row) >= 3:
                    site, username, password = row[0], row[1], row[2]
                    notes = row[3] if len(row) > 3 else ""
                    
                    # Skip empty rows
                    if not site or not username:
                        continue
                    
                    passwords[site] = {
                        'username': username,
                        'password': password,
                        'notes': notes,
                        'created': datetime.now().isoformat(),
                        'modified': datetime.now().isoformat()
                    }
        
        return passwords
    
    def _import_lastpass(self, filepath: str) -> Dict[str, Dict]:
        """Import LastPass CSV export"""
        passwords = {}
        
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                # LastPass CSV headers: url,username,password,totp,extra,name,grouping,fav
                site = row.get('name') or row.get('url', '')
                username = row.get('username', '')
                password = row.get('password', '')
                notes = row.get('extra', '')
                
                # Convert None to empty string
                site = site or ''
                username = username or ''
                password = password or ''
                notes = notes or ''
                
                # Skip empty entries
                if not site or not username:
                    continue
                
                # Sanitize site name to remove problematic characters
                site = site.strip()
                
                # Clean up the site name
                if site.startswith('http'):
                    # Extract domain from URL
                    from urllib.parse import urlparse
                    try:
                        parsed = urlparse(site)
                        site = parsed.netloc or site
                    except Exception:
                        # If URL parsing fails, use the original
                        pass
                
                # Remove any null bytes or other problematic characters
                site = site.replace('\x00', '').replace('\r', '').replace('\n', ' ')
                username = username.replace('\x00', '').replace('\r', '').replace('\n', ' ')
                password = password.replace('\x00', '')
                notes = notes.replace('\x00', '').replace('\r\n', '\n').replace('\r', '\n')
                
                # Ensure site name is valid
                if site:
                    passwords[site] = {
                        'username': username.strip(),
                        'password': password,
                        'notes': notes.strip(),
                        'created': datetime.now().isoformat(),
                        'modified': datetime.now().isoformat()
                    }
        
        return passwords
    
    def _import_bitwarden(self, filepath: str) -> Dict[str, Dict]:
        """Import Bitwarden CSV export"""
        passwords = {}
        
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                # Bitwarden CSV headers: folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
                if row.get('type') != 'login':
                    continue
                
                site = row.get('name', '')
                username = row.get('login_username', '')
                password = row.get('login_password', '')
                notes = row.get('notes', '')
                
                if site and username:
                    passwords[site] = {
                        'username': username,
                        'password': password,
                        'notes': notes,
                        'created': datetime.now().isoformat(),
                        'modified': datetime.now().isoformat()
                    }
        
        return passwords
    
    def _import_1password(self, filepath: str) -> Dict[str, Dict]:
        """Import 1Password CSV export"""
        passwords = {}
        
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                # 1Password CSV varies, but typically: Title,Username,Password,URL,Notes
                site = row.get('Title') or row.get('title', '')
                username = row.get('Username') or row.get('username', '')
                password = row.get('Password') or row.get('password', '')
                notes = row.get('Notes') or row.get('notes', '')
                
                if site and username:
                    passwords[site] = {
                        'username': username,
                        'password': password,
                        'notes': notes,
                        'created': datetime.now().isoformat(),
                        'modified': datetime.now().isoformat()
                    }
        
        return passwords
    
    def _import_chrome(self, filepath: str) -> Dict[str, Dict]:
        """Import Chrome/Edge CSV export"""
        passwords = {}
        
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                # Chrome CSV headers: name,url,username,password
                site = row.get('name') or row.get('url', '')
                username = row.get('username', '')
                password = row.get('password', '')
                
                if site and username:
                    # Clean up URL if needed
                    if site.startswith('http'):
                        from urllib.parse import urlparse
                        parsed = urlparse(site)
                        site = parsed.netloc or site
                    
                    passwords[site] = {
                        'username': username,
                        'password': password,
                        'notes': '',
                        'created': datetime.now().isoformat(),
                        'modified': datetime.now().isoformat()
                    }
        
        return passwords
    
    def _import_keepass(self, filepath: str) -> Dict[str, Dict]:
        """Import KeePass CSV export"""
        passwords = {}
        
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                # KeePass CSV headers: Title,Username,Password,URL,Notes
                site = row.get('Title', '')
                username = row.get('Username', '')
                password = row.get('Password', '')
                notes = row.get('Notes', '')
                
                if site and username:
                    passwords[site] = {
                        'username': username,
                        'password': password,
                        'notes': notes,
                        'created': datetime.now().isoformat(),
                        'modified': datetime.now().isoformat()
                    }
        
        return passwords


class VaultExporter:
    """Export passwords to various formats"""
    
    def export_passwords(self, passwords: Dict[str, Dict], format_type: str, 
                        filepath: str = None, master_password: str = None) -> str:
        """
        Export passwords to specified format.
        
        Args:
            passwords: Dictionary of passwords from VaultKey
            format_type: Export format (csv, json, vaultkey)
            filepath: Optional file path (returns string if not provided)
            master_password: Required for encrypted formats
            
        Returns:
            Exported data as string if no filepath provided
        """
        if format_type == 'csv':
            data = self._export_csv(passwords)
        elif format_type == 'json':
            data = self._export_json(passwords)
        elif format_type == 'vaultkey':
            data = self._export_vaultkey(passwords, master_password)
        elif format_type == 'lastpass':
            data = self._export_lastpass_csv(passwords)
        elif format_type == 'bitwarden':
            data = self._export_bitwarden_csv(passwords)
        else:
            raise ValueError(f"Unsupported export format: {format_type}")
        
        if filepath:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(data)
            return f"Exported to {filepath}"
        else:
            return data
    
    def _export_csv(self, passwords: Dict[str, Dict]) -> str:
        """Export to generic CSV format"""
        output = StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['site', 'username', 'password', 'notes', 'created', 'modified'])
        
        # Write passwords
        for site, data in sorted(passwords.items()):
            writer.writerow([
                site,
                data.get('username', ''),
                data.get('password', ''),
                data.get('notes', ''),
                data.get('created', ''),
                data.get('modified', '')
            ])
        
        return output.getvalue()
    
    def _export_json(self, passwords: Dict[str, Dict]) -> str:
        """Export to JSON format (unencrypted)"""
        export_data = {
            'generator': 'VaultKey Password Manager',
            'version': '1.0',
            'exported': datetime.now().isoformat(),
            'passwords': passwords
        }
        
        return json.dumps(export_data, indent=2)
    
    def _export_vaultkey(self, passwords: Dict[str, Dict], master_password: str) -> str:
        """Export to encrypted VaultKey format"""
        if not master_password:
            raise ValueError("Master password required for encrypted export")
        
        # Create temporary crypto instance
        crypto = Crypto()
        temp_salt_file = 'export_salt.bin'
        crypto.salt_file = temp_salt_file
        
        try:
            # Generate new salt for export
            crypto.create_key(master_password)
            
            # Prepare data
            vault_data = {
                'version': '1.0',
                'exported': datetime.now().isoformat(),
                'passwords': passwords
            }
            
            # Encrypt the data
            encrypted = crypto.encrypt(json.dumps(vault_data))
            
            # Read the salt
            with open(temp_salt_file, 'rb') as f:
                salt_data = f.read()
            
            # Create export structure
            export_data = {
                'format': 'vaultkey_encrypted',
                'version': '1.0',
                'salt': base64.b64encode(salt_data).decode('utf-8'),
                'encrypted_data': base64.b64encode(encrypted).decode('utf-8')
            }
            
            # Clean up
            os.remove(temp_salt_file)
            
            return json.dumps(export_data, indent=2)
            
        except Exception as e:
            # Clean up on error
            if os.path.exists(temp_salt_file):
                os.remove(temp_salt_file)
            raise e
    
    def _export_lastpass_csv(self, passwords: Dict[str, Dict]) -> str:
        """Export to LastPass CSV format"""
        output = StringIO()
        writer = csv.writer(output)
        
        # LastPass CSV header
        writer.writerow(['url', 'username', 'password', 'totp', 'extra', 'name', 'grouping', 'fav'])
        
        for site, data in sorted(passwords.items()):
            writer.writerow([
                f'https://{site}',  # url
                data.get('username', ''),  # username
                data.get('password', ''),  # password
                '',  # totp
                data.get('notes', ''),  # extra
                site,  # name
                'Imported',  # grouping
                '0'  # fav
            ])
        
        return output.getvalue()
    
    def _export_bitwarden_csv(self, passwords: Dict[str, Dict]) -> str:
        """Export to Bitwarden CSV format"""
        output = StringIO()
        writer = csv.writer(output)
        
        # Bitwarden CSV header
        writer.writerow(['folder', 'favorite', 'type', 'name', 'notes', 'fields', 
                        'reprompt', 'login_uri', 'login_username', 'login_password', 'login_totp'])
        
        for site, data in sorted(passwords.items()):
            writer.writerow([
                '',  # folder
                '',  # favorite
                'login',  # type
                site,  # name
                data.get('notes', ''),  # notes
                '',  # fields
                '',  # reprompt
                f'https://{site}',  # login_uri
                data.get('username', ''),  # login_username
                data.get('password', ''),  # login_password
                ''  # login_totp
            ])
        
        return output.getvalue()


# Example usage and testing
if __name__ == "__main__":
    # Test import
    importer = VaultImporter()
    print("Supported import formats:")
    for fmt, desc in importer.SUPPORTED_FORMATS.items():
        print(f"  {fmt}: {desc}")
    
    # Test export
    exporter = VaultExporter()
    test_passwords = {
        'github.com': {
            'username': 'user@example.com',
            'password': 'test123',
            'notes': 'My GitHub account',
            'created': datetime.now().isoformat(),
            'modified': datetime.now().isoformat()
        },
        'google.com': {
            'username': 'user@gmail.com',
            'password': 'test456',
            'notes': '',
            'created': datetime.now().isoformat(),
            'modified': datetime.now().isoformat()
        }
    }
    
    print("\n\nCSV Export:")
    print(exporter.export_passwords(test_passwords, 'csv'))
    
    print("\nJSON Export:")
    print(exporter.export_passwords(test_passwords, 'json'))