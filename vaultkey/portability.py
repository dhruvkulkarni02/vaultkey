"""
portability.py - Import and export passwords in various formats
Supports CSV, JSON, and encrypted VaultKey format
"""
import csv
import json
import os
from typing import Dict, List, Optional
from datetime import datetime
import base64
from io import StringIO

from .crypto import Crypto, legacy_decrypt
from .errors import VaultFormatError


class VaultImporter:
    """Import passwords from various password manager formats"""
    
    SUPPORTED_FORMATS = {
        'vaultkey': 'VaultKey encrypted backup',
        'csv': 'Generic CSV (site,username,password)',
        'json': 'VaultKey JSON export',
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
        elif format_type == 'json':
            return self._import_json(filepath)
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
        """Import VaultKey encrypted export"""
        if not master_password:
            raise ValueError("Master password required for VaultKey import")
        
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        try:
            if 'envelope' in data:
                # The envelope carries its own salt and KDF parameters
                decrypted = Crypto.from_envelope(master_password, base64.b64decode(data['envelope']))[1]
            else:
                # VaultKey 1.0.x export: salt stored alongside a Fernet token
                decrypted = legacy_decrypt(
                    master_password,
                    base64.b64decode(data['salt']),
                    base64.b64decode(data['encrypted_data'])
                )
            return json.loads(decrypted)['passwords']
        except Exception as e:
            raise ValueError(f"Failed to decrypt backup: {str(e)}")
    
    def _import_json(self, filepath: str) -> Dict[str, Dict]:
        """Import an unencrypted VaultKey JSON export"""
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            data = json.load(f)
        
        passwords = data.get('passwords') if isinstance(data, dict) else None
        if not isinstance(passwords, dict):
            raise VaultFormatError("Not a VaultKey JSON export (no 'passwords' object)")
        
        return {
            site: {
                'username': entry.get('username', ''),
                'password': entry.get('password', ''),
                'notes': entry.get('notes', ''),
                'created': entry.get('created') or datetime.now().isoformat(),
                'modified': entry.get('modified') or datetime.now().isoformat()
            }
            for site, entry in passwords.items()
            if isinstance(entry, dict)
        }
    
    @staticmethod
    def _add_entry(passwords: Dict[str, Dict], site: str, entry: Dict) -> None:
        """
        Add an imported entry without overwriting another one for the same site.
        
        Several accounts on one site (e.g. two Gmail logins) are kept as
        "site (username)", then "site (username) #2", ...; exact duplicates are dropped.
        """
        key = site
        if key in passwords:
            existing = passwords[key]
            if (existing['username'], existing['password']) == (entry['username'], entry['password']):
                return
            base = f"{site} ({entry['username']})" if entry['username'] else site
            key, n = base, 2
            while key in passwords:
                key = f"{base} #{n}"
                n += 1
        passwords[key] = entry
    
    # Header names recognised by the generic CSV importer, per field
    CSV_COLUMN_ALIASES = {
        'site': ['site', 'name', 'title', 'url', 'login_uri', 'website', 'service'],
        'username': ['username', 'login_username', 'login', 'user', 'email', 'user name'],
        'password': ['password', 'login_password', 'pass'],
        'notes': ['notes', 'note', 'extra', 'comments', 'comment'],
    }
    
    def _import_generic_csv(self, filepath: str) -> Dict[str, Dict]:
        """
        Import generic CSV.
        
        With a header row, columns are matched by name (see CSV_COLUMN_ALIASES),
        in any order. Without one, columns must be site,username,password[,notes].
        """
        passwords = {}
        
        with open(filepath, 'r', encoding='utf-8-sig', newline='') as f:
            # Try to detect delimiter
            sample = f.read(1024)
            f.seek(0)
            
            delimiter = ','
            if '\t' in sample:
                delimiter = '\t'
            
            reader = csv.reader(f, delimiter=delimiter)
            first_row = next(reader, None)
            if not first_row:
                return passwords
            
            columns = self._map_csv_header(first_row)
            if columns is None:
                # No header: positional site,username,password[,notes]
                columns = {'site': 0, 'username': 1, 'password': 2, 'notes': 3}
                rows = [first_row]
            else:
                rows = []
            
            for row in rows + list(reader):
                def field(name):
                    index = columns.get(name)
                    return row[index] if index is not None and index < len(row) else ""
                
                site, username, password = field('site'), field('username'), field('password')
                
                # Skip empty rows
                if not site or not password:
                    continue
                
                self._add_entry(passwords, site, {
                    'username': username,
                    'password': password,
                    'notes': field('notes'),
                    'created': datetime.now().isoformat(),
                    'modified': datetime.now().isoformat()
                })
        
        return passwords
    
    def _map_csv_header(self, row: List[str]) -> Optional[Dict[str, int]]:
        """
        Map field name -> column index if row is a header, else return None.
        
        Raises:
            ValueError: The row looks like a header, but lacks a site or password column
        """
        normalized = [col.strip().lower() for col in row]
        columns = {}
        for name, aliases in self.CSV_COLUMN_ALIASES.items():
            # Earlier aliases win, e.g. a 'name' column beats a 'url' column for the site
            for alias in aliases:
                if alias in normalized:
                    columns[name] = normalized.index(alias)
                    break
        
        found = {'site', 'password'} & set(columns)
        if not found:
            # Data cells can coincide with aliases (e.g. a username "user"), so
            # only a recognisable site or password column marks a header
            return None
        if len(found) < 2:
            raise ValueError(
                f"CSV header {row} has no recognisable site and password columns; "
                f"use --format to pick the exporting password manager"
            )
        return columns
    
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
                
                if site and username:
                    # Clean up the site name
                    if site.startswith('http'):
                        # Extract domain from URL
                        from urllib.parse import urlparse
                        parsed = urlparse(site)
                        site = parsed.netloc or site
                    
                    self._add_entry(passwords, site, {
                        'username': username,
                        'password': password,
                        'notes': notes,
                        'created': datetime.now().isoformat(),
                        'modified': datetime.now().isoformat()
                    })
        
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
                    self._add_entry(passwords, site, {
                        'username': username,
                        'password': password,
                        'notes': notes,
                        'created': datetime.now().isoformat(),
                        'modified': datetime.now().isoformat()
                    })
        
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
                    self._add_entry(passwords, site, {
                        'username': username,
                        'password': password,
                        'notes': notes,
                        'created': datetime.now().isoformat(),
                        'modified': datetime.now().isoformat()
                    })
        
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
                    
                    self._add_entry(passwords, site, {
                        'username': username,
                        'password': password,
                        'notes': '',
                        'created': datetime.now().isoformat(),
                        'modified': datetime.now().isoformat()
                    })
        
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
                    self._add_entry(passwords, site, {
                        'username': username,
                        'password': password,
                        'notes': notes,
                        'created': datetime.now().isoformat(),
                        'modified': datetime.now().isoformat()
                    })
        
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
            # Exports may contain plaintext passwords: create the file owner-only
            fd = os.open(filepath, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with open(fd, 'w', encoding='utf-8', newline='') as f:
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
        
        # Fresh salt; the envelope records it along with the KDF parameters
        crypto = Crypto()
        crypto.create_key(master_password)
        
        vault_data = {
            'version': '1.0',
            'exported': datetime.now().isoformat(),
            'passwords': passwords
        }
        
        export_data = {
            'format': 'vaultkey_encrypted',
            'version': '2.0',
            'envelope': base64.b64encode(crypto.encrypt(json.dumps(vault_data))).decode('utf-8')
        }
        return json.dumps(export_data, indent=2)
    
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