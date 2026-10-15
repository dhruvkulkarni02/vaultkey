"""
manager.py - Main password manager class that orchestrates all functionality
"""
import json
import os
import time
from typing import Dict, Optional, List, Tuple
from datetime import datetime

from .crypto import Crypto, legacy_decrypt
from .errors import (
    DecryptionError,
    LockoutError,
    VaultExistsError,
    VaultFormatError,
    VaultLockedError,
    VaultNotFoundError,
)
from .storage import CURRENT_VERSION, Storage
from .generator import generate_password

DEFAULT_VAULT_PATH = os.path.join("~", ".vaultkey", "passwords.encrypted")


def default_vault_path() -> str:
    """Vault location: $VAULTKEY_VAULT if set, otherwise ~/.vaultkey/passwords.encrypted"""
    return os.path.expanduser(os.environ.get("VAULTKEY_VAULT") or DEFAULT_VAULT_PATH)


class PasswordManager:
    """Main class that combines crypto, storage, and password management"""
    
    def __init__(self, storage_file: Optional[str] = None):
        """
        Initialize the password manager.
        
        Args:
            storage_file: Path of the encrypted vault file (default: default_vault_path())
        """
        self.crypto = Crypto()
        self.storage = Storage(storage_file or default_vault_path())
        self.unlocked = False
        self._cached_passwords = {}
        self.migrated_from_version = None  # Set when unlock() upgraded a 1.0.x vault
        
        # VaultKey 1.0.x kept the KDF salt in a separate file next to the vault
        vault_dir = os.path.dirname(os.path.abspath(self.storage.filename))
        self.legacy_salt_file = os.path.join(vault_dir, "salt.bin")
        
        # Lockout after repeated failures. This only lasts as long as this object
        # (e.g. one interactive session); the real defence against guessing is
        # the cost of Argon2id, which also applies to offline attacks.
        self.failed_attempts = 0
        self.lockout_until = None
        self.max_attempts = 5
        self.lockout_duration = 300  # 5 minutes
    
    def create_vault(self, master_password: str) -> None:
        """
        Create a new password vault with the given master password.
        
        Args:
            master_password: The master password to protect the vault
            
        Raises:
            VaultExistsError: If vault already exists
            ValueError: If the master password is empty
        """
        if self.storage.exists():
            raise VaultExistsError("Vault already exists! Use unlock() instead.")
        if not master_password:
            raise ValueError("Master password must not be empty")
        
        # Create encryption key (with a fresh random salt) from master password
        self.crypto.create_key(master_password)
        
        # Create empty vault with metadata
        self._cached_passwords = {
            "version": "1.1",  # Updated version for history support
            "created": datetime.now().isoformat(),
            "passwords": {},
            "settings": {
                "history_enabled": True,
                "max_history_items": 10  # Keep last 10 passwords
            }
        }
        self._save()
        self.unlocked = True
    
    def unlock(self, master_password: str) -> bool:
        """
        Unlock the vault using the master password.
        
        Vaults written by VaultKey 1.0.x are re-encrypted in the current format
        on the first successful unlock.
        
        Args:
            master_password: The master password to unlock the vault
            
        Returns:
            True if unlocked successfully, False if wrong password
            
        Raises:
            LockoutError: Too many failed attempts
            VaultNotFoundError: No vault file exists
            VaultFormatError: The vault file is malformed or from an unknown version
        """
        # Check if locked out
        if self.lockout_until and time.time() < self.lockout_until:
            remaining = int(self.lockout_until - time.time())
            raise LockoutError(f"Too many failed attempts. Try again in {remaining} seconds.")
        
        if not self.storage.exists():
            raise VaultNotFoundError("No vault exists! Create one with create_vault() first.")
        
        version, data = self.storage.load()
        try:
            if version == CURRENT_VERSION:
                crypto, decrypted_data = Crypto.from_envelope(master_password, data)
            elif version in (1, 2):
                crypto, decrypted_data = None, self._decrypt_legacy_vault(master_password, version, data)
            else:
                raise VaultFormatError(f"Unsupported vault version: {version}")
        except DecryptionError:
            # A failed attempt leaves an already-unlocked session as it was
            self._register_failed_attempt()
            return False
        
        self._cached_passwords = json.loads(decrypted_data)
        self.unlocked = True
        self.failed_attempts = 0
        self.lockout_until = None
        
        if crypto is None:
            # Re-encrypt the 1.0.x vault in the current format, with a fresh salt
            self.crypto = Crypto()
            self.crypto.create_key(master_password)
            self._save()
            self.migrated_from_version = version
        else:
            self.crypto = crypto
        
        # Check if we need to migrate to newer version
        if self._cached_passwords.get("version") == "1.0":
            self._migrate_vault_to_v1_1()
        
        return True
    
    def _register_failed_attempt(self) -> None:
        """Count a failed unlock and start a lockout once the limit is reached"""
        self.failed_attempts += 1
        if self.failed_attempts >= self.max_attempts:
            self.failed_attempts = 0
            self.lockout_until = time.time() + self.lockout_duration
            raise LockoutError(
                f"Too many failed attempts. Locked for {self.lockout_duration // 60} minutes."
            )
    
    def _decrypt_legacy_vault(self, master_password: str, version: int, data: bytes) -> str:
        """Decrypt a vault written by VaultKey 1.0.x (Fernet, salt kept in salt.bin)"""
        if version == 2 and data.startswith(b"VAULTKEY"):
            # Skip the 1.0.x b"VAULTKEY" + HMAC header; Fernet authenticates the token itself
            data = data[40:]
        return legacy_decrypt(master_password, _read_legacy_salt(self.legacy_salt_file), data)
    
    def _migrate_vault_to_v1_1(self) -> None:
        """Migrate vault from v1.0 to v1.1 with history support"""
        self._cached_passwords["version"] = "1.1"
        self._cached_passwords["settings"] = {
            "history_enabled": True,
            "max_history_items": 10
        }
        
        # Add history to existing passwords
        for site, data in self._cached_passwords["passwords"].items():
            if "history" not in data:
                data["history"] = []
        
        self._save()
    
    def lock(self) -> None:
        """Lock the vault and clear cached passwords from memory"""
        self.unlocked = False
        self._cached_passwords = {}
        self.crypto.key = None
    
    def is_unlocked(self) -> bool:
        """Check if the vault is currently unlocked"""
        return self.unlocked
    
    def add_password(
        self, 
        site: str, 
        username: str, 
        password: Optional[str] = None,
        notes: Optional[str] = None,
        generate_new: bool = False,
        password_length: int = 16
    ) -> str:
        """
        Add or update a password in the vault.
        
        Args:
            site: Website or service name
            username: Username or email
            password: Password (if None and generate_new=True, will generate one)
            notes: Optional notes about this account
            generate_new: Whether to generate a new password
            password_length: Length of generated password
            
        Returns:
            The password that was saved
            
        Raises:
            VaultLockedError: If vault is locked
        """
        if not self.unlocked:
            raise VaultLockedError("Vault is locked! Call unlock() first.")
        
        # Generate password if requested
        if generate_new or password is None:
            password = generate_password(password_length)
        
        # Check if updating existing password
        existing = self._cached_passwords["passwords"].get(site)
        if existing:
            # Save to history before updating
            self._add_to_history(site, existing["password"], existing.get("modified"))
        
        # Add to passwords with metadata
        self._cached_passwords["passwords"][site] = {
            "username": username,
            "password": password,
            "notes": notes or "",
            "created": existing["created"] if existing else datetime.now().isoformat(),
            "modified": datetime.now().isoformat(),
            "history": existing.get("history", []) if existing else []
        }
        
        # Save to disk
        self._save()
        
        return password
    
    def _add_to_history(self, site: str, old_password: str, changed_date: Optional[str] = None) -> None:
        """Add a password to the history for a site"""
        if not self._cached_passwords.get("settings", {}).get("history_enabled", True):
            return
        
        max_history = self._cached_passwords.get("settings", {}).get("max_history_items", 10)
        
        history_entry = {
            "password": old_password,
            "changed": changed_date or datetime.now().isoformat(),
            "retired": datetime.now().isoformat()
        }
        
        # Get or create history list
        if site in self._cached_passwords["passwords"]:
            history = self._cached_passwords["passwords"][site].get("history", [])
            
            # Don't add duplicates
            if history and history[-1]["password"] == old_password:
                return
            
            # Add to history
            history.append(history_entry)
            
            # Trim history to max items
            if len(history) > max_history:
                history = history[-max_history:]
            
            self._cached_passwords["passwords"][site]["history"] = history
    
    def get_password(self, site: str) -> Optional[Dict[str, str]]:
        """
        Retrieve password information for a site.
        
        Args:
            site: Website or service name
            
        Returns:
            Dictionary with username, password, notes, etc., or None if not found
        """
        if not self.unlocked:
            raise VaultLockedError("Vault is locked! Call unlock() first.")
        
        return self._cached_passwords["passwords"].get(site)
    
    def get_password_history(self, site: str) -> List[Dict[str, str]]:
        """
        Get password history for a site.
        
        Args:
            site: Website or service name
            
        Returns:
            List of historical passwords with change dates
        """
        if not self.unlocked:
            raise VaultLockedError("Vault is locked! Call unlock() first.")
        
        password_data = self._cached_passwords["passwords"].get(site)
        if not password_data:
            return []
        
        return password_data.get("history", [])
    
    def clear_history(self, site: str = None) -> int:
        """
        Clear password history for a specific site or all sites.
        
        Args:
            site: Site to clear history for (None = all sites)
            
        Returns:
            Number of history entries cleared
        """
        if not self.unlocked:
            raise VaultLockedError("Vault is locked! Call unlock() first.")
        
        cleared = 0
        
        if site:
            # Clear history for specific site
            if site in self._cached_passwords["passwords"]:
                history = self._cached_passwords["passwords"][site].get("history", [])
                cleared = len(history)
                self._cached_passwords["passwords"][site]["history"] = []
        else:
            # Clear all history
            for site_name, data in self._cached_passwords["passwords"].items():
                history = data.get("history", [])
                cleared += len(history)
                data["history"] = []
        
        if cleared > 0:
            self._save()
        
        return cleared
    
    def check_password_reuse(self, site: str, password: str) -> bool:
        """
        Check if a password was previously used for this site.
        
        Args:
            site: Website or service name
            password: Password to check
            
        Returns:
            True if password was used before, False otherwise
        """
        if not self.unlocked:
            raise VaultLockedError("Vault is locked! Call unlock() first.")
        
        password_data = self._cached_passwords["passwords"].get(site)
        if not password_data:
            return False
        
        # Check current password
        if password_data["password"] == password:
            return True
        
        # Check history
        for hist in password_data.get("history", []):
            if hist["password"] == password:
                return True
        
        return False
    
    def list_sites(self) -> List[str]:
        """
        List all sites that have stored passwords.
        
        Returns:
            List of site names
        """
        if not self.unlocked:
            raise VaultLockedError("Vault is locked! Call unlock() first.")
        
        return sorted(self._cached_passwords["passwords"].keys())
    
    def search_sites(self, query: str) -> List[str]:
        """
        Search for sites containing the query string.
        
        Args:
            query: Search string (case-insensitive)
            
        Returns:
            List of matching site names
        """
        if not self.unlocked:
            raise VaultLockedError("Vault is locked! Call unlock() first.")
        
        query_lower = query.lower()
        matches = [
            site for site in self._cached_passwords["passwords"].keys()
            if query_lower in site.lower()
        ]
        return sorted(matches)
    
    def delete_password(self, site: str) -> bool:
        """
        Delete a password from the vault.
        
        Args:
            site: Website or service name
            
        Returns:
            True if deleted, False if site not found
        """
        if not self.unlocked:
            raise VaultLockedError("Vault is locked! Call unlock() first.")
        
        if site in self._cached_passwords["passwords"]:
            del self._cached_passwords["passwords"][site]
            self._save()
            return True
        return False
    
    def update_password(
        self, 
        site: str, 
        new_password: Optional[str] = None,
        new_username: Optional[str] = None,
        new_notes: Optional[str] = None,
        generate_new: bool = False,
        password_length: int = 16
    ) -> bool:
        """
        Update an existing password entry.
        
        Args:
            site: Website or service name
            new_password: New password (optional)
            new_username: New username (optional)
            new_notes: New notes (optional)
            generate_new: Whether to generate a new password
            password_length: Length of generated password
            
        Returns:
            True if updated, False if site not found
        """
        if not self.unlocked:
            raise VaultLockedError("Vault is locked! Call unlock() first.")
        
        if site not in self._cached_passwords["passwords"]:
            return False
        
        entry = self._cached_passwords["passwords"][site]
        
        # Save old password to history if changing password
        if new_password or generate_new:
            self._add_to_history(site, entry["password"], entry.get("modified"))
        
        # Update fields if provided
        if new_username is not None:
            entry["username"] = new_username
        
        if generate_new:
            entry["password"] = generate_password(password_length)
        elif new_password is not None:
            entry["password"] = new_password
        
        if new_notes is not None:
            entry["notes"] = new_notes
        
        # Update modified timestamp
        entry["modified"] = datetime.now().isoformat()
        
        self._save()
        return True
    
    def get_vault_info(self) -> Dict:
        """
        Get information about the vault.
        
        Returns:
            Dictionary with vault metadata
        """
        if not self.unlocked:
            raise VaultLockedError("Vault is locked! Call unlock() first.")
        
        # Count total history entries
        total_history = 0
        for data in self._cached_passwords["passwords"].values():
            total_history += len(data.get("history", []))
        
        return {
            "version": self._cached_passwords.get("version", "1.0"),
            "created": self._cached_passwords.get("created", "Unknown"),
            "password_count": len(self._cached_passwords["passwords"]),
            "history_entries": total_history,
            "history_enabled": self._cached_passwords.get("settings", {}).get("history_enabled", True),
            "file_info": self.storage.get_file_info()
        }
    
    def export_passwords(self, include_passwords: bool = False, include_history: bool = False) -> Dict:
        """
        Export passwords (for backup or migration).
        
        Args:
            include_passwords: Whether to include actual passwords
            include_history: Whether to include password history
            
        Returns:
            Dictionary of all password data
        """
        if not self.unlocked:
            raise VaultLockedError("Vault is locked! Call unlock() first.")
        
        export_data = {
            "version": self._cached_passwords.get("version", "1.0"),
            "exported": datetime.now().isoformat(),
            "passwords": {}
        }
        
        for site, data in self._cached_passwords["passwords"].items():
            export_entry = {
                "username": data["username"],
                "password": data["password"] if include_passwords else "***HIDDEN***",
                "notes": data.get("notes", ""),
                "created": data.get("created", ""),
                "modified": data.get("modified", "")
            }
            
            if include_history and data.get("history"):
                export_entry["history"] = [
                    {
                        "password": h["password"] if include_passwords else "***HIDDEN***",
                        "changed": h.get("changed", ""),
                        "retired": h.get("retired", "")
                    }
                    for h in data["history"]
                ]
            
            export_data["passwords"][site] = export_entry
        
        return export_data
    
    def import_entries(self, entries: Dict[str, Dict], overwrite: bool = False) -> Tuple[List[str], List[str]]:
        """
        Add many entries with a single save, so an import either fully lands or not at all.
        
        Args:
            entries: Mapping of site -> {"username", "password", "notes", ...}
            overwrite: Replace existing entries instead of skipping them
            
        Returns:
            (imported_sites, skipped_sites)
        """
        if not self.unlocked:
            raise VaultLockedError("Vault is locked! Call unlock() first.")
        
        imported, skipped = [], []
        now = datetime.now().isoformat()
        for site, data in entries.items():
            existing = self._cached_passwords["passwords"].get(site)
            if existing and not overwrite:
                skipped.append(site)
                continue
            if existing:
                self._add_to_history(site, existing["password"], existing.get("modified"))
            self._cached_passwords["passwords"][site] = {
                "username": data.get("username", ""),
                "password": data.get("password", ""),
                "notes": data.get("notes", ""),
                "created": existing["created"] if existing else now,
                "modified": now,
                "history": existing.get("history", []) if existing else [],
            }
            imported.append(site)
        
        if imported:
            self._save()
        return imported, skipped
    
    def _save(self, crypto: Optional[Crypto] = None) -> None:
        """Encrypt the current password data and atomically replace the vault file"""
        json_data = json.dumps(self._cached_passwords, indent=2)
        self.storage.save((crypto or self.crypto).encrypt(json_data))
    
    def create_secure_backup(self, backup_password: str, backup_path: Optional[str] = None) -> str:
        """
        Create a self-contained encrypted backup, protected by its own password.
        
        The salt and KDF parameters are stored inside the backup file, so the
        single file is all that's needed to restore it.
        
        Args:
            backup_password: Password for the backup (may equal the master password)
            backup_path: Path for backup file (default: auto-generate)
            
        Returns:
            Path to created backup file
        """
        if not self.unlocked:
            raise VaultLockedError("Vault is locked! Call unlock() first.")
        if not backup_password:
            raise ValueError("Backup password must not be empty")
        
        # Generate backup filename if not provided
        if not backup_path:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_path = f"vaultkey_backup_{timestamp}.vkbak"
        
        # Create backup data with metadata
        backup_data = {
            "version": "1.2",
            "backup_date": datetime.now().isoformat(),
            "original_vault": self.storage.filename,
            "backup_type": "secure_backup",
            "data": self._cached_passwords
        }
        
        backup_crypto = Crypto()
        backup_crypto.create_key(backup_password)
        Storage(backup_path).save(backup_crypto.encrypt(json.dumps(backup_data, indent=2)))
        
        return backup_path
    
    def restore_from_backup(
        self,
        backup_path: str,
        backup_password: str,
        master_password: Optional[str] = None
    ) -> str:
        """
        Replace the vault's contents with a backup.
        
        If the vault is unlocked, the restored data is encrypted under the current
        master password. Otherwise master_password is required and becomes the
        master password of the restored vault (e.g. restoring onto a new machine).
        
        Args:
            backup_path: Path to backup file
            backup_password: Password for backup
            master_password: Master password for the restored vault, if not unlocked
            
        Returns:
            The backup's creation date (ISO format), or "unknown date"
            
        Raises:
            DecryptionError: Wrong backup password, or the backup is corrupted
            VaultFormatError: The file is not a VaultKey backup
            VaultLockedError: The vault is locked and no master_password was given
        """
        if not self.unlocked and not master_password:
            raise VaultLockedError("Unlock the vault or give a master password for the restored vault")
        
        version, encrypted_data = Storage(backup_path).load()
        if version == CURRENT_VERSION:
            decrypted_data = Crypto.from_envelope(backup_password, encrypted_data)[1]
        elif version in (1, 2):
            # 1.0.x backups kept their salt in a "<backup>.salt" sidecar file
            salt = _read_legacy_salt(backup_path + ".salt")
            decrypted_data = legacy_decrypt(backup_password, salt, encrypted_data)
        else:
            raise VaultFormatError(f"Unsupported backup version: {version}")
        
        backup_data = json.loads(decrypted_data)
        
        # Validate backup format
        vault_data = backup_data.get("data")
        if (backup_data.get("backup_type") != "secure_backup"
                or not isinstance(vault_data, dict)
                or not isinstance(vault_data.get("passwords"), dict)):
            raise VaultFormatError("Invalid backup format")
        
        if not self.unlocked:
            self.crypto = Crypto()
            self.crypto.create_key(master_password)
        
        self._cached_passwords = vault_data
        if self._cached_passwords.get("version") == "1.0":
            self._migrate_vault_to_v1_1()
        self._save()
        self.unlocked = True
        
        return backup_data.get("backup_date", "unknown date")

    def change_master_password(self, current_password: str, new_password: str) -> bool:
        """
        Change the master password for the vault.
        
        The vault is re-encrypted under a new salt and key and atomically
        replaces the old file, so a crash leaves one of the two intact.
        
        Args:
            current_password: Current master password
            new_password: New master password
            
        Returns:
            True if successful, False if current password is wrong
        """
        if not new_password:
            raise ValueError("Master password must not be empty")
        
        # Verify current password
        if not self.unlock(current_password):
            return False
        
        new_crypto = Crypto()
        new_crypto.create_key(new_password)
        self._save(new_crypto)
        self.crypto = new_crypto
        
        return True


def _read_legacy_salt(salt_file: str) -> bytes:
    """Read a VaultKey 1.0.x salt file, which is required to decrypt 1.0.x data"""
    if not os.path.exists(salt_file):
        raise VaultFormatError(
            f"This file was created by VaultKey 1.0 and needs its salt file, "
            f"which is missing: {salt_file}"
        )
    with open(salt_file, 'rb') as f:
        return f.read()
