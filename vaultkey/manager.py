"""
manager.py - Main password manager class that orchestrates all functionality
"""
import json
import os
from typing import Dict, Optional, List
from datetime import datetime

from .crypto import Crypto
from .storage import Storage
from .generator import generate_password


class PasswordManager:
    """Main class that combines crypto, storage, and password management"""
    
    def __init__(self, storage_file: str = "passwords.encrypted"):
        """
        Initialize the password manager.
        
        Args:
            storage_file: Name of the file to store encrypted passwords
        """
        self.crypto = Crypto()
        self.storage = Storage(storage_file)
        self.unlocked = False
        self._cached_passwords = {}
    
    def create_vault(self, master_password: str) -> None:
        """
        Create a new password vault with the given master password.
        
        Args:
            master_password: The master password to protect the vault
            
        Raises:
            Exception: If vault already exists
        """
        if self.storage.exists():
            raise Exception("Vault already exists! Use unlock() instead.")
        
        # Create encryption key from master password
        self.crypto.create_key(master_password)
        
        # Create empty vault with metadata
        vault_data = {
            "version": "1.1",  # Updated version for history support
            "created": datetime.now().isoformat(),
            "passwords": {},
            "settings": {
                "history_enabled": True,
                "max_history_items": 10  # Keep last 10 passwords
            }
        }
        
        # Encrypt and save
        encrypted_data = self.crypto.encrypt(json.dumps(vault_data))
        self.storage.save(encrypted_data)
        
        self.unlocked = True
        self._cached_passwords = vault_data
        print(f"✓ Created new vault: {self.storage.filename}")
    
    def unlock(self, master_password: str) -> bool:
        """
        Unlock an existing vault with the master password.
        
        Args:
            master_password: The master password to unlock the vault
            
        Returns:
            True if successfully unlocked, False if wrong password
        """
        if not self.storage.exists():
            raise Exception("No vault found! Use create_vault() first.")
        
        try:
            # Set up decryption key
            self.crypto.create_key(master_password)
            
            # Try to decrypt the vault
            encrypted_data = self.storage.load()
            decrypted_data = self.crypto.decrypt(encrypted_data)
            
            # Parse the JSON data
            self._cached_passwords = json.loads(decrypted_data)
            
            # Migrate old vaults to support history
            if self._cached_passwords.get("version", "1.0") == "1.0":
                self._migrate_vault_to_v1_1()
            
            self.unlocked = True
            return True
            
        except Exception as e:
            # Wrong password or corrupted data
            self.unlocked = False
            self._cached_passwords = {}
            return False
    
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
            Exception: If vault is locked
        """
        if not self.unlocked:
            raise Exception("Vault is locked! Call unlock() first.")
        
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
            raise Exception("Vault is locked! Call unlock() first.")
        
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
            raise Exception("Vault is locked! Call unlock() first.")
        
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
            raise Exception("Vault is locked! Call unlock() first.")
        
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
            raise Exception("Vault is locked! Call unlock() first.")
        
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
            raise Exception("Vault is locked! Call unlock() first.")
        
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
            raise Exception("Vault is locked! Call unlock() first.")
        
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
            raise Exception("Vault is locked! Call unlock() first.")
        
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
            raise Exception("Vault is locked! Call unlock() first.")
        
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
            raise Exception("Vault is locked! Call unlock() first.")
        
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
            raise Exception("Vault is locked! Call unlock() first.")
        
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
    
    def _save(self) -> None:
        """Save the current password data to encrypted storage"""
        json_data = json.dumps(self._cached_passwords, indent=2)
        encrypted_data = self.crypto.encrypt(json_data)
        self.storage.save(encrypted_data)
    
    def change_master_password(self, current_password: str, new_password: str) -> bool:
        """
        Change the master password for the vault.
        
        Args:
            current_password: Current master password
            new_password: New master password
            
        Returns:
            True if successful, False if current password is wrong
        """
        # Verify current password
        if not self.unlock(current_password):
            return False
        
        # Create new salt and encryption key
        if os.path.exists(self.crypto.salt_file):
            os.remove(self.crypto.salt_file)
        
        # Re-encrypt with new password
        self.crypto.create_key(new_password)
        self._save()
        
        return True


# Example usage (for testing)
if __name__ == "__main__":
    # Test the password manager with history
    pm = PasswordManager("test_vault_with_history.encrypted")
    
    print("=== Password Manager with History Test ===\n")
    
    # Create a new vault
    print("Creating new vault...")
    pm.create_vault("my-master-password")
    
    # Add a password
    print("\nAdding initial password for github.com...")
    pm.add_password("github.com", "user@example.com", "initial_password_123")
    
    # Update the password (should save to history)
    print("Updating password (first change)...")
    pm.update_password("github.com", new_password="second_password_456")
    
    # Update again
    print("Updating password (second change)...")
    pm.update_password("github.com", new_password="third_password_789")
    
    # Check history
    print("\nPassword history for github.com:")
    history = pm.get_password_history("github.com")
    for i, hist in enumerate(history, 1):
        print(f"  {i}. Password: {hist['password'][:10]}... (changed: {hist['changed'][:10]})")
    
    # Check reuse
    print("\nChecking password reuse:")
    print(f"  'initial_password_123' was used before: {pm.check_password_reuse('github.com', 'initial_password_123')}")
    print(f"  'never_used_password' was used before: {pm.check_password_reuse('github.com', 'never_used_password')}")
    
    # Vault info
    print("\nVault info:")
    info = pm.get_vault_info()
    print(f"  Version: {info['version']}")
    print(f"  Passwords: {info['password_count']}")
    print(f"  History entries: {info['history_entries']}")
    
    # Clean up
    pm.lock()
    os.remove("test_vault_with_history.encrypted")
    os.remove("salt.bin")
    print("\n✓ Test completed successfully!")