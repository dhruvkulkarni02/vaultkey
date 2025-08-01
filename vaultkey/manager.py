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
            "version": "1.0",
            "created": datetime.now().isoformat(),
            "passwords": {}
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
            self.unlocked = True
            return True
            
        except Exception as e:
            # Wrong password or corrupted data
            self.unlocked = False
            self._cached_passwords = {}
            return False
    
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
        
        # Add to passwords with metadata
        self._cached_passwords["passwords"][site] = {
            "username": username,
            "password": password,
            "notes": notes or "",
            "created": datetime.now().isoformat(),
            "modified": datetime.now().isoformat()
        }
        
        # Save to disk
        self._save()
        
        return password
    
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
        
        return {
            "version": self._cached_passwords.get("version", "1.0"),
            "created": self._cached_passwords.get("created", "Unknown"),
            "password_count": len(self._cached_passwords["passwords"]),
            "file_info": self.storage.get_file_info()
        }
    
    def export_passwords(self, include_passwords: bool = False) -> Dict:
        """
        Export passwords (for backup or migration).
        
        Args:
            include_passwords: Whether to include actual passwords
            
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
            export_data["passwords"][site] = {
                "username": data["username"],
                "password": data["password"] if include_passwords else "***HIDDEN***",
                "notes": data.get("notes", ""),
                "created": data.get("created", ""),
                "modified": data.get("modified", "")
            }
        
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
    # Test the password manager
    pm = PasswordManager("test_vault.encrypted")
    
    print("=== Password Manager Test ===\n")
    
    # Create a new vault
    print("Creating new vault...")
    pm.create_vault("my-master-password")
    
    # Add some passwords
    print("\nAdding passwords...")
    pm.add_password("github.com", "user@example.com", "ghp_1234567890")
    pm.add_password("google.com", "user@gmail.com", generate_new=True)
    password = pm.add_password("amazon.com", "shopper@email.com", generate_new=True, password_length=20)
    print(f"Generated password for Amazon: {password}")
    
    # List sites
    print("\nStored passwords:")
    for site in pm.list_sites():
        info = pm.get_password(site)
        print(f"  • {site}: {info['username']}")
    
    # Search
    print("\nSearching for 'git':")
    for site in pm.search_sites("git"):
        print(f"  • {site}")
    
    # Vault info
    print("\nVault info:")
    info = pm.get_vault_info()
    print(f"  • Version: {info['version']}")
    print(f"  • Passwords stored: {info['password_count']}")
    
    # Clean up
    pm.lock()
    os.remove("test_vault.encrypted")
    os.remove("salt.bin")
    print("\n✓ Test completed successfully!")