'''
storage.py - Handles all data storage operations
This is the data core of VaultKey
'''
import os
from typing import Optional


class Storage:
    """Manages persistent storage of encrypted password data"""
    
    def __init__(self, filename: str = "passwords.encrypted"):
        """
        Initialize storage with a filename.
        
        Args:
            filename: Name of the file to store encrypted passwords
        """
        self.filename = filename
    
    def save(self, encrypted_data: bytes, version: int = 2) -> None:
        """
        Save encrypted data to file with secure permissions and version header.
        
        Args:
            encrypted_data: The encrypted bytes to save
            version: Version number for future compatibility
        """
        # Add version header for future compatibility
        version_header = f"VAULTKEY_V{version}:".encode()
        data_to_save = version_header + encrypted_data
        
        # Write the data to file
        with open(self.filename, 'wb') as f:
            f.write(data_to_save)
        
        # Set restrictive file permissions (Unix/Linux/Mac only)
        # This makes the file readable/writable by owner only (600)
        if os.name == 'posix':  # Unix-like systems
            os.chmod(self.filename, 0o600)
    
    def load(self) -> tuple:
        """
        Load encrypted data from file and return version info.
        
        Returns:
            Tuple of (version, encrypted_data) where version is int and data is bytes
            Returns (1, data) for legacy files without version headers
        """
        if not os.path.exists(self.filename):
            # Return empty data with current version for new vaults
            return (2, b'')
        
        with open(self.filename, 'rb') as f:
            data = f.read()
        
        # Check for version header
        if data.startswith(b'VAULTKEY_V'):
            try:
                # Parse version from header like "VAULTKEY_V2:"
                header_end = data.find(b':')
                if header_end > 0:
                    version_str = data[10:header_end].decode()
                    version = int(version_str)
                    encrypted_data = data[header_end + 1:]
                    return (version, encrypted_data)
            except (ValueError, UnicodeDecodeError):
                pass
        
        # Legacy format without version header
        return (1, data)
    
    def exists(self) -> bool:
        """
        Check if the password file exists.
        
        Returns:
            True if password file exists, False otherwise
        """
        return os.path.exists(self.filename)
    
    def delete(self) -> bool:
        """
        Delete the password file (use with caution!).
        
        Returns:
            True if file was deleted, False if it didn't exist
        """
        if os.path.exists(self.filename):
            os.remove(self.filename)
            return True
        return False
    
    def get_file_info(self) -> Optional[dict]:
        """
        Get information about the storage file.
        
        Returns:
            Dictionary with file info, or None if file doesn't exist
        """
        if not self.exists():
            return None
        
        stat = os.stat(self.filename)
        return {
            'size': stat.st_size,
            'modified': stat.st_mtime,
            'permissions': oct(stat.st_mode)[-3:] if os.name == 'posix' else 'N/A'
        }


# Example usage (for testing)
if __name__ == "__main__":
    # Create storage instance
    storage = Storage("test_passwords.encrypted")
    
    # Test saving some data
    test_data = b"This is some encrypted data (pretend it's encrypted!)"
    storage.save(test_data)
    print("✓ Saved test data")
    
    # Test loading it back
    loaded_data = storage.load()
    print(f"✓ Loaded {len(loaded_data)} bytes")
    
    # Verify it matches
    assert test_data == loaded_data
    print("✓ Data matches!")
    
    # Check file info
    info = storage.get_file_info()
    print(f"✓ File info: {info}")
    
    # Clean up test file
    storage.delete()
    print("✓ Test file cleaned up")