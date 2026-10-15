'''
storage.py - Handles all data storage operations
This is the data core of VaultKey
'''
import os
import tempfile
from typing import Optional, Tuple

# File format written by this version: "VAULTKEY_V3:" followed by a crypto envelope.
# V1 (no header) and V2 are VaultKey 1.0.x files, which are only read, for migration.
CURRENT_VERSION = 3


class Storage:
    """Manages persistent storage of encrypted password data"""
    
    def __init__(self, filename: str = "passwords.encrypted"):
        """
        Initialize storage with a filename.
        
        Args:
            filename: Name of the file to store encrypted passwords
        """
        self.filename = filename
    
    def save(self, encrypted_data: bytes, version: int = CURRENT_VERSION) -> None:
        """
        Atomically save encrypted data with a version header.

        The data is written to a temporary file in the same directory (created
        owner-only, 0600), flushed to disk, then renamed over the old file. A
        crash at any point leaves either the old or the new file intact, never
        a half-written one.

        Args:
            encrypted_data: The encrypted bytes to save
            version: Version number for future compatibility
        """
        data_to_save = f"VAULTKEY_V{version}:".encode() + encrypted_data

        directory = os.path.dirname(os.path.abspath(self.filename))
        os.makedirs(directory, mode=0o700, exist_ok=True)

        fd, temp_path = tempfile.mkstemp(prefix=".vaultkey-", suffix=".tmp", dir=directory)
        try:
            with os.fdopen(fd, 'wb') as f:
                f.write(data_to_save)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_path, self.filename)
        except BaseException:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise

        # Persist the rename itself (POSIX only; Windows can't open directories)
        if os.name == 'posix':
            dir_fd = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
    
    def load(self) -> Tuple[int, bytes]:
        """
        Load encrypted data from file and return version info.
        
        Returns:
            Tuple of (version, encrypted_data) where version is int and data is bytes
            Returns (1, data) for legacy files without version headers
        """
        if not os.path.exists(self.filename):
            # Return empty data with current version for new vaults
            return (CURRENT_VERSION, b'')
        
        with open(self.filename, 'rb') as f:
            data = f.read()
        
        # Check for version header
        if data.startswith(b'VAULTKEY_V'):
            try:
                # Parse version from header like "VAULTKEY_V3:"
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

