"""
crypto.py - Handles all encryption and decryption operations
This is the security core of VaultKey
"""
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import argon2


class Crypto:
    """Handles encryption/decryption using Fernet (AES-128 + HMAC)"""
    
    def __init__(self):
        self.key = None
        self.salt_file = "salt.bin"
        
    def create_key(self, master_password: str) -> None:
        """
        Derive an encryption key from the master password.
        
        This uses Argon2id (upgraded from PBKDF2) to:
        1. Provide memory-hard key derivation resistant to GPU/ASIC attacks
        2. Use a salt to prevent rainbow table attacks
        3. Generate a 256-bit key suitable for Fernet
        """
        # Step 1: Get or create a salt
        # Salt ensures same password generates different keys for different vaults
        if os.path.exists(self.salt_file):
            with open(self.salt_file, 'rb') as f:
                salt = f.read()
        else:
            # Generate a new random 32-byte salt (increased from 16)
            salt = os.urandom(32)
            with open(self.salt_file, 'wb') as f:
                f.write(salt)
        
        # Step 2: Use Argon2id for key derivation (memory-hard function)
        try:
            # Use Argon2id with high memory cost for better security
            hasher = argon2.PasswordHasher(
                time_cost=3,      # 3 iterations
                memory_cost=65536,  # 64MB memory
                parallelism=4,    # 4 parallel threads
                hash_len=32,      # 32 bytes output
                salt_len=32       # 32 bytes salt
            )
            
            # Generate key using Argon2id
            key_hash = hasher.hash(master_password, salt=salt)
            # Extract just the hash part (remove the parameters)
            key_bytes = key_hash.split('$')[-1].encode()
            key = base64.urlsafe_b64encode(base64.b64decode(key_bytes + b'=='))
            
        except Exception:
            # Fallback to PBKDF2 for compatibility if Argon2 fails
            print("⚠️  Warning: Falling back to PBKDF2 (install argon2-cffi for better security)")
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,  # 32 bytes = 256 bits
                salt=salt,
                iterations=100000,  # More iterations = slower but more secure
            )
            key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        
        # Step 4: Create Fernet instance with the key
        self.key = Fernet(key)
    
    def encrypt(self, data: str) -> bytes:
        """
        Encrypt a string and return encrypted bytes.
        
        Fernet guarantees:
        - Data is encrypted with AES-128 in CBC mode
        - HMAC authentication to detect tampering
        - Timestamp to support key rotation (optional)
        """
        if not self.key:
            raise ValueError("No encryption key set. Call create_key first.")
        
        # Fernet requires bytes, so encode the string
        return self.key.encrypt(data.encode('utf-8'))
    
    def decrypt(self, encrypted_data: bytes) -> str:
        """
        Decrypt bytes and return the original string.
        
        Will raise an exception if:
        - Wrong password was used (invalid key)
        - Data has been tampered with (HMAC fails)
        - Data is corrupted
        """
        if not self.key:
            raise ValueError("No encryption key set. Call create_key first.")
        
        # Decrypt and decode back to string
        decrypted_bytes = self.key.decrypt(encrypted_data)
        return decrypted_bytes.decode('utf-8')
    
    def verify_password(self, master_password: str, test_data: bytes) -> bool:
        """
        Verify if a master password is correct by trying to decrypt test data.
        Returns True if password is correct, False otherwise.
        """
        try:
            # Create a temporary key with the provided password
            temp_crypto = Crypto()
            temp_crypto.salt_file = self.salt_file  # Use same salt
            temp_crypto.create_key(master_password)
            
            # Try to decrypt
            temp_crypto.decrypt(test_data)
            return True
        except Exception:
            # Any decryption error means wrong password
            return False


# Example usage (for testing)
if __name__ == "__main__":
    # Create crypto instance
    crypto = Crypto()
    
    # Set up encryption with a master password
    crypto.create_key("my-super-secret-password")
    
    # Encrypt some data
    secret_data = "My GitHub password is: ghp_abcd1234"
    encrypted = crypto.encrypt(secret_data)
    print(f"Encrypted: {encrypted[:50]}...")  # Show first 50 chars
    
    # Decrypt it back
    decrypted = crypto.decrypt(encrypted)
    print(f"Decrypted: {decrypted}")
    
    # Verify it worked
    assert secret_data == decrypted
    print("✓ Encryption/decryption working correctly!")