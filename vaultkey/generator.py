"""
generator.py - Secure password generation using cryptographically secure randomness
"""
import secrets
import string
from typing import List


def generate_password(
    length: int = 16,
    use_uppercase: bool = True,
    use_lowercase: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    exclude_ambiguous: bool = False
) -> str:
    """
    Generate a cryptographically secure random password.
    
    Args:
        length: Length of the password (default: 16)
        use_uppercase: Include uppercase letters A-Z
        use_lowercase: Include lowercase letters a-z
        use_digits: Include digits 0-9
        use_symbols: Include special characters
        exclude_ambiguous: Exclude ambiguous characters (0, O, l, 1, etc.)
    
    Returns:
        A secure random password
    
    Raises:
        ValueError: If length < 1 or no character types selected
    """
    if length < 1:
        raise ValueError("Password length must be at least 1")
    
    # Build character set based on options
    characters = ""
    
    if use_uppercase:
        characters += string.ascii_uppercase
    if use_lowercase:
        characters += string.ascii_lowercase
    if use_digits:
        characters += string.digits
    if use_symbols:
        characters += string.punctuation
    
    # Remove ambiguous characters if requested
    if exclude_ambiguous:
        ambiguous = "0O1lI|`"
        characters = "".join(c for c in characters if c not in ambiguous)
    
    if not characters:
        raise ValueError("At least one character type must be selected")
    
    # Generate password using secure random
    # secrets.choice is cryptographically secure, unlike random.choice
    password = ''.join(secrets.choice(characters) for _ in range(length))
    
    # Ensure password has at least one of each selected type (for passwords 4+ chars)
    if length >= 4:
        password = _ensure_character_types(
            password, 
            use_uppercase, 
            use_lowercase, 
            use_digits, 
            use_symbols,
            exclude_ambiguous
        )
    
    return password


def _ensure_character_types(
    password: str,
    use_uppercase: bool,
    use_lowercase: bool,
    use_digits: bool,
    use_symbols: bool,
    exclude_ambiguous: bool
) -> str:
    """
    Ensure password contains at least one of each selected character type.
    This prevents passwords like "AAAAAAA" when all types are selected.
    """
    required_chars = []
    
    # Build list of required character sets
    if use_uppercase:
        chars = string.ascii_uppercase
        if exclude_ambiguous:
            chars = chars.replace('O', '').replace('I', '')
        if chars and not any(c in password for c in chars):
            required_chars.append(secrets.choice(chars))
    
    if use_lowercase:
        chars = string.ascii_lowercase
        if exclude_ambiguous:
            chars = chars.replace('o', '').replace('l', '').replace('i', '')
        if chars and not any(c in password for c in chars):
            required_chars.append(secrets.choice(chars))
    
    if use_digits:
        chars = string.digits
        if exclude_ambiguous:
            chars = chars.replace('0', '').replace('1', '')
        if chars and not any(c in password for c in chars):
            required_chars.append(secrets.choice(chars))
    
    if use_symbols:
        chars = string.punctuation
        if exclude_ambiguous:
            chars = chars.replace('|', '').replace('`', '')
        if chars and not any(c in password for c in chars):
            required_chars.append(secrets.choice(chars))
    
    # If we need to add required characters
    if required_chars:
        # Convert password to list for manipulation
        password_list = list(password)
        
        # Replace random positions with required characters
        for char in required_chars:
            pos = secrets.randbelow(len(password_list))
            password_list[pos] = char
        
        password = ''.join(password_list)
    
    return password


def generate_passphrase(
    word_count: int = 4,
    separator: str = "-",
    capitalize: bool = True,
    include_number: bool = True
) -> str:
    """
    Generate a passphrase using random words (like "Correct-Horse-Battery-Staple").
    
    Note: This is a simple implementation. For production use, you'd want
    to use a proper word list like EFF's diceware list.
    """
    # Simple word list for demonstration
    # In production, use a comprehensive word list
    words = [
        "correct", "horse", "battery", "staple", "dragon", "phoenix",
        "thunder", "crystal", "shadow", "flame", "storm", "river",
        "mountain", "forest", "ocean", "desert", "warrior", "wizard",
        "knight", "castle", "bridge", "tower", "garden", "diamond"
    ]
    
    # Select random words
    selected = [secrets.choice(words) for _ in range(word_count)]
    
    # Capitalize if requested
    if capitalize:
        selected = [word.capitalize() for word in selected]
    
    # Add a number if requested
    if include_number:
        selected.append(str(secrets.randbelow(100)))
    
    return separator.join(selected)


# Example usage (for testing)
if __name__ == "__main__":
    print("=== Password Generator Test ===\n")
    
    # Generate different types of passwords
    print("Standard password (16 chars):", generate_password())
    print("Long password (32 chars):", generate_password(32))
    print("Numbers only (PIN):", generate_password(6, False, False, True, False))
    print("No symbols:", generate_password(16, use_symbols=False))
    print("No ambiguous chars:", generate_password(16, exclude_ambiguous=True))
    
    print("\nPassphrase:", generate_passphrase())
    print("Passphrase (6 words):", generate_passphrase(6))
    
    # Test security - generate many passwords and check randomness
    print("\n=== Randomness Test ===")
    passwords = [generate_password(8) for _ in range(5)]
    print("5 random 8-char passwords:")
    for p in passwords:
        print(f"  {p}")
    
    # Verify they're all different (extremely likely with secure random)
    assert len(set(passwords)) == len(passwords)
    print("✓ All passwords are unique!")