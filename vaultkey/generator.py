"""
generator.py - Secure password generation using cryptographically secure randomness
"""
import secrets
import string
from typing import List


# Characters that are easily confused with each other in many fonts
AMBIGUOUS_CHARACTERS = "0O1lI|`"


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
    
    Passwords at least as long as the number of selected character types
    contain at least one character of each type.
    
    Args:
        length: Length of the password (default: 16)
        use_uppercase: Include uppercase letters A-Z
        use_lowercase: Include lowercase letters a-z
        use_digits: Include digits 0-9
        use_symbols: Include special characters
        exclude_ambiguous: Exclude ambiguous characters (see AMBIGUOUS_CHARACTERS)
    
    Returns:
        A secure random password
    
    Raises:
        ValueError: If length < 1 or no character types selected
    """
    if length < 1:
        raise ValueError("Password length must be at least 1")
    
    # Build one character set per selected type
    character_sets = _character_sets(
        use_uppercase, use_lowercase, use_digits, use_symbols, exclude_ambiguous
    )
    characters = "".join(character_sets)
    
    if not characters:
        raise ValueError("At least one character type must be selected")
    
    # Draw whole passwords until one contains every selected type. Unlike
    # patching characters into a password afterwards, this keeps every valid
    # password equally likely. secrets.choice is cryptographically secure.
    while True:
        password = ''.join(secrets.choice(characters) for _ in range(length))
        if length < len(character_sets) or all(
            any(c in char_set for c in password) for char_set in character_sets
        ):
            return password


def _character_sets(
    use_uppercase: bool,
    use_lowercase: bool,
    use_digits: bool,
    use_symbols: bool,
    exclude_ambiguous: bool
) -> List[str]:
    """Return the character set of each selected type"""
    selected = [
        (use_uppercase, string.ascii_uppercase),
        (use_lowercase, string.ascii_lowercase),
        (use_digits, string.digits),
        (use_symbols, string.punctuation),
    ]
    
    character_sets = []
    for enabled, chars in selected:
        if not enabled:
            continue
        if exclude_ambiguous:
            chars = "".join(c for c in chars if c not in AMBIGUOUS_CHARACTERS)
        character_sets.append(chars)
    return character_sets


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