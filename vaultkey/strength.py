"""
strength.py - Password strength analysis and scoring
"""
import math
import re
from typing import Dict, List, Tuple
import os


class PasswordStrength:
    """Analyze password strength and provide recommendations"""
    
    def __init__(self):
        # Common passwords list (in production, load from file)
        self.common_passwords = {
            'password', '123456', 'password123', 'admin', 'letmein',
            'welcome', 'monkey', '1234567890', 'qwerty', 'abc123',
            'Password1', 'password1', '123456789', 'welcome123',
            '1234', '12345', 'iloveyou', 'admin123', 'root',
            'toor', 'pass', 'test', 'guest', 'master', 'batman',
            'superman', 'password!', 'changeme', 'default'
        }
        
        # Load comprehensive common passwords if available
        self._load_common_passwords()
    
    def _load_common_passwords(self):
        """Load common passwords from file if available"""
        # You can download from: https://github.com/danielmiessler/SecLists
        common_file = os.path.join(os.path.dirname(__file__), 'common_passwords.txt')
        if os.path.exists(common_file):
            with open(common_file, 'r') as f:
                self.common_passwords.update(line.strip() for line in f)
    
    def analyze(self, password: str) -> Dict:
        """
        Analyze password strength and return detailed results
        
        Returns:
            Dictionary with score, strength level, and feedback
        """
        results = {
            'score': 0,  # 0-100
            'strength': 'very_weak',  # very_weak, weak, fair, strong, very_strong
            'entropy': 0,
            'checks': {},
            'feedback': [],
            'suggestions': []
        }
        
        # Basic checks
        checks = {
            'length': len(password),
            'has_lowercase': bool(re.search(r'[a-z]', password)),
            'has_uppercase': bool(re.search(r'[A-Z]', password)),
            'has_digits': bool(re.search(r'\d', password)),
            'has_symbols': bool(re.search(r'[^a-zA-Z0-9]', password)),
            'is_common': password.lower() in self.common_passwords,
            'has_patterns': self._check_patterns(password),
            'has_sequences': self._check_sequences(password),
            'has_repeats': self._check_repeats(password),
            'has_dictionary_words': self._check_dictionary(password),
        }
        
        results['checks'] = checks
        
        # Calculate entropy
        entropy = self._calculate_entropy(password)
        results['entropy'] = round(entropy, 2)
        
        # Score based on various factors
        score = 0
        
        # Length scoring (up to 30 points)
        if checks['length'] >= 20:
            score += 30
        elif checks['length'] >= 16:
            score += 25
        elif checks['length'] >= 12:
            score += 20
        elif checks['length'] >= 8:
            score += 10
        else:
            score += 5
            results['feedback'].append("Password is too short")
        
        # Character variety (up to 20 points)
        variety = sum([
            checks['has_lowercase'],
            checks['has_uppercase'],
            checks['has_digits'],
            checks['has_symbols']
        ])
        score += variety * 5
        
        # Entropy bonus (up to 30 points)
        if entropy >= 60:
            score += 30
        elif entropy >= 40:
            score += 20
        elif entropy >= 30:
            score += 10
        else:
            score += 5
        
        # Penalties
        if checks['is_common']:
            score -= 50
            results['feedback'].append("This is a commonly used password")
            results['suggestions'].append("Choose a unique password")
        
        if checks['has_patterns']:
            score -= 15
            results['feedback'].append("Password contains predictable patterns")
            results['suggestions'].append("Avoid patterns like '123' or 'abc'")
        
        if checks['has_sequences']:
            score -= 10
            results['feedback'].append("Password contains keyboard sequences")
            results['suggestions'].append("Avoid sequences like 'qwerty' or 'asdf'")
        
        if checks['has_repeats']:
            score -= 10
            results['feedback'].append("Password has repeating characters")
            results['suggestions'].append("Avoid repeating characters like 'aaa' or '111'")
        
        # Additional bonuses
        if checks['length'] >= 15 and variety >= 3:
            score += 10  # Long and complex
        
        if not checks['has_dictionary_words'] and checks['length'] >= 12:
            score += 10  # No dictionary words
        
        # Ensure score is within bounds
        score = max(0, min(100, score))
        results['score'] = score
        
        # Determine strength level
        if score >= 80:
            results['strength'] = 'very_strong'
        elif score >= 60:
            results['strength'] = 'strong'
        elif score >= 40:
            results['strength'] = 'fair'
        elif score >= 20:
            results['strength'] = 'weak'
        else:
            results['strength'] = 'very_weak'
        
        # Add suggestions based on missing elements
        if not checks['has_uppercase']:
            results['suggestions'].append("Add uppercase letters")
        if not checks['has_lowercase']:
            results['suggestions'].append("Add lowercase letters")
        if not checks['has_digits']:
            results['suggestions'].append("Add numbers")
        if not checks['has_symbols']:
            results['suggestions'].append("Add special characters")
        if checks['length'] < 12:
            results['suggestions'].append("Make password at least 12 characters long")
        
        return results
    
    def _calculate_entropy(self, password: str) -> float:
        """Calculate password entropy in bits"""
        charset_size = 0
        
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'\d', password):
            charset_size += 10
        if re.search(r'[^a-zA-Z0-9]', password):
            charset_size += 32  # Approximate special characters
        
        if charset_size == 0:
            return 0
        
        # Entropy = length * log2(charset_size)
        return len(password) * math.log2(charset_size)
    
    def _check_patterns(self, password: str) -> bool:
        """Check for common patterns like 123, abc, etc."""
        patterns = [
            r'(012|123|234|345|456|567|678|789|890)',  # Number sequences
            r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)',  # Letter sequences
            r'(.)\1{2,}',  # Repeating characters (3 or more)
        ]
        
        for pattern in patterns:
            if re.search(pattern, password.lower()):
                return True
        return False
    
    def _check_sequences(self, password: str) -> bool:
        """Check for keyboard sequences"""
        sequences = [
            'qwerty', 'asdf', 'zxcv', 'qwer', 'asdfg', 'zxcvb',
            'qaz', 'wsx', 'edc', 'rfv', 'tgb', 'yhn', 'ujm',
            '!@#$', '@#$%', '#$%^', '$%^&', '%^&*', '^&*(', '&*()', '*()_', '()_+',
        ]
        
        password_lower = password.lower()
        for seq in sequences:
            if seq in password_lower or seq[::-1] in password_lower:
                return True
        return False
    
    def _check_repeats(self, password: str) -> bool:
        """Check for repeating characters"""
        return bool(re.search(r'(.)\1{2,}', password))
    
    def _check_dictionary(self, password: str) -> bool:
        """Check if password contains dictionary words"""
        # Simple check - in production, use a proper dictionary
        common_words = {
            'love', 'hate', 'hello', 'world', 'python', 'admin',
            'user', 'pass', 'word', 'test', 'demo', 'sample'
        }
        
        password_lower = password.lower()
        for word in common_words:
            if len(word) >= 4 and word in password_lower:
                return True
        return False
    
    def get_time_to_crack(self, entropy: float) -> str:
        """Estimate time to crack based on entropy"""
        # Assuming 1 trillion guesses per second (modern GPU cluster)
        guesses_per_second = 1e12
        total_combinations = 2 ** entropy
        seconds = total_combinations / (2 * guesses_per_second)  # Average case
        
        if seconds < 1:
            return "instantly"
        elif seconds < 60:
            return f"{seconds:.0f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.0f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.0f} hours"
        elif seconds < 2592000:
            return f"{seconds/86400:.0f} days"
        elif seconds < 31536000:
            return f"{seconds/2592000:.0f} months"
        elif seconds < 315360000:
            return f"{seconds/31536000:.0f} years"
        else:
            return "centuries"
    
    def suggest_improvement(self, password: str) -> str:
        """Suggest an improved version of the password"""
        improved = password
        
        # Add complexity if missing
        if not re.search(r'[A-Z]', improved):
            # Capitalize random positions
            if improved:
                pos = len(improved) // 3
                improved = improved[:pos] + improved[pos].upper() + improved[pos+1:]
        
        if not re.search(r'\d', improved):
            # Add some numbers
            improved += '42'
        
        if not re.search(r'[^a-zA-Z0-9]', improved):
            # Add symbols
            improved += '!#'
        
        # Extend length if too short
        if len(improved) < 12:
            improved += '_Secure'
        
        return improved


def format_strength_bar(score: int, width: int = 20) -> str:
    """Create a visual strength bar"""
    filled = int((score / 100) * width)
    bar = '█' * filled + '░' * (width - filled)
    
    # Color codes (for terminal)
    if score >= 80:
        color = '\033[92m'  # Green
    elif score >= 60:
        color = '\033[93m'  # Yellow
    elif score >= 40:
        color = '\033[33m'  # Orange
    else:
        color = '\033[91m'  # Red
    
    reset = '\033[0m'
    return f"{color}{bar}{reset} {score}%"


# Example usage
if __name__ == "__main__":
    analyzer = PasswordStrength()
    
    test_passwords = [
        "password",
        "Password1",
        "MyP@ssw0rd",
        "correcthorsebatterystaple",
        "gX9#mK2$pL5@nQ8!",
        "12345678",
        "qwertyuiop",
        "MySuper$ecureP@ssw0rd2024!"
    ]
    
    print("=== Password Strength Analyzer ===\n")
    
    for pwd in test_passwords:
        print(f"Password: {pwd}")
        results = analyzer.analyze(pwd)
        
        print(f"Strength: {format_strength_bar(results['score'])}")
        print(f"Level: {results['strength'].replace('_', ' ').title()}")
        print(f"Entropy: {results['entropy']} bits")
        print(f"Time to crack: {analyzer.get_time_to_crack(results['entropy'])}")
        
        if results['feedback']:
            print("Issues:")
            for issue in results['feedback']:
                print(f"  - {issue}")
        
        if results['suggestions']:
            print("Suggestions:")
            for suggestion in results['suggestions']:
                print(f"  - {suggestion}")
        
        print("-" * 50)