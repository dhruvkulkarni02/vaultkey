"""
breach.py - Check passwords against known data breaches using HaveIBeenPwned API
Uses k-anonymity to never send full password hashes to the API
"""
import hashlib
import requests
from typing import Dict, List, Tuple, Optional
import time


class BreachChecker:
    """Check passwords against known breaches using HIBP API"""
    
    def __init__(self):
        self.api_base = "https://api.pwnedpasswords.com/range/"
        self.headers = {
            'User-Agent': 'VaultKey-Password-Manager',
            'Accept': 'application/json'
        }
        self.cache = {}  # Cache API responses
        self.last_request_time = 0
        self.min_request_interval = 1.5  # Rate limiting
    
    def check_password(self, password: str) -> Dict:
        """
        Check if a password has been in any breaches.
        
        Uses k-anonymity: only sends first 5 chars of SHA1 hash to API,
        never revealing the full password or hash.
        
        Returns:
            Dict with breach count, severity, and recommendations
        """
        # Generate SHA1 hash of password
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        
        # Check cache first
        if prefix in self.cache:
            response_text = self.cache[prefix]
        else:
            # Rate limiting
            self._rate_limit()
            
            try:
                # Request all hashes starting with this prefix
                response = requests.get(
                    f"{self.api_base}{prefix}",
                    headers=self.headers,
                    timeout=10
                )
                response.raise_for_status()
                response_text = response.text
                
                # Cache the response
                self.cache[prefix] = response_text
                
            except requests.exceptions.RequestException as e:
                return {
                    'error': True,
                    'message': f"Could not check breach status: {str(e)}",
                    'found': False,
                    'count': 0
                }
        
        # Check if our suffix appears in the response
        breach_count = 0
        for line in response_text.splitlines():
            if ':' in line:
                hash_suffix, count = line.split(':')
                if hash_suffix == suffix:
                    breach_count = int(count)
                    break
        
        # Analyze results
        result = {
            'error': False,
            'found': breach_count > 0,
            'count': breach_count,
            'hash_prefix': prefix,  # For transparency
        }
        
        # Add severity assessment
        if breach_count == 0:
            result['severity'] = 'safe'
            result['message'] = "Good news! This password hasn't been found in any breaches."
            result['recommendation'] = "This password appears to be unique."
        elif breach_count < 10:
            result['severity'] = 'low'
            result['message'] = f"This password has been seen {breach_count} times in breaches."
            result['recommendation'] = "Consider changing this password as a precaution."
        elif breach_count < 100:
            result['severity'] = 'medium'
            result['message'] = f"Warning: This password has been exposed {breach_count} times."
            result['recommendation'] = "You should change this password soon."
        elif breach_count < 1000:
            result['severity'] = 'high'
            result['message'] = f"Alert: This password has been found {breach_count} times in breaches!"
            result['recommendation'] = "Change this password immediately."
        else:
            result['severity'] = 'critical'
            result['message'] = f"CRITICAL: This password has been exposed {breach_count:,} times!"
            result['recommendation'] = "This password is extremely compromised. Change it NOW!"
        
        return result
    
    def check_multiple(self, passwords: Dict[str, str]) -> Dict[str, Dict]:
        """
        Check multiple passwords efficiently.
        
        Args:
            passwords: Dict mapping site names to passwords
            
        Returns:
            Dict mapping site names to breach check results
        """
        results = {}
        total = len(passwords)
        
        for i, (site, password) in enumerate(passwords.items(), 1):
            print(f"Checking {i}/{total}: {site}...", end='\r')
            results[site] = self.check_password(password)
        
        print(" " * 50, end='\r')  # Clear progress line
        return results
    
    def _rate_limit(self):
        """Implement rate limiting to be respectful to the API"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.min_request_interval:
            time.sleep(self.min_request_interval - time_since_last)
        
        self.last_request_time = time.time()
    
    def get_breach_statistics(self, results: Dict[str, Dict]) -> Dict:
        """
        Generate statistics from breach check results.
        
        Args:
            results: Results from check_multiple()
            
        Returns:
            Statistics including counts by severity
        """
        stats = {
            'total_checked': len(results),
            'total_breached': 0,
            'total_exposures': 0,
            'by_severity': {
                'safe': 0,
                'low': 0,
                'medium': 0,
                'high': 0,
                'critical': 0
            },
            'errors': 0
        }
        
        for site, result in results.items():
            if result.get('error'):
                stats['errors'] += 1
            else:
                severity = result.get('severity', 'safe')
                stats['by_severity'][severity] += 1
                
                if result['found']:
                    stats['total_breached'] += 1
                    stats['total_exposures'] += result['count']
        
        return stats
    
    def format_breach_summary(self, stats: Dict) -> List[str]:
        """Format statistics into readable summary lines"""
        lines = []
        
        total = stats['total_checked']
        breached = stats['total_breached']
        safe = stats['by_severity']['safe']
        
        lines.append(f"Checked {total} passwords")
        lines.append(f"✅ {safe} passwords have never been breached")
        
        if breached > 0:
            lines.append(f"⚠️  {breached} passwords found in breaches")
            lines.append(f"📊 Total exposures: {stats['total_exposures']:,}")
            
            # Severity breakdown
            if stats['by_severity']['critical'] > 0:
                lines.append(f"🚨 CRITICAL: {stats['by_severity']['critical']} passwords")
            if stats['by_severity']['high'] > 0:
                lines.append(f"❗ High risk: {stats['by_severity']['high']} passwords")
            if stats['by_severity']['medium'] > 0:
                lines.append(f"⚠️  Medium risk: {stats['by_severity']['medium']} passwords")
            if stats['by_severity']['low'] > 0:
                lines.append(f"📌 Low risk: {stats['by_severity']['low']} passwords")
        
        if stats['errors'] > 0:
            lines.append(f"❌ Failed to check: {stats['errors']} passwords")
        
        return lines


# Example usage and testing
if __name__ == "__main__":
    checker = BreachChecker()
    
    print("=== Password Breach Checker Test ===\n")
    
    # Test some known breached passwords
    test_passwords = {
        "Common Password": "password123",
        "Another Common": "123456",
        "Slightly Better": "P@ssw0rd!",
        "Random Strong": "gX9#mK2$pL5@nQ8!vR7&",
    }
    
    print("Checking passwords against breach database...\n")
    
    for name, password in test_passwords.items():
        result = checker.check_password(password)
        
        print(f"{name}:")
        if result['error']:
            print(f"  ❌ Error: {result['message']}")
        else:
            if result['found']:
                severity_emoji = {
                    'low': '📌',
                    'medium': '⚠️',
                    'high': '❗',
                    'critical': '🚨'
                }.get(result['severity'], '❓')
                
                print(f"  {severity_emoji} {result['message']}")
                print(f"  💡 {result['recommendation']}")
            else:
                print(f"  ✅ {result['message']}")
        print()
    
    # Test batch checking
    print("\n=== Batch Check Test ===")
    results = checker.check_multiple(test_passwords)
    stats = checker.get_breach_statistics(results)
    
    print("\nSummary:")
    for line in checker.format_breach_summary(stats):
        print(f"  {line}")