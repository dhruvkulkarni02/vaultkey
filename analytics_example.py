#!/usr/bin/env python3
"""
Optional usage analytics for VaultKey (with user consent)
Add this to track basic usage patterns while respecting privacy
"""

import os
import json
import requests
import hashlib
from datetime import datetime
from pathlib import Path

class VaultKeyAnalytics:
    def __init__(self):
        self.analytics_file = Path.home() / '.vaultkey' / 'analytics.json'
        self.analytics_enabled = self._check_analytics_consent()
    
    def _check_analytics_consent(self):
        """Check if user has consented to analytics"""
        if self.analytics_file.exists():
            with open(self.analytics_file, 'r') as f:
                data = json.load(f)
                return data.get('consent', False)
        return False
    
    def request_analytics_consent(self):
        """Ask user for analytics consent"""
        print("\n📊 VaultKey Analytics (Optional)")
        print("Help improve VaultKey by sharing anonymous usage statistics.")
        print("This includes:")
        print("  - Command usage frequency (no password data)")
        print("  - Error types and frequencies")
        print("  - Performance metrics")
        print("  - Operating system and Python version")
        print("\nNo passwords or personal data are ever collected.")
        
        consent = input("Enable anonymous analytics? (y/N): ").lower().strip()
        
        # Ensure analytics directory exists
        self.analytics_file.parent.mkdir(exist_ok=True)
        
        analytics_data = {
            'consent': consent == 'y',
            'consent_date': datetime.now().isoformat(),
            'user_id': hashlib.sha256(os.urandom(32)).hexdigest()[:16]  # Anonymous ID
        }
        
        with open(self.analytics_file, 'w') as f:
            json.dump(analytics_data, f, indent=2)
        
        self.analytics_enabled = analytics_data['consent']
        return self.analytics_enabled
    
    def track_command_usage(self, command_name):
        """Track command usage (if consent given)"""
        if not self.analytics_enabled:
            return
        
        try:
            # Send anonymous usage data
            data = {
                'command': command_name,
                'timestamp': datetime.now().isoformat(),
                'version': '1.0.1',
                'platform': os.name
            }
            
            # Replace with your analytics endpoint
            # requests.post('https://your-analytics-api.com/track', json=data, timeout=2)
            print(f"📊 [Analytics] Command used: {command_name}")
            
        except Exception:
            # Silently fail - never interrupt user experience for analytics
            pass

# Usage in your CLI
def track_usage(command_name):
    """Helper function to track command usage"""
    analytics = VaultKeyAnalytics()
    if not analytics.analytics_enabled and not analytics.analytics_file.exists():
        # First time - ask for consent
        analytics.request_analytics_consent()
    
    analytics.track_command_usage(command_name)

# Example integration in cli.py:
# @cli.command()
# def init():
#     track_usage('init')  # Add this line
#     # ... rest of your init command
