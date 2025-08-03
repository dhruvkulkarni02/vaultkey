#!/usr/bin/env python3
"""
Entry point for PyInstaller - fixes relative import issues
"""
import sys
import os

# Add the parent directory to Python path so imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Now import and run the CLI
from vaultkey.cli import cli

if __name__ == '__main__':
    cli()
