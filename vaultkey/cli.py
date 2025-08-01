#!/usr/bin/env python3
"""
VaultKey - Secure Password Manager CLI
"""
import click
import getpass
import sys
import os
from typing import Optional

from .manager import PasswordManager
from .generator import generate_password
from .strength import PasswordStrength, format_strength_bar

# Initialize password manager with default vault file
DEFAULT_VAULT = os.path.expanduser("~/.vaultkey/passwords.encrypted")
pm = None


def get_password_manager() -> PasswordManager:
    """Get or create password manager instance"""
    global pm
    if pm is None:
        # Create directory if it doesn't exist
        vault_dir = os.path.dirname(DEFAULT_VAULT)
        if not os.path.exists(vault_dir):
            os.makedirs(vault_dir, mode=0o700)  # Secure directory
        pm = PasswordManager(DEFAULT_VAULT)
    return pm


def prompt_master_password(confirm: bool = False) -> Optional[str]:
    """Prompt for master password with optional confirmation"""
    password = getpass.getpass("Master password: ")
    
    if confirm:
        confirm_password = getpass.getpass("Confirm master password: ")
        if password != confirm_password:
            click.echo("❌ Passwords don't match!", err=True)
            return None
    
    return password


@click.group()
@click.version_option(version="0.1.0", prog_name="VaultKey")
def cli():
    """VaultKey - A secure password manager
    
    Store your passwords locally with strong encryption.
    Your master password is never stored anywhere.
    """
    pass


@cli.command()
def init():
    """Initialize a new password vault"""
    pm = get_password_manager()
    
    # Check if vault already exists
    if pm.storage.exists():
        click.echo("⚠️  Vault already exists!")
        if not click.confirm("Do you want to delete it and create a new one?"):
            return
        
        # Delete existing vault
        pm.storage.delete()
        if os.path.exists("salt.bin"):
            os.remove("salt.bin")
    
    click.echo("🔐 Creating a new password vault...\n")
    click.echo("Choose a strong master password.")
    click.echo("This password protects all your other passwords.")
    click.echo("Make it long and unique!\n")
    
    # Get master password
    password = prompt_master_password(confirm=True)
    if not password:
        return
    
    try:
        pm.create_vault(password)
        click.echo("\n✅ Password vault created successfully!")
        click.echo(f"📁 Location: {DEFAULT_VAULT}")
        click.echo("\nYou can now start adding passwords with 'vaultkey add'")
    except Exception as e:
        click.echo(f"❌ Error creating vault: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--site', '-s', prompt="Site/Service", help='Website or service name')
@click.option('--username', '-u', prompt="Username", help='Username or email')
@click.option('--generate', '-g', is_flag=True, help='Generate a secure password')
@click.option('--length', '-l', default=16, help='Generated password length')
@click.option('--no-symbols', is_flag=True, help='Exclude symbols from generated password')
@click.option('--notes', '-n', help='Optional notes about this account')
def add(site, username, generate, length, no_symbols, notes):
    """Add a new password to the vault"""
    pm = get_password_manager()
    
    # Unlock vault
    password = prompt_master_password()
    if not password or not pm.unlock(password):
        click.echo("❌ Invalid master password!", err=True)
        sys.exit(1)
    
    try:
        # Get or generate password
        if generate:
            password = generate_password(length, use_symbols=not no_symbols)
            click.echo(f"\n🎲 Generated password: {click.style(password, fg='green', bold=True)}")
            if click.confirm("\nSave this password?"):
                pm.add_password(site, username, password, notes)
                click.echo(f"✅ Password for {site} saved!")
            else:
                click.echo("❌ Password not saved.")
        else:
            password = getpass.getpass("Password: ")
            confirm = getpass.getpass("Confirm password: ")
            
            if password != confirm:
                click.echo("❌ Passwords don't match!", err=True)
                return
            
            pm.add_password(site, username, password, notes)
            click.echo(f"✅ Password for {site} saved!")
            
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)
    finally:
        pm.lock()


@cli.command()
@click.option('--site', '-s', required=True, help='Website or service name')
@click.option('--show', '-S', is_flag=True, help='Show password in plain text')
@click.option('--copy', '-c', is_flag=True, help='Copy password to clipboard (requires pyperclip)')
def get(site, show, copy):
    """Retrieve a password from the vault"""
    pm = get_password_manager()
    
    # Unlock vault
    password = prompt_master_password()
    if not password or not pm.unlock(password):
        click.echo("❌ Invalid master password!", err=True)
        sys.exit(1)
    
    try:
        # Search for exact match first
        creds = pm.get_password(site)
        
        # If not found, search for partial matches
        if not creds:
            matches = pm.search_sites(site)
            if matches:
                click.echo(f"No exact match for '{site}'. Did you mean:")
                for match in matches[:5]:  # Show max 5 matches
                    click.echo(f"  • {match}")
                
                if len(matches) == 1:
                    if click.confirm(f"\nRetrieve password for {matches[0]}?"):
                        site = matches[0]
                        creds = pm.get_password(site)
                else:
                    return
            else:
                click.echo(f"❌ No password found for '{site}'", err=True)
                return
        
        # Display credentials
        click.echo(f"\n🔐 Credentials for {click.style(site, bold=True)}")
        click.echo(f"👤 Username: {click.style(creds['username'], fg='cyan')}")
        
        if show:
            click.echo(f"🔑 Password: {click.style(creds['password'], fg='yellow')}")
        else:
            click.echo(f"🔑 Password: {'*' * len(creds['password'])} (use --show to display)")
        
        if creds.get('notes'):
            click.echo(f"📝 Notes: {creds['notes']}")
        
        if creds.get('modified'):
            click.echo(f"📅 Last modified: {creds['modified'][:10]}")
        
        # Copy to clipboard if requested
        if copy:
            try:
                import pyperclip
                pyperclip.copy(creds['password'])
                click.echo("\n✅ Password copied to clipboard!")
            except ImportError:
                click.echo("\n⚠️  Install 'pyperclip' to enable clipboard support", err=True)
                
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)
    finally:
        pm.lock()


@cli.command()
@click.option('--filter', '-f', help='Filter sites by search term')
@click.option('--verbose', '-v', is_flag=True, help='Show more details')
def list(filter, verbose):
    """List all stored passwords"""
    pm = get_password_manager()
    
    # Unlock vault
    password = prompt_master_password()
    if not password or not pm.unlock(password):
        click.echo("❌ Invalid master password!", err=True)
        sys.exit(1)
    
    try:
        # Get sites
        if filter:
            sites = pm.search_sites(filter)
            click.echo(f"\n🔍 Sites matching '{filter}':")
        else:
            sites = pm.list_sites()
            click.echo("\n📋 All stored passwords:")
        
        if not sites:
            click.echo("  (No passwords stored)")
            return
        
        # Display sites
        for site in sites:
            if verbose:
                info = pm.get_password(site)
                click.echo(f"\n  🌐 {click.style(site, bold=True)}")
                click.echo(f"     👤 {info['username']}")
                if info.get('notes'):
                    click.echo(f"     📝 {info['notes']}")
                if info.get('modified'):
                    click.echo(f"     📅 Modified: {info['modified'][:10]}")
            else:
                info = pm.get_password(site)
                click.echo(f"  • {site} ({info['username']})")
        
        # Summary
        click.echo(f"\n📊 Total: {len(sites)} password(s)")
        
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)
    finally:
        pm.lock()


@cli.command()
@click.option('--site', '-s', required=True, help='Website or service name')
def delete(site):
    """Delete a password from the vault"""
    pm = get_password_manager()
    
    # Unlock vault
    password = prompt_master_password()
    if not password or not pm.unlock(password):
        click.echo("❌ Invalid master password!", err=True)
        sys.exit(1)
    
    try:
        # Check if site exists
        if not pm.get_password(site):
            click.echo(f"❌ No password found for '{site}'", err=True)
            return
        
        # Confirm deletion
        click.echo(f"⚠️  About to delete password for: {site}")
        if click.confirm("Are you sure?"):
            if pm.delete_password(site):
                click.echo(f"✅ Password for {site} deleted")
            else:
                click.echo("❌ Failed to delete password", err=True)
        else:
            click.echo("❌ Deletion cancelled")
            
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)
    finally:
        pm.lock()


@cli.command()
@click.option('--site', '-s', required=True, help='Website or service name')
@click.option('--new-password', '-p', help='New password (leave empty to generate)')
@click.option('--new-username', '-u', help='New username')
@click.option('--generate', '-g', is_flag=True, help='Generate a new password')
@click.option('--length', '-l', default=16, help='Generated password length')
def update(site, new_password, new_username, generate, length):
    """Update an existing password"""
    pm = get_password_manager()
    
    # Unlock vault
    password = prompt_master_password()
    if not password or not pm.unlock(password):
        click.echo("❌ Invalid master password!", err=True)
        sys.exit(1)
    
    try:
        # Check if site exists
        current = pm.get_password(site)
        if not current:
            click.echo(f"❌ No password found for '{site}'", err=True)
            return
        
        click.echo(f"\n📝 Updating password for: {site}")
        click.echo(f"Current username: {current['username']}")
        
        # Get new password if needed
        if generate:
            new_password = generate_password(length)
            click.echo(f"\n🎲 Generated password: {click.style(new_password, fg='green', bold=True)}")
            if not click.confirm("Use this password?"):
                return
        elif not new_password and not new_username:
            new_password = getpass.getpass("New password (leave empty to keep current): ")
        
        # Update
        if pm.update_password(site, new_password=new_password or None, 
                            new_username=new_username or None):
            click.echo(f"✅ Password for {site} updated!")
        else:
            click.echo("❌ Failed to update password", err=True)
            
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)
    finally:
        pm.lock()


@cli.command()
@click.option('--length', '-l', default=16, type=int, help='Password length')
@click.option('--count', '-c', default=1, type=int, help='Number of passwords to generate')
@click.option('--no-symbols', is_flag=True, help='Exclude symbols')
@click.option('--no-digits', is_flag=True, help='Exclude numbers')
@click.option('--no-uppercase', is_flag=True, help='Exclude uppercase letters')
@click.option('--no-ambiguous', is_flag=True, help='Exclude ambiguous characters (0,O,l,1)')
def generate(length, count, no_symbols, no_digits, no_uppercase, no_ambiguous):
    """Generate secure passwords without saving them"""
    click.echo(f"\n🎲 Generating {count} password(s) of length {length}:\n")
    
    for i in range(count):
        password = generate_password(
            length=length,
            use_symbols=not no_symbols,
            use_digits=not no_digits,
            use_uppercase=not no_uppercase,
            exclude_ambiguous=no_ambiguous
        )
        
        if count == 1:
            click.echo(click.style(password, fg='green', bold=True))
        else:
            click.echo(f"{i+1}. {click.style(password, fg='green', bold=True)}")
    
    click.echo("\n💡 Tip: Use 'vaultkey add -g' to generate and save a password")


@cli.command()
def info():
    """Show information about the password vault"""
    pm = get_password_manager()
    
    # Check if vault exists
    if not pm.storage.exists():
        click.echo("❌ No vault found. Run 'vaultkey init' to create one.")
        return
    
    # Unlock vault
    password = prompt_master_password()
    if not password or not pm.unlock(password):
        click.echo("❌ Invalid master password!", err=True)
        sys.exit(1)
    
    try:
        info = pm.get_vault_info()
        
        click.echo("\n🔐 VaultKey Password Vault\n")
        click.echo(f"📁 Location: {DEFAULT_VAULT}")
        click.echo(f"📅 Created: {info['created'][:10] if info['created'] != 'Unknown' else 'Unknown'}")
        click.echo(f"🔢 Version: {info['version']}")
        click.echo(f"🔑 Passwords stored: {info['password_count']}")
        
        if info['file_info']:
            file_info = info['file_info']
            size_kb = file_info['size'] / 1024
            click.echo(f"💾 File size: {size_kb:.1f} KB")
            if file_info.get('permissions') != 'N/A':
                click.echo(f"🔒 Permissions: {file_info['permissions']}")
                
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)
    finally:
        pm.lock()


@cli.command()
@click.option('--site', '-s', help='Check specific site (or all if not specified)')
@click.option('--verbose', '-v', is_flag=True, help='Show detailed analysis')
@click.option('--check-breaches', '-b', is_flag=True, help='Check against known breaches')
def audit(site, verbose, check_breaches):
    """Audit password strength and security"""
    pm = get_password_manager()
    analyzer = PasswordStrength()
    
    # Unlock vault
    password = prompt_master_password()
    if not password or not pm.unlock(password):
        click.echo("❌ Invalid master password!", err=True)
        sys.exit(1)
    
    try:
        click.echo("\n🔍 Security Audit Report\n")
        
        # Get sites to audit
        if site:
            sites = [site] if pm.get_password(site) else []
            if not sites:
                click.echo(f"❌ No password found for '{site}'", err=True)
                return
        else:
            sites = pm.list_sites()
        
        if not sites:
            click.echo("No passwords to audit.")
            return
        
        # Statistics
        total_passwords = len(sites)
        strength_counts = {
            'very_strong': 0,
            'strong': 0,
            'fair': 0,
            'weak': 0,
            'very_weak': 0
        }
        issues_found = []
        
        # Analyze each password
        for site_name in sites:
            creds = pm.get_password(site_name)
            analysis = analyzer.analyze(creds['password'])
            strength_counts[analysis['strength']] += 1
            
            # Display results
            click.echo(f"\n{'='*60}")
            click.echo(f"🌐 {click.style(site_name, bold=True)}")
            click.echo(f"👤 {creds['username']}")
            click.echo(f"💪 Strength: {format_strength_bar(analysis['score'])}")
            click.echo(f"📊 Level: {analysis['strength'].replace('_', ' ').title()}")
            
            if verbose:
                click.echo(f"🔢 Entropy: {analysis['entropy']} bits")
                click.echo(f"⏱️  Time to crack: {analyzer.get_time_to_crack(analysis['entropy'])}")
                
                # Show character composition
                checks = analysis['checks']
                click.echo("\nCharacter types:")
                click.echo(f"  • Length: {checks['length']} characters")
                click.echo(f"  • Lowercase: {'✓' if checks['has_lowercase'] else '✗'}")
                click.echo(f"  • Uppercase: {'✓' if checks['has_uppercase'] else '✗'}")
                click.echo(f"  • Numbers: {'✓' if checks['has_digits'] else '✗'}")
                click.echo(f"  • Symbols: {'✓' if checks['has_symbols'] else '✗'}")
            
            # Show issues
            if analysis['feedback']:
                click.echo("\n⚠️  Issues:")
                for issue in analysis['feedback']:
                    click.echo(f"  • {issue}")
                    issues_found.append((site_name, issue))
            
            # Show suggestions
            if analysis['suggestions'] and (verbose or analysis['score'] < 60):
                click.echo("\n💡 Suggestions:")
                for suggestion in analysis['suggestions']:
                    click.echo(f"  • {suggestion}")
        
        # Summary
        click.echo(f"\n{'='*60}")
        click.echo("\n📊 Summary Report\n")
        click.echo(f"Total passwords audited: {total_passwords}")
        click.echo("\nStrength distribution:")
        
        for strength, count in strength_counts.items():
            if count > 0:
                percentage = (count / total_passwords) * 100
                label = strength.replace('_', ' ').title()
                bar_length = int(percentage / 5)
                bar = '█' * bar_length
                
                # Color based on strength
                if strength == 'very_strong':
                    color = 'green'
                elif strength == 'strong':
                    color = 'yellow'
                elif strength == 'fair':
                    color = 'yellow'
                else:
                    color = 'red'
                
                click.echo(f"  {label:12} [{count:2}]: {click.style(bar, fg=color)} {percentage:.0f}%")
        
        # Overall security score
        weights = {
            'very_strong': 100,
            'strong': 80,
            'fair': 60,
            'weak': 40,
            'very_weak': 20
        }
        overall_score = sum(weights[s] * c for s, c in strength_counts.items()) / total_passwords
        
        click.echo(f"\nOverall security score: {format_strength_bar(int(overall_score))}")
        
        # Recommendations
        if strength_counts['weak'] > 0 or strength_counts['very_weak'] > 0:
            click.echo("\n🚨 Critical: You have weak passwords that should be updated immediately!")
            weak_sites = [s for s in sites if analyzer.analyze(pm.get_password(s)['password'])['score'] < 40]
            for ws in weak_sites[:5]:  # Show max 5
                click.echo(f"  • {ws}")
        
        if issues_found and verbose:
            click.echo("\n📋 All issues found:")
            for site_name, issue in issues_found[:10]:  # Show max 10
                click.echo(f"  • {site_name}: {issue}")
        
        # Breach checking placeholder
        if check_breaches:
            click.echo("\n🔐 Breach Checking")
            click.echo("  (Breach checking will be implemented next)")
            
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)
    finally:
        pm.lock()


@cli.command()
@click.option('--password', '-p', help='Password to check (will prompt if not provided)')
def check(password):
    """Check the strength of a password without saving it"""
    analyzer = PasswordStrength()
    
    if not password:
        password = getpass.getpass("Password to check: ")
    
    click.echo("\n🔍 Password Strength Analysis\n")
    
    results = analyzer.analyze(password)
    
    # Don't show the actual password
    masked = password[0] + '*' * (len(password) - 2) + password[-1] if len(password) > 2 else '*' * len(password)
    click.echo(f"Password: {masked}")
    click.echo(f"Length: {len(password)} characters")
    click.echo(f"\nStrength: {format_strength_bar(results['score'])}")
    click.echo(f"Level: {results['strength'].replace('_', ' ').title()}")
    click.echo(f"Entropy: {results['entropy']} bits")
    click.echo(f"Time to crack: {analyzer.get_time_to_crack(results['entropy'])}")
    
    if results['feedback']:
        click.echo("\n⚠️  Issues:")
        for issue in results['feedback']:
            click.echo(f"  • {issue}")
    
    if results['suggestions']:
        click.echo("\n💡 Suggestions:")
        for suggestion in results['suggestions']:
            click.echo(f"  • {suggestion}")
    
    # Suggest improved version
    if results['score'] < 80:
        improved = analyzer.suggest_improvement(password)
        if improved != password:
            click.echo(f"\n🔧 Example improvement: {improved}")


if __name__ == '__main__':
    try:
        cli()
    except KeyboardInterrupt:
        click.echo("\n👋 Goodbye!", err=True)
        sys.exit(0)