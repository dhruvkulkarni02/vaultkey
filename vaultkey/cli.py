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
from .breach import BreachChecker
from .portability import VaultImporter, VaultExporter

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
        passwords_for_breach_check = {}
        
        # Analyze each password
        for site_name in sites:
            creds = pm.get_password(site_name)
            analysis = analyzer.analyze(creds['password'])
            strength_counts[analysis['strength']] += 1
            
            # Store for breach checking
            if check_breaches:
                passwords_for_breach_check[site_name] = creds['password']
            
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
        
        # Breach checking
        if check_breaches:
            click.echo("\n🔐 Checking passwords against breach database...")
            click.echo("(Using HaveIBeenPwned API with k-anonymity)")
            
            checker = BreachChecker()
            breach_results = checker.check_multiple(passwords_for_breach_check)
            breach_stats = checker.get_breach_statistics(breach_results)
            
            click.echo("\n📊 Breach Check Results:")
            for line in checker.format_breach_summary(breach_stats):
                click.echo(f"  {line}")
            
            # Show critical breaches
            critical_breaches = [
                (site, result) for site, result in breach_results.items()
                if not result.get('error') and result.get('severity') in ['critical', 'high']
            ]
            
            if critical_breaches:
                click.echo("\n🚨 Passwords requiring immediate attention:")
                for site, result in critical_breaches[:10]:  # Max 10
                    click.echo(f"  • {site}: {result['message']}")
            
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)
    finally:
        pm.lock()


@cli.command()
@click.option('--password', '-p', help='Password to check (will prompt if not provided)')
@click.option('--check-breach', '-b', is_flag=True, help='Also check if password has been breached')
def check(password, check_breach):
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
    
    # Check breaches if requested
    if check_breach:
        click.echo("\n🔐 Checking breach database...")
        checker = BreachChecker()
        breach_result = checker.check_password(password)
        
        if breach_result.get('error'):
            click.echo(f"❌ {breach_result['message']}")
        else:
            if breach_result['found']:
                severity_emoji = {
                    'low': '📌',
                    'medium': '⚠️',
                    'high': '❗',
                    'critical': '🚨'
                }.get(breach_result['severity'], '❓')
                
                click.echo(f"\n{severity_emoji} Breach Status:")
                click.echo(f"  {breach_result['message']}")
                click.echo(f"  💡 {breach_result['recommendation']}")
            else:
                click.echo(f"\n✅ {breach_result['message']}")


@cli.command()
@click.option('--site', '-s', help='Check specific site (or all if not specified)')
@click.option('--verbose', '-v', is_flag=True, help='Show detailed results')
def breaches(site, verbose):
    """Check if passwords have been exposed in data breaches"""
    pm = get_password_manager()
    checker = BreachChecker()
    
    # Unlock vault
    password = prompt_master_password()
    if not password or not pm.unlock(password):
        click.echo("❌ Invalid master password!", err=True)
        sys.exit(1)
    
    try:
        click.echo("\n🔍 Breach Detection Report")
        click.echo("Using HaveIBeenPwned API (k-anonymity protected)\n")
        
        # Get passwords to check
        passwords_to_check = {}
        if site:
            creds = pm.get_password(site)
            if not creds:
                click.echo(f"❌ No password found for '{site}'", err=True)
                return
            passwords_to_check[site] = creds['password']
        else:
            # Check all passwords
            for site_name in pm.list_sites():
                creds = pm.get_password(site_name)
                passwords_to_check[site_name] = creds['password']
        
        if not passwords_to_check:
            click.echo("No passwords to check.")
            return
        
        # Check breaches
        click.echo(f"Checking {len(passwords_to_check)} password(s)...\n")
        results = checker.check_multiple(passwords_to_check)
        
        # Display results
        breached_sites = []
        safe_sites = []
        
        for site_name, result in results.items():
            if result.get('error'):
                click.echo(f"❌ {site_name}: {result['message']}")
            elif result['found']:
                breached_sites.append((site_name, result))
                
                severity_emoji = {
                    'low': '📌',
                    'medium': '⚠️',
                    'high': '❗',
                    'critical': '🚨'
                }.get(result['severity'], '❓')
                
                click.echo(f"{severity_emoji} {click.style(site_name, bold=True)}")
                click.echo(f"   {result['message']}")
                click.echo(f"   💡 {result['recommendation']}")
                
                if verbose:
                    click.echo(f"   Hash prefix checked: {result['hash_prefix']}...")
                
                click.echo()
            else:
                safe_sites.append(site_name)
        
        # Show safe passwords
        if safe_sites:
            click.echo(f"\n✅ Safe passwords ({len(safe_sites)}):")
            if verbose or len(safe_sites) <= 10:
                for site_name in safe_sites:
                    click.echo(f"   • {site_name}")
            else:
                # Show first 5 and last 5
                for site_name in safe_sites[:5]:
                    click.echo(f"   • {site_name}")
                if len(safe_sites) > 10:
                    click.echo(f"   ... and {len(safe_sites) - 10} more")
                for site_name in safe_sites[-5:]:
                    click.echo(f"   • {site_name}")
        
        # Summary
        stats = checker.get_breach_statistics(results)
        click.echo(f"\n{'='*50}")
        click.echo("📊 Summary:")
        for line in checker.format_breach_summary(stats):
            click.echo(f"   {line}")
        
        # Recommendations
        if breached_sites:
            click.echo("\n💡 Recommendations:")
            click.echo("   1. Change all breached passwords immediately")
            click.echo("   2. Use unique passwords for each account")
            click.echo("   3. Enable two-factor authentication where possible")
            click.echo("   4. Run 'vk generate' to create strong passwords")
            
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)
    finally:
        pm.lock()

# Import/export commands
@cli.command(name = 'import')
@click.option('--file', '-f', required=True, type=click.Path(exists=True), help='File to import')
@click.option('--format', '-F', required=True, 
              type=click.Choice(['csv', 'lastpass', 'bitwarden', '1password', 'chrome', 'keepass', 'vaultkey']),
              help='Import file format')
@click.option('--dry-run', is_flag=True, help='Preview import without saving')
@click.option('--merge', is_flag=True, help='Merge with existing passwords (default: skip duplicates)')
def import_passwords(file, format, dry_run, merge):
    """Import passwords from another password manager"""
    pm = get_password_manager()
    importer = VaultImporter()
    
    click.echo(f"\n📥 Importing passwords from {format} file: {file}")
    
    # Special handling for encrypted vaultkey format
    import_master_password = None
    if format == 'vaultkey':
        import_master_password = getpass.getpass("Enter password for the backup file: ")
    
    try:
        # Import the passwords
        imported_passwords = importer.import_file(file, format, import_master_password)
        
        if not imported_passwords:
            click.echo("❌ No passwords found in import file")
            return
        
        click.echo(f"\n📊 Found {len(imported_passwords)} password(s) to import")
        
        # Show preview
        if dry_run or click.confirm("\nShow preview?"):
            click.echo("\nPasswords to import:")
            for site, data in list(imported_passwords.items())[:10]:
                click.echo(f"  • {site} ({data['username']})")
            if len(imported_passwords) > 10:
                click.echo(f"  ... and {len(imported_passwords) - 10} more")
        
        if dry_run:
            click.echo("\n✅ Dry run complete. No passwords were imported.")
            return
        
        # Unlock vault for actual import
        if not click.confirm("\nProceed with import?"):
            click.echo("❌ Import cancelled")
            return
        
        master_password = prompt_master_password()
        if not master_password or not pm.unlock(master_password):
            click.echo("❌ Invalid master password!", err=True)
            sys.exit(1)
        
        # Process imports
        imported_count = 0
        skipped_count = 0
        updated_count = 0
        
        for site, data in imported_passwords.items():
            existing = pm.get_password(site)
            
            if existing:
                if merge:
                    # Update existing password
                    pm.update_password(
                        site,
                        new_password=data['password'],
                        new_username=data['username'],
                        new_notes=data.get('notes')
                    )
                    updated_count += 1
                    click.echo(f"  ↻ Updated: {site}")
                else:
                    skipped_count += 1
                    if skipped_count <= 5:  # Show first 5 skipped
                        click.echo(f"  ⏭️  Skipped (already exists): {site}")
            else:
                # Add new password
                pm.add_password(
                    site,
                    data['username'],
                    data['password'],
                    data.get('notes', '')
                )
                imported_count += 1
                if imported_count <= 5:  # Show first 5 imported
                    click.echo(f"  ✅ Imported: {site}")
        
        # Summary
        click.echo(f"\n📊 Import Summary:")
        click.echo(f"  ✅ Imported: {imported_count} password(s)")
        if updated_count > 0:
            click.echo(f"  ↻ Updated: {updated_count} password(s)")
        if skipped_count > 0:
            click.echo(f"  ⏭️  Skipped: {skipped_count} password(s)")
        
        click.echo(f"\n✅ Import complete!")
        
    except Exception as e:
        click.echo(f"❌ Import failed: {e}", err=True)
        sys.exit(1)
    finally:
        if pm.is_unlocked():
            pm.lock()


@cli.command()
@click.option('--format', '-F', required=True,
              type=click.Choice(['csv', 'json', 'vaultkey', 'lastpass', 'bitwarden']),
              help='Export format')
@click.option('--output', '-o', type=click.Path(), help='Output file (prints to screen if not specified)')
@click.option('--site', '-s', help='Export specific site only')
def export(format, output, site):
    """Export passwords to various formats"""
    pm = get_password_manager()
    exporter = VaultExporter()
    
    # Unlock vault
    master_password = prompt_master_password()
    if not master_password or not pm.unlock(master_password):
        click.echo("❌ Invalid master password!", err=True)
        sys.exit(1)
    
    try:
        # Get passwords to export
        if site:
            creds = pm.get_password(site)
            if not creds:
                click.echo(f"❌ No password found for '{site}'", err=True)
                return
            passwords_to_export = {site: creds}
        else:
            # Export all passwords
            passwords_to_export = {}
            for site_name in pm.list_sites():
                passwords_to_export[site_name] = pm.get_password(site_name)
        
        if not passwords_to_export:
            click.echo("❌ No passwords to export")
            return
        
        click.echo(f"\n📤 Exporting {len(passwords_to_export)} password(s) to {format} format")
        
        # Handle encrypted export
        export_password = None
        if format == 'vaultkey':
            click.echo("\n🔐 Encrypted export requires a password.")
            click.echo("This can be the same as your master password or different.")
            export_password = prompt_master_password(confirm=True)
            if not export_password:
                return
        
        # Perform export
        result = exporter.export_passwords(
            passwords_to_export,
            format,
            output,
            export_password
        )
        
        if output:
            click.echo(f"✅ {result}")
            
            # Security reminder for unencrypted formats
            if format != 'vaultkey':
                click.echo("\n⚠️  WARNING: This export contains unencrypted passwords!")
                click.echo("   Keep this file secure and delete it after use.")
        else:
            # Output to screen
            click.echo("\n" + "="*60)
            click.echo(result)
            click.echo("="*60)
            
            if format != 'vaultkey':
                click.echo("\n⚠️  WARNING: Passwords shown above are unencrypted!")
        
    except Exception as e:
        click.echo(f"❌ Export failed: {e}", err=True)
        sys.exit(1)
    finally:
        pm.lock()

@cli.command()
def formats():
    """List supported import/export formats"""
    importer = VaultImporter()
    
    click.echo("\n📥 Supported Import Formats:\n")
    for fmt, description in importer.SUPPORTED_FORMATS.items():
        click.echo(f"  • {fmt:12} - {description}")
    
    click.echo("\n📤 Supported Export Formats:\n")
    click.echo("  • csv         - Generic CSV format")
    click.echo("  • json        - JSON format (unencrypted)")
    click.echo("  • vaultkey    - VaultKey encrypted backup")
    click.echo("  • lastpass    - LastPass CSV format")
    click.echo("  • bitwarden   - Bitwarden CSV format")
    
    click.echo("\n💡 Tips:")
    click.echo("  - Use 'vaultkey' format for secure backups")
    click.echo("  - CSV/JSON exports are unencrypted - handle with care!")
    click.echo("  - Import preserves original creation dates where possible")

#Password history management
# Add these commands to your cli.py file after the other commands

@cli.command()
@click.option('--site', '-s', required=True, help='Website or service name')
@click.option('--show-passwords', '-p', is_flag=True, help='Show actual passwords (hidden by default)')
def history(site, show_passwords):
    """View password history for a site"""
    pm = get_password_manager()
    
    # Unlock vault
    password = prompt_master_password()
    if not password or not pm.unlock(password):
        click.echo("❌ Invalid master password!", err=True)
        sys.exit(1)
    
    try:
        # Get current password info
        current = pm.get_password(site)
        if not current:
            click.echo(f"❌ No password found for '{site}'", err=True)
            return
        
        # Get history
        history_entries = pm.get_password_history(site)
        
        click.echo(f"\n📜 Password History for {click.style(site, bold=True)}\n")
        
        # Show current password
        click.echo("Current password:")
        if show_passwords:
            click.echo(f"  🔑 {click.style(current['password'], fg='green')}")
        else:
            click.echo(f"  🔑 {'*' * len(current['password'])}")
        click.echo(f"  📅 Last modified: {current.get('modified', 'Unknown')[:10]}")
        
        if not history_entries:
            click.echo("\nNo password history recorded.")
        else:
            click.echo(f"\nPrevious passwords ({len(history_entries)} total):")
            
            # Show history in reverse order (most recent first)
            for i, hist in enumerate(reversed(history_entries), 1):
                click.echo(f"\n{i}. Previous password:")
                if show_passwords:
                    click.echo(f"   🔑 {hist['password']}")
                else:
                    click.echo(f"   🔑 {'*' * len(hist['password'])}")
                
                changed_date = hist.get('changed', 'Unknown')
                retired_date = hist.get('retired', 'Unknown')
                
                if changed_date != 'Unknown':
                    click.echo(f"   📅 Used from: {changed_date[:10]}")
                if retired_date != 'Unknown':
                    click.echo(f"   📅 Retired on: {retired_date[:10]}")
                
                # Calculate how long ago
                try:
                    from datetime import datetime
                    retired = datetime.fromisoformat(retired_date)
                    days_ago = (datetime.now() - retired).days
                    if days_ago == 0:
                        click.echo(f"   ⏰ Retired today")
                    elif days_ago == 1:
                        click.echo(f"   ⏰ Retired yesterday")
                    else:
                        click.echo(f"   ⏰ Retired {days_ago} days ago")
                except:
                    pass
        
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)
    finally:
        pm.lock()


@cli.command(name='clear-history')
@click.option('--site', '-s', help='Clear history for specific site (or all if not specified)')
@click.option('--force', '-f', is_flag=True, help='Skip confirmation')
def clear_history(site, force):
    """Clear password history"""
    pm = get_password_manager()
    
    # Unlock vault
    password = prompt_master_password()
    if not password or not pm.unlock(password):
        click.echo("❌ Invalid master password!", err=True)
        sys.exit(1)
    
    try:
        if site:
            # Check if site exists
            if not pm.get_password(site):
                click.echo(f"❌ No password found for '{site}'", err=True)
                return
            
            history_count = len(pm.get_password_history(site))
            if history_count == 0:
                click.echo(f"No history to clear for {site}")
                return
            
            click.echo(f"⚠️  About to clear {history_count} historical password(s) for {site}")
        else:
            # Count total history entries
            total_history = 0
            for site_name in pm.list_sites():
                total_history += len(pm.get_password_history(site_name))
            
            if total_history == 0:
                click.echo("No history to clear")
                return
            
            click.echo(f"⚠️  About to clear ALL password history ({total_history} entries)")
        
        if not force and not click.confirm("Are you sure?"):
            click.echo("❌ Cancelled")
            return
        
        # Clear history
        cleared = pm.clear_history(site)
        
        if site:
            click.echo(f"✅ Cleared {cleared} historical password(s) for {site}")
        else:
            click.echo(f"✅ Cleared {cleared} historical password(s) across all sites")
        
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)
    finally:
        pm.lock()


@cli.command(name='history-stats')
@click.option('--include-current', '-c', is_flag=True, help='Include current passwords in analysis')
def history_stats(include_current):
    """Show password history statistics"""
    pm = get_password_manager()
    
    # Unlock vault
    password = prompt_master_password()
    if not password or not pm.unlock(password):
        click.echo("❌ Invalid master password!", err=True)
        sys.exit(1)
    
    try:
        vault_info = pm.get_vault_info()
        
        click.echo("\n📊 Password History Statistics\n")
        
        # Overall stats
        click.echo(f"Total sites: {vault_info['password_count']}")
        click.echo(f"Total history entries: {vault_info['history_entries']}")
        click.echo(f"History tracking: {'Enabled' if vault_info['history_enabled'] else 'Disabled'}")
        
        # Per-site stats
        sites_with_history = 0
        max_history_site = None
        max_history_count = 0
        total_changes = 0
        
        # Analyze each site
        for site in pm.list_sites():
            history = pm.get_password_history(site)
            if history:
                sites_with_history += 1
                total_changes += len(history)
                
                if len(history) > max_history_count:
                    max_history_count = len(history)
                    max_history_site = site
        
        click.echo(f"\nSites with history: {sites_with_history}")
        
        if max_history_site:
            click.echo(f"Most changed password: {max_history_site} ({max_history_count} changes)")
        
        if sites_with_history > 0:
            avg_changes = total_changes / sites_with_history
            click.echo(f"Average changes per site: {avg_changes:.1f}")
        
        # Find recently changed passwords
        click.echo("\n🕐 Recently changed passwords:")
        recent_changes = []
        
        for site in pm.list_sites():
            site_data = pm.get_password(site)
            if site_data.get('modified'):
                try:
                    from datetime import datetime
                    modified = datetime.fromisoformat(site_data['modified'])
                    days_ago = (datetime.now() - modified).days
                    
                    if days_ago <= 30:  # Changed in last 30 days
                        recent_changes.append((site, days_ago))
                except:
                    pass
        
        if recent_changes:
            recent_changes.sort(key=lambda x: x[1])
            for site, days in recent_changes[:5]:  # Show top 5
                if days == 0:
                    click.echo(f"  • {site} - changed today")
                elif days == 1:
                    click.echo(f"  • {site} - changed yesterday")
                else:
                    click.echo(f"  • {site} - changed {days} days ago")
        else:
            click.echo("  No recent changes")
        
        # Check for potential reuse
        if include_current:
            click.echo("\n🔄 Checking for password reuse...")
            passwords_seen = {}
            reuse_found = False
            
            for site in pm.list_sites():
                current = pm.get_password(site)
                pwd = current['password']
                
                if pwd in passwords_seen:
                    if not reuse_found:
                        click.echo("  ⚠️  Same password used on multiple sites:")
                        reuse_found = True
                    click.echo(f"     • {site} and {passwords_seen[pwd]}")
                else:
                    passwords_seen[pwd] = site
                
                # Check history too
                for hist in pm.get_password_history(site):
                    if hist['password'] == current['password']:
                        click.echo(f"  ⚠️  {site} - current password was used before!")
            
            if not reuse_found:
                click.echo("  ✅ No password reuse detected")
        
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)
    finally:
        pm.lock()

if __name__ == '__main__':
    try:
        cli()
    except KeyboardInterrupt:
        click.echo("\n👋 Goodbye!", err=True)
        sys.exit(0)