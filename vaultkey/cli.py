#!/usr/bin/env python3
"""
VaultKey - Secure Password Manager CLI
"""
import click
import getpass
import sys
import os
from typing import Optional
from tabulate import tabulate
from datetime import datetime
import threading
import time

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


def clear_clipboard_after_delay(seconds):
    """Clear clipboard after specified seconds"""
    def clear():
        time.sleep(seconds)
        try:
            import pyperclip
            pyperclip.copy("")
        except:
            pass
    
    thread = threading.Thread(target=clear, daemon=True)
    thread.start()


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
@click.option('--copy', '-c', is_flag=True, help='Copy password to clipboard')
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
                clear_clipboard_after_delay(30)
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
@click.option('--sort', '-s', type=click.Choice(['site', 'username', 'modified', 'strength']), 
              default='site', help='Sort by column')
@click.option('--weak-only', '-w', is_flag=True, help='Show only weak passwords')
def list(filter, verbose, sort, weak_only):
    """List all stored passwords in a table"""
    pm = get_password_manager()
    analyzer = PasswordStrength() if (weak_only or sort == 'strength') else None
    
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
        
        # Prepare data for table
        table_data = []
        
        for site in sites:
            info = pm.get_password(site)
            
            # Calculate password strength if needed
            strength_score = None
            if analyzer:
                analysis = analyzer.analyze(info['password'])
                strength_score = analysis['score']
                
                # Skip if filtering for weak only
                if weak_only and strength_score >= 40:
                    continue
            
            # Calculate age
            try:
                modified = datetime.fromisoformat(info.get('modified', ''))
                age_days = (datetime.now() - modified).days
                if age_days == 0:
                    age_str = "Today"
                elif age_days == 1:
                    age_str = "Yesterday"
                elif age_days < 30:
                    age_str = f"{age_days}d ago"
                elif age_days < 365:
                    age_str = f"{age_days // 30}mo ago"
                else:
                    age_str = f"{age_days // 365}y ago"
                sort_age = age_days
            except:
                age_str = "Unknown"
                sort_age = 9999
            
            # Prepare row data
            row_data = {
                'site': site,
                'username': info['username'],
                'modified': age_str,
                'sort_age': sort_age,
                'password_length': len(info['password'])
            }
            
            if analyzer:
                row_data['strength'] = strength_score
            
            if verbose:
                row_data['notes'] = info.get('notes', '')[:40] + '...' if len(info.get('notes', '')) > 40 else info.get('notes', '')
                row_data['created'] = info.get('created', '')[:10] if info.get('created') else 'Unknown'
            
            table_data.append(row_data)
        
        if not table_data:
            if weak_only:
                click.echo("  ✅ No weak passwords found!")
            else:
                click.echo("  (No passwords match criteria)")
            return
        
        # Sort data
        if sort == 'site':
            table_data.sort(key=lambda x: x['site'].lower())
        elif sort == 'username':
            table_data.sort(key=lambda x: x['username'].lower())
        elif sort == 'modified':
            table_data.sort(key=lambda x: x['sort_age'])
        elif sort == 'strength' and analyzer:
            table_data.sort(key=lambda x: x.get('strength', 0))
        
        # Prepare display table
        headers = ['Site', 'Username', 'Length', 'Modified']
        display_data = []
        
        if analyzer:
            headers.insert(3, 'Strength')
        
        if verbose:
            headers.extend(['Created', 'Notes'])
        
        for row in table_data:
            display_row = [
                row['site'],
                row['username'],
                str(row['password_length']),
                row['modified']
            ]
            
            if analyzer:
                # Create strength bar
                score = row.get('strength', 0)
                if score >= 80:
                    strength_bar = click.style('████████', fg='green')
                elif score >= 60:
                    strength_bar = click.style('██████', fg='yellow')
                elif score >= 40:
                    strength_bar = click.style('████', fg='yellow')
                else:
                    strength_bar = click.style('██', fg='red')
                display_row.insert(3, strength_bar)
            
            if verbose:
                display_row.extend([
                    row.get('created', 'Unknown'),
                    row.get('notes', '')
                ])
            
            display_data.append(display_row)
        
        # Display table
        click.echo()
        click.echo(tabulate(display_data, headers=headers, tablefmt='simple_grid'))
        
        # Summary
        click.echo(f"\n📊 Total: {len(table_data)} password(s)")
        
        if analyzer and not weak_only:
            weak_count = sum(1 for r in table_data if r.get('strength', 100) < 40)
            if weak_count > 0:
                click.echo(f"⚠️  {weak_count} weak password(s) - run 'vk list --weak-only' to see them")
        
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)
    finally:
        pm.lock()


@cli.command()
@click.argument('site')
@click.option('--force', '-f', is_flag=True, help='Skip confirmation prompt')
def delete(site, force):
    """Delete a password from the vault
    
    Example:
        vk delete github
        vk delete github -f    # Skip confirmation
    """
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
        if force or click.confirm("Are you sure?"):
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
@click.argument('query')
@click.option('--type', '-t', type=click.Choice(['all', 'weak', 'strong', 'old', 'recent']), 
              default='all', help='Filter by type')
@click.option('--show-passwords', '-p', is_flag=True, help='Show passwords in results')
def search(query, type, show_passwords):
    """Search passwords by site, username, or notes"""
    pm = get_password_manager()
    analyzer = PasswordStrength()
    
    # Unlock vault
    password = prompt_master_password()
    if not password or not pm.unlock(password):
        click.echo("❌ Invalid master password!", err=True)
        sys.exit(1)
    
    try:
        query_lower = query.lower()
        results = []
        
        # Search through all passwords
        for site in pm.list_sites():
            data = pm.get_password(site)
            
            # Check if query matches site, username, or notes
            if (query_lower in site.lower() or 
                query_lower in data.get('username', '').lower() or 
                query_lower in data.get('notes', '').lower()):
                
                # Get password strength
                analysis = analyzer.analyze(data['password'])
                strength_score = analysis['score']
                
                # Calculate age
                try:
                    modified = datetime.fromisoformat(data.get('modified', ''))
                    age_days = (datetime.now() - modified).days
                    if age_days == 0:
                        age_str = "Today"
                    elif age_days == 1:
                        age_str = "Yesterday"
                    elif age_days < 30:
                        age_str = f"{age_days} days ago"
                    elif age_days < 365:
                        age_str = f"{age_days // 30} months ago"
                    else:
                        age_str = f"{age_days // 365} years ago"
                except:
                    age_str = "Unknown"
                    age_days = 9999
                
                # Apply type filter
                if type == 'weak' and strength_score >= 60:
                    continue
                elif type == 'strong' and strength_score < 60:
                    continue
                elif type == 'old' and age_days < 90:
                    continue
                elif type == 'recent' and age_days > 30:
                    continue
                
                # Add to results
                result = {
                    'site': site,
                    'username': data.get('username', ''),
                    'password': data['password'] if show_passwords else '•' * len(data['password']),
                    'strength': strength_score,
                    'modified': age_str,
                    'notes': data.get('notes', '')[:30] + '...' if len(data.get('notes', '')) > 30 else data.get('notes', '')
                }
                results.append(result)
        
        if not results:
            click.echo(f"No passwords found matching '{query}'")
            return
        
        # Sort by relevance (exact matches first)
        results.sort(key=lambda x: (
            query_lower not in x['site'].lower(),  # Exact site matches first
            x['site'].lower()
        ))
        
        click.echo(f"\n🔍 Found {len(results)} password(s) matching '{query}'")
        
        if type != 'all':
            click.echo(f"   Filtered by: {type}")
        
        click.echo()
        
        # Prepare table data
        headers = ['Site', 'Username', 'Strength', 'Modified']
        if show_passwords:
            headers.insert(2, 'Password')
        if any(r['notes'] for r in results):
            headers.append('Notes')
        
        table_data = []
        for r in results:
            # Create strength bar
            score = r['strength']
            if score >= 80:
                strength_bar = click.style('████████', fg='green')
            elif score >= 60:
                strength_bar = click.style('██████', fg='yellow')
            elif score >= 40:
                strength_bar = click.style('████', fg='yellow')
            else:
                strength_bar = click.style('██', fg='red')
            
            row = [r['site'], r['username'], strength_bar, r['modified']]
            if show_passwords:
                row.insert(2, r['password'])
            if any(res['notes'] for res in results):
                row.append(r['notes'])
            
            table_data.append(row)
        
        # Display results in a table
        click.echo(tabulate(table_data, headers=headers, tablefmt='simple_grid'))
        
        # Show summary
        if len(results) > 1:
            weak_count = sum(1 for r in results if r['strength'] < 40)
            if weak_count > 0:
                click.echo(f"\n⚠️  {weak_count} weak password(s) found - consider updating them")
        
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)
    finally:
        pm.lock()


@cli.command()
@click.argument('site')
@click.option('--timeout', '-t', default=30, help='Clear clipboard after N seconds (0 = don\'t clear)')
def cp(site, timeout):
    """Copy password to clipboard without displaying it"""
    pm = get_password_manager()
    
    # Unlock vault
    password = prompt_master_password()
    if not password or not pm.unlock(password):
        click.echo("❌ Invalid master password!", err=True)
        sys.exit(1)
    
    try:
        # Try exact match first
        creds = pm.get_password(site)
        
        # If not found, try fuzzy search
        if not creds:
            matches = pm.search_sites(site)
            if not matches:
                click.echo(f"❌ No password found for '{site}'", err=True)
                return
            
            if len(matches) == 1:
                site = matches[0]
                creds = pm.get_password(site)
                click.echo(f"Found: {site}")
            else:
                # Multiple matches - show them
                click.echo(f"Multiple matches for '{site}':")
                for i, match in enumerate(matches[:10], 1):
                    click.echo(f"  {i}. {match}")
                
                if len(matches) > 10:
                    click.echo(f"  ... and {len(matches) - 10} more")
                
                # Ask user to be more specific
                click.echo("\nPlease use the exact site name")
                return
        
        # Copy to clipboard
        try:
            import pyperclip
            pyperclip.copy(creds['password'])
            click.echo(f"✅ Password for {click.style(site, bold=True)} copied to clipboard")
            
            # Auto-clear clipboard after timeout
            if timeout > 0:
                click.echo(f"⏱️  Clipboard will be cleared in {timeout} seconds...")
                clear_clipboard_after_delay(timeout)
        except ImportError:
            click.echo("⚠️  Install 'pyperclip' to enable clipboard support", err=True)
            click.echo("   Run: pip install pyperclip")
            
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
def interactive():
    """Launch interactive mode with a professional interface"""
    pm = get_password_manager()
    
    # Check if vault exists
    if not pm.storage.exists():
        show_welcome_screen()
        if click.confirm("\n    Create a new password vault?", default=True):
            if not create_new_vault():
                return
        else:
            return
    
    # Professional splash screen
    show_splash_screen()
    
    # Unlock vault with styled prompt
    click.echo("\n    🔐 Enter Master Password")
    click.echo("    " + "─" * 30)
    password = getpass.getpass("    Password: ")
    
    if not password or not pm.unlock(password):
        click.echo("\n    ❌ Authentication failed")
        time.sleep(1)
        return
    
    click.echo("\n    ✅ Vault unlocked successfully")
    time.sleep(0.5)
    
    try:
        # Main application loop
        main_menu_loop(pm)
    
    except KeyboardInterrupt:
        show_exit_screen()
    except Exception as e:
        click.echo(f"\n    ❌ Unexpected error: {e}", err=True)
        click.echo("    Please report this issue if it persists.")
        click.pause()
    finally:
        pm.lock()


def show_welcome_screen():
    """Display professional welcome screen for new users"""
    click.clear()
    click.echo("\n" * 3)
    click.echo("    ╔═══════════════════════════════════════════════════════╗")
    click.echo("    ║                                                       ║")
    click.echo("    ║              Welcome to VaultKey                      ║")
    click.echo("    ║         Professional Password Manager                 ║")
    click.echo("    ║                                                       ║")
    click.echo("    ╚═══════════════════════════════════════════════════════╝")
    click.echo()
    click.echo("    🔒 Military-grade encryption (AES-256)")
    click.echo("    📱 Local storage - your data never leaves your device")
    click.echo("    🚀 Fast, secure, and easy to use")
    click.echo()
    click.echo("    No vault detected. Let's set up your secure vault!")


def show_splash_screen():
    """Display professional splash screen"""
    click.clear()
    click.echo("\n" * 3)
    click.echo(click.style("    ██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗██╗  ██╗███████╗██╗   ██╗", fg='cyan'))
    click.echo(click.style("    ██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝██║ ██╔╝██╔════╝╚██╗ ██╔╝", fg='cyan'))
    click.echo(click.style("    ██║   ██║███████║██║   ██║██║     ██║   █████╔╝ █████╗   ╚████╔╝ ", fg='cyan'))
    click.echo(click.style("    ╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║   ██╔═██╗ ██╔══╝    ╚██╔╝  ", fg='cyan'))
    click.echo(click.style("     ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║   ██║  ██╗███████╗   ██║   ", fg='cyan'))
    click.echo(click.style("      ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝   ╚═╝  ╚═╝╚══════╝   ╚═╝   ", fg='cyan'))
    click.echo()
    click.echo(click.style("                        Professional Password Manager", fg='white', dim=True))
    click.echo(click.style("                              Version 0.1.0", fg='white', dim=True))
    time.sleep(1)


def show_exit_screen():
    """Display professional exit screen"""
    click.clear()
    click.echo("\n" * 5)
    click.echo("    ╔═══════════════════════════════════════════════════════╗")
    click.echo("    ║                                                       ║")
    click.echo("    ║            Thank you for using VaultKey               ║")
    click.echo("    ║         Your passwords are safely encrypted           ║")
    click.echo("    ║                                                       ║")
    click.echo("    ╚═══════════════════════════════════════════════════════╝")
    click.echo()
    click.echo("    🔒 Vault locked")
    click.echo("    👋 Goodbye!")
    click.echo("\n" * 2)
    time.sleep(0.5)


def main_menu_loop(pm):
    """Main application loop with professional menu"""
    while True:
        sites = pm.list_sites()
        analyzer = PasswordStrength()
        
        # Calculate statistics
        weak_count = 0
        for site in sites[:20]:  # Quick sample for performance
            data = pm.get_password(site)
            if analyzer.analyze(data['password'])['score'] < 40:
                weak_count += 1
        
        # Display main menu
        click.clear()
        display_header(f"Main Menu │ {len(sites)} passwords")
        
        # Quick stats bar
        if sites:
            security_status = "🟢 Secure" if weak_count == 0 else "🟡 Needs Attention"
            click.echo(f"    Security Status: {security_status}")
            click.echo("    " + "─" * 55)
        
        # Menu options with better organization
        menu_items = [
            ("1", "🔍", "Search Passwords", "Find passwords quickly"),
            ("2", "➕", "Add Password", "Store a new password"),
            ("3", "📋", "Browse Vault", "View all passwords"),
            ("4", "🔐", "Quick Copy", "Copy password to clipboard"),
            ("", "", "", ""),  # Separator
            ("5", "🛡️", "Security Audit", "Check password strength"),
            ("6", "🎲", "Generate Password", "Create secure passwords"),
            ("", "", "", ""),  # Separator
            ("7", "⚙️", "Settings", "Configure VaultKey"),
            ("0", "🚪", "Exit", "Lock vault and exit"),
        ]
        
        for key, icon, title, desc in menu_items:
            if key:
                click.echo(f"    {key}. {icon}  {title:<20} {click.style(desc, fg='bright_black')}")
            else:
                click.echo()
        
        click.echo("\n    " + "─" * 55)
        
        # Professional prompt
        choice = click.prompt("    Select option", type=str, default="", show_default=False)
        
        # Handle menu choices
        if choice == "0" or choice.lower() == "q":
            if confirm_action("Exit VaultKey?"):
                show_exit_screen()
                break
        
        elif choice == "1":
            search_passwords_professional(pm)
        
        elif choice == "2":
            add_password_professional(pm)
        
        elif choice == "3":
            browse_vault_professional(pm)
        
        elif choice == "4":
            quick_copy_professional(pm)
        
        elif choice == "5":
            security_audit_professional(pm)
        
        elif choice == "6":
            password_generator_professional()
        
        elif choice == "7":
            settings_professional(pm)
        
        else:
            show_error("Invalid option. Please try again.")


def display_header(title, width=60):
    """Display a professional header"""
    click.echo("\n    ┌" + "─" * (width - 2) + "┐")
    click.echo(f"    │ {title:<{width - 4}} │")
    click.echo("    └" + "─" * (width - 2) + "┘")
    click.echo()


def confirm_action(message, default=False):
    """Professional confirmation prompt"""
    click.echo()
    result = click.confirm(f"    ⚠️  {message}", default=default)
    return result


def show_error(message):
    """Display error message professionally"""
    click.echo()
    click.echo(f"    {click.style('⚠️  ' + message, fg='yellow')}")
    time.sleep(1.5)


def show_success(message):
    """Display success message professionally"""
    click.echo()
    click.echo(f"    {click.style('✅ ' + message, fg='green')}")
    time.sleep(1)


def search_passwords_professional(pm):
    """Professional search interface"""
    click.clear()
    display_header("Search Passwords")
    
    click.echo("    Enter search term (site, username, or notes):")
    click.echo("    " + "─" * 40)
    query = click.prompt("    🔍", default="", show_default=False)
    
    if not query:
        return
    
    click.echo("\n    Searching...")
    results = []
    
    for site in pm.list_sites():
        data = pm.get_password(site)
        if (query.lower() in site.lower() or 
            query.lower() in data.get('username', '').lower() or 
            query.lower() in data.get('notes', '').lower()):
            results.append((site, data))
    
    click.clear()
    display_header(f"Search Results │ '{query}'")
    
    if not results:
        click.echo(f"    No matches found for '{query}'")
        click.echo("\n    💡 Try a different search term")
        click.pause("\n    Press any key to continue...")
        return
    
    click.echo(f"    Found {len(results)} match{'es' if len(results) > 1 else ''}:\n")
    
    # Display results
    for i, (site, data) in enumerate(results[:15], 1):
        click.echo(f"    {i:2}. {site}")
        click.echo(f"        👤 {data['username']}")
        click.echo()
    
    if len(results) > 15:
        click.echo(f"    ... and {len(results) - 15} more results")
    
    # Action menu
    click.echo("\n    Actions: (V)iew  (C)opy  (B)ack")
    action = click.prompt("\n    Action", type=str, default="b").lower()
    
    if action in ["v", "c"] and results:
        if len(results) == 1:
            selected_site = results[0][0]
        else:
            num = click.prompt("    Select number", type=int, default=1)
            if 1 <= num <= min(len(results), 15):
                selected_site = results[num-1][0]
            else:
                show_error("Invalid selection")
                return
        
        if action == "v":
            view_password_professional(pm, selected_site)
        elif action == "c":
            copy_password_professional(pm, selected_site)


def add_password_professional(pm):
    """Professional add password interface"""
    click.clear()
    display_header("Add New Password")
    
    click.echo("    Step 1: Basic Information")
    click.echo("    " + "─" * 40)
    
    site = click.prompt("    🌐 Site/Service")
    username = click.prompt("    👤 Username/Email")
    
    if pm.get_password(site):
        if not confirm_action(f"Password for '{site}' already exists. Replace it?"):
            return
    
    click.echo("\n    Step 2: Password Creation")
    click.echo("    " + "─" * 40)
    click.echo("    1. Generate secure password (recommended)")
    click.echo("    2. Enter password manually")
    
    pwd_choice = click.prompt("\n    Choice", type=str, default="1")
    
    if pwd_choice == "1":
        length = click.prompt("    Length", type=int, default=16)
        password = generate_password(length)
        
        click.echo(f"\n    Generated Password:")
        click.echo(f"    {click.style(password, fg='green', bold=True)}")
        
        if not confirm_action("Use this password?", default=True):
            return
    else:
        password = getpass.getpass("\n    Enter password: ")
        confirm = getpass.getpass("    Confirm password: ")
        
        if password != confirm:
            show_error("Passwords don't match")
            return
    
    notes = ""
    if click.confirm("\n    Add notes?", default=False):
        notes = click.prompt("    📝 Notes", default="")
    
    click.echo("\n    Saving password...")
    try:
        pm.add_password(site, username, password, notes)
        show_success(f"Password saved for {site}")
        
        if confirm_action("Copy password to clipboard?", default=True):
            try:
                import pyperclip
                pyperclip.copy(password)
                click.echo("    📋 Password copied to clipboard")
                clear_clipboard_after_delay(30)
            except ImportError:
                click.echo("    ⚠️  Clipboard not available")
    
    except Exception as e:
        show_error(f"Failed to save: {e}")
    
    click.pause("\n    Press any key to continue...")


def browse_vault_professional(pm):
    """Professional vault browser"""
    sites = pm.list_sites()
    if not sites:
        click.clear()
        display_header("Browse Vault")
        click.echo("    Your vault is empty!")
        click.echo("\n    💡 Press '2' in the main menu to add your first password")
        click.pause("\n    Press any key to continue...")
        return
    
    page_size = 10
    current_page = 0
    
    while True:
        total_pages = max(1, (len(sites) - 1) // page_size + 1)
        current_page = min(current_page, total_pages - 1)
        
        start_idx = current_page * page_size
        end_idx = min(start_idx + page_size, len(sites))
        page_sites = sites[start_idx:end_idx]
        
        click.clear()
        display_header(f"Browse Vault │ Page {current_page + 1}/{total_pages}")
        
        for i, site in enumerate(page_sites, start_idx + 1):
            data = pm.get_password(site)
            click.echo(f"    {i:3}. {site}")
            click.echo(f"         👤 {data['username']}")
            click.echo()
        
        click.echo("    " + "─" * 50)
        
        nav_options = []
        if current_page > 0:
            nav_options.append("(P)rev")
        if current_page < total_pages - 1:
            nav_options.append("(N)ext")
        nav_options.extend(["(V)iew", "(B)ack"])
        
        click.echo("    " + "  ".join(nav_options))
        
        action = click.prompt("\n    Action", type=str, default="b").lower()
        
        if action == "b":
            break
        elif action == "n" and current_page < total_pages - 1:
            current_page += 1
        elif action == "p" and current_page > 0:
            current_page -= 1
        elif action == "v" and page_sites:
            try:
                num = click.prompt("    View number", type=int)
                if start_idx < num <= start_idx + len(page_sites):
                    view_password_professional(pm, sites[num-1])
            except:
                pass


def view_password_professional(pm, site):
    """Professional password viewer"""
    data = pm.get_password(site)
    if not data:
        show_error(f"Password not found for '{site}'")
        return
    
    click.clear()
    display_header(f"Password Details │ {site}")
    
    click.echo(f"    Username:    {data['username']}")
    click.echo("    " + "─" * 40)
    
    if click.confirm("\n    Show password?", default=False):
        click.echo(f"    Password:    {click.style(data['password'], fg='yellow', bold=True)}")
    else:
        click.echo(f"    Password:    {'●' * len(data['password'])}")
    
    if data.get('notes'):
        click.echo(f"\n    Notes:       {data['notes']}")
    
    click.echo(f"\n    Created:     {data.get('created', 'Unknown')[:10]}")
    click.echo(f"    Modified:    {data.get('modified', 'Unknown')[:10]}")
    
    click.echo("\n    Actions: (C)opy  (B)ack")
    action = click.prompt("\n    Action", type=str, default="b").lower()
    
    if action == "c":
        copy_password_professional(pm, site)


def copy_password_professional(pm, site):
    """Copy password with professional feedback"""
    try:
        import pyperclip
        data = pm.get_password(site)
        pyperclip.copy(data['password'])
        
        click.echo()
        click.echo("    ┌─────────────────────────────────────────┐")
        click.echo("    │         ✅ Password Copied!             │")
        click.echo("    │                                         │")
        click.echo("    │    📋 Clipboard will clear in 30s      │")
        click.echo("    └─────────────────────────────────────────┘")
        
        clear_clipboard_after_delay(30)
        time.sleep(2)
        
    except ImportError:
        show_error("Clipboard not available. Install 'pyperclip'")
        time.sleep(2)


def quick_copy_professional(pm):
    """Quick copy with search"""
    click.clear()
    display_header("Quick Copy")
    
    site_query = click.prompt("    🔍 Site name", default="")
    
    if not site_query:
        return
    
    matches = []
    for site in pm.list_sites():
        if site_query.lower() in site.lower():
            matches.append(site)
    
    if not matches:
        show_error(f"No matches for '{site_query}'")
        return
    
    if len(matches) == 1:
        selected = matches[0]
    else:
        click.echo(f"\n    Found {len(matches)} matches:")
        for i, site in enumerate(matches[:10], 1):
            data = pm.get_password(site)
            click.echo(f"    {i}. {site} ({data['username']})")
        
        try:
            choice = click.prompt("\n    Select number", type=int)
            if 1 <= choice <= len(matches):
                selected = matches[choice - 1]
            else:
                return
        except:
            return
    
    copy_password_professional(pm, selected)


def security_audit_professional(pm):
    """Professional security audit"""
    click.clear()
    display_header("Security Audit")
    
    sites = pm.list_sites()
    if not sites:
        click.echo("    No passwords to audit")
        click.pause("\n    Press any key to continue...")
        return
    
    click.echo(f"    Analyzing {len(sites)} passwords...\n")
    
    analyzer = PasswordStrength()
    weak_passwords = []
    
    with click.progressbar(sites, label='    Scanning', 
                          bar_template='    %(label)s  [%(bar)s]  %(info)s',
                          fill_char='█', empty_char='░') as bar:
        for site in bar:
            data = pm.get_password(site)
            analysis = analyzer.analyze(data['password'])
            if analysis['score'] < 40:
                weak_passwords.append((site, analysis['score']))
    
    click.clear()
    display_header("Security Audit Results")
    
    if weak_passwords:
        click.echo(f"    ⚠️  {len(weak_passwords)} weak password(s) found:\n")
        for site, score in weak_passwords[:5]:
            click.echo(f"    • {site}")
        if len(weak_passwords) > 5:
            click.echo(f"    ... and {len(weak_passwords) - 5} more")
    else:
        click.echo("    ✅ All passwords are strong!")
    
    click.echo("\n    💡 Recommendations:")
    click.echo("    • Use the password generator for strong passwords")
    click.echo("    • Update passwords regularly")
    click.echo("    • Enable two-factor authentication")
    
    click.pause("\n    Press any key to continue...")


def password_generator_professional():
    """Professional password generator"""
    click.clear()
    display_header("Password Generator")
    
    settings = {
        'length': 16,
        'symbols': True,
        'digits': True,
        'uppercase': True,
        'lowercase': True
    }
    
    while True:
        click.echo("    Current Settings:")
        click.echo("    " + "─" * 40)
        click.echo(f"    Length:     {settings['length']} characters")
        click.echo(f"    Symbols:    {'✓' if settings['symbols'] else '✗'}")
        click.echo(f"    Numbers:    {'✓' if settings['digits'] else '✗'}")
        click.echo(f"    Uppercase:  {'✓' if settings['uppercase'] else '✗'}")
        
        password = generate_password(
            length=settings['length'],
            use_symbols=settings['symbols'],
            use_digits=settings['digits'],
            use_uppercase=settings['uppercase']
        )
        
        click.echo("\n    Generated Password:")
        click.echo("    " + "─" * 40)
        click.echo(f"    {click.style(password, fg='green', bold=True)}")
        
        click.echo("\n    Actions: (C)opy  (R)egenerate  (S)ettings  (B)ack")
        action = click.prompt("\n    Action", type=str, default="r").lower()
        
        if action == "b":
            break
        elif action == "c":
            try:
                import pyperclip
                pyperclip.copy(password)
                show_success("Password copied to clipboard")
            except ImportError:
                show_error("Clipboard not available")
        elif action == "s":
            click.echo("\n    Modify Settings:")
            settings['length'] = click.prompt("    Length", type=int, default=settings['length'])
            settings['symbols'] = click.confirm("    Include symbols", default=settings['symbols'])
            settings['digits'] = click.confirm("    Include numbers", default=settings['digits'])
            settings['uppercase'] = click.confirm("    Include uppercase", default=settings['uppercase'])
        
        click.clear()
        display_header("Password Generator")


def settings_professional(pm):
    """Professional settings interface"""
    click.clear()
    display_header("Settings")
    
    click.echo("    1. 🔐 Change Master Password")
    click.echo("    2. 📊 View Statistics")
    click.echo("    3. 🔄 Import/Export")
    click.echo("    0. 🔙 Back")
    
    choice = click.prompt("\n    Select option", type=str, default="0")
    
    if choice == "1":
        click.echo("\n    Feature coming soon!")
    elif choice == "2":
        show_statistics_professional(pm)
    elif choice == "3":
        click.echo("\n    Use 'vk export' and 'vk import' commands")
    
    click.pause("\n    Press any key to continue...")


def show_statistics_professional(pm):
    """Display vault statistics"""
    click.clear()
    display_header("Vault Statistics")
    
    sites = pm.list_sites()
    click.echo(f"    Total Passwords: {len(sites)}")
    
    if sites:
        analyzer = PasswordStrength()
        strength_counts = {'strong': 0, 'weak': 0}
        
        for site in sites:
            data = pm.get_password(site)
            score = analyzer.analyze(data['password'])['score']
            if score >= 60:
                strength_counts['strong'] += 1
            else:
                strength_counts['weak'] += 1
        
        click.echo(f"    Strong Passwords: {strength_counts['strong']}")
        click.echo(f"    Weak Passwords: {strength_counts['weak']}")
    
    click.pause("\n    Press any key to continue...")


def create_new_vault():
    """Interactive vault creation"""
    pm = get_password_manager()
    
    click.clear()
    display_header("Create New Vault")
    
    click.echo("    Welcome to VaultKey!")
    click.echo("    Let's create your secure password vault.\n")
    
    click.echo("    📋 Master Password Requirements:")
    click.echo("    • At least 12 characters long")
    click.echo("    • Mix of letters, numbers, and symbols")
    click.echo("    • Something you can remember!\n")
    
    password = getpass.getpass("    Master password: ")
    confirm_pwd = getpass.getpass("    Confirm password: ")
    
    if password != confirm_pwd:
        show_error("Passwords don't match")
        return False
    
    click.echo("\n    Creating encrypted vault...")
    
    try:
        pm.create_vault(password)
        show_success("Vault created successfully!")
        click.pause("\n    Press any key to continue...")
        return True
    except Exception as e:
        show_error(f"Failed to create vault: {e}")
        return False


@cli.command()
def version():
    """Show VaultKey version and info"""
    click.echo("\n🔐 VaultKey Password Manager")
    click.echo("Version: 0.1.0")
    click.echo("Author: Your Name")
    click.echo("License: MIT")
    click.echo("\nA secure, local password manager with strong encryption")
    click.echo("Your passwords never leave your device!")
    click.echo("\nFor help: vk --help")


# Entry point
if __name__ == '__main__':
    cli()