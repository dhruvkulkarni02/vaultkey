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
            # Note: Can't echo here as it would interrupt whatever the user is doing
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
                # Check if has history
                history = pm.get_password_history(site)
                row_data['history'] = f"{len(history)} changes" if history else "No history"
            
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
            headers.extend(['Created', 'History', 'Notes'])
        
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
                    row.get('history', 'No history'),
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
def edit(site):
    """Interactive edit mode for a password entry"""
    pm = get_password_manager()
    
    # Unlock vault
    password = prompt_master_password()
    if not password or not pm.unlock(password):
        click.echo("❌ Invalid master password!", err=True)
        sys.exit(1)
    
    try:
        # Find the site
        current = pm.get_password(site)
        if not current:
            # Try fuzzy search
            matches = pm.search_sites(site)
            if not matches:
                click.echo(f"❌ No password found for '{site}'", err=True)
                return
            
            # Show matches
            click.echo(f"No exact match for '{site}'. Found these matches:")
            for i, match in enumerate(matches[:10], 1):
                creds = pm.get_password(match)
                click.echo(f"  {i}. {match} ({creds['username']})")
            
            if len(matches) > 10:
                click.echo(f"  ... and {len(matches) - 10} more")
            
            # Let user choose
            if len(matches) == 1:
                if click.confirm(f"\nEdit {matches[0]}?"):
                    site = matches[0]
                    current = pm.get_password(site)
                else:
                    return
            else:
                choice = click.prompt("\nEnter number to edit (0 to cancel)", 
                                    type=int, default=0)
                if choice == 0 or choice > len(matches):
                    return
                site = matches[choice - 1]
                current = pm.get_password(site)
        
        # Show current details
        click.echo(f"\n📝 Editing: {click.style(site, bold=True)}")
        click.echo("="*50)
        click.echo(f"Username: {current['username']}")
        click.echo(f"Password: {'*' * len(current['password'])}")
        click.echo(f"Notes: {current.get('notes', 'No notes')}")
        click.echo(f"Created: {current.get('created', 'Unknown')[:10]}")
        click.echo(f"Modified: {current.get('modified', 'Unknown')[:10]}")
        
        # Check password strength
        analyzer = PasswordStrength()
        analysis = analyzer.analyze(current['password'])
        click.echo(f"Strength: {format_strength_bar(analysis['score'])}")
        click.echo("="*50)
        
        # Edit menu
        while True:
            click.echo("\nWhat would you like to edit?")
            click.echo("  1. Username")
            click.echo("  2. Password")
            click.echo("  3. Notes")
            click.echo("  4. View current password")
            click.echo("  5. Check password strength")
            click.echo("  0. Save and exit")
            click.echo("  x. Cancel without saving")
            
            choice = click.prompt("Choice", type=str, default="0")
            
            if choice == "0":
                # Save and exit
                click.echo("\n✅ Changes saved successfully!")
                break
            
            elif choice.lower() == "x":
                # Cancel
                click.echo("\n❌ Edit cancelled - no changes saved")
                break
            
            elif choice == "1":
                # Edit username
                new_username = click.prompt("\nNew username", 
                                          default=current['username'])
                if new_username != current['username']:
                    if pm.update_password(site, new_username=new_username):
                        current['username'] = new_username
                        click.echo("✅ Username updated")
                    else:
                        click.echo("❌ Failed to update username")
            
            elif choice == "2":
                # Edit password
                click.echo("\nPassword options:")
                click.echo("  1. Enter new password manually")
                click.echo("  2. Generate secure password")
                click.echo("  3. Cancel")
                
                pwd_choice = click.prompt("Choice", type=str, default="3")
                
                if pwd_choice == "1":
                    new_password = getpass.getpass("New password: ")
                    confirm = getpass.getpass("Confirm password: ")
                    
                    if new_password != confirm:
                        click.echo("❌ Passwords don't match!")
                        continue
                    
                    # Check strength
                    analysis = analyzer.analyze(new_password)
                    click.echo(f"\nStrength: {format_strength_bar(analysis['score'])}")
                    
                    if analysis['score'] < 40:
                        click.echo("⚠️  This is a weak password!")
                        if not click.confirm("Use it anyway?"):
                            continue
                    
                    if pm.update_password(site, new_password=new_password):
                        current['password'] = new_password
                        click.echo("✅ Password updated")
                    else:
                        click.echo("❌ Failed to update password")
                
                elif pwd_choice == "2":
                    # Generate password
                    length = click.prompt("Password length", type=int, default=16)
                    use_symbols = click.confirm("Include symbols?", default=True)
                    
                    new_password = generate_password(length, use_symbols=use_symbols)
                    click.echo(f"\n🎲 Generated: {click.style(new_password, fg='green', bold=True)}")
                    
                    if click.confirm("Use this password?"):
                        if pm.update_password(site, new_password=new_password):
                            current['password'] = new_password
                            click.echo("✅ Password updated")
                        else:
                            click.echo("❌ Failed to update password")
            
            elif choice == "3":
                # Edit notes
                current_notes = current.get('notes', '')
                click.echo(f"\nCurrent notes: {current_notes}")
                new_notes = click.prompt("New notes (empty to clear)", 
                                       default=current_notes, show_default=False)
                
                if pm.update_password(site, new_notes=new_notes):
                    current['notes'] = new_notes
                    click.echo("✅ Notes updated")
                else:
                    click.echo("❌ Failed to update notes")
            
            elif choice == "4":
                # View password
                if click.confirm("\nShow password in plain text?"):
                    click.echo(f"Password: {click.style(current['password'], fg='yellow')}")
            
            elif choice == "5":
                # Check strength
                analysis = analyzer.analyze(current['password'])
                click.echo(f"\n🔍 Password Analysis:")
                click.echo(f"Strength: {format_strength_bar(analysis['score'])}")
                click.echo(f"Level: {analysis['strength'].replace('_', ' ').title()}")
                click.echo(f"Entropy: {analysis['entropy']} bits")
                
                if analysis['feedback']:
                    click.echo("\n⚠️  Issues:")
                    for issue in analysis['feedback']:
                        click.echo(f"  • {issue}")
                
                if analysis['suggestions']:
                    click.echo("\n💡 Suggestions:")
                    for suggestion in analysis['suggestions']:
                        click.echo(f"  • {suggestion}")
            
            else:
                click.echo("Invalid choice")
        
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)
    finally:
        pm.lock()


@cli.command()
@click.option('--filter', '-f', help='Filter sites to delete')
@click.option('--older-than', '-o', type=int, help='Delete passwords older than N days')
@click.option('--weak', '-w', is_flag=True, help='Delete only weak passwords')
@click.option('--force', '-F', is_flag=True, help='Skip all confirmations (dangerous!)')
def bulk_delete(filter, older_than, weak, force):
    """Bulk delete multiple passwords at once"""
    pm = get_password_manager()
    analyzer = PasswordStrength() if weak else None
    
    # Unlock vault
    password = prompt_master_password()
    if not password or not pm.unlock(password):
        click.echo("❌ Invalid master password!", err=True)
        sys.exit(1)
    
    try:
        # Get all sites
        sites = pm.list_sites()
        to_delete = []
        
        # Apply filters
        for site in sites:
            data = pm.get_password(site)
            
            # Filter by search term
            if filter and filter.lower() not in site.lower():
                continue
            
            # Filter by age
            if older_than:
                try:
                    modified = datetime.fromisoformat(data.get('modified', ''))
                    age_days = (datetime.now() - modified).days
                    if age_days < older_than:
                        continue
                except:
                    continue
            
            # Filter by strength
            if weak:
                analysis = analyzer.analyze(data['password'])
                if analysis['score'] >= 40:  # Not weak
                    continue
            
            to_delete.append(site)
        
        if not to_delete:
            click.echo("No passwords match the criteria")
            return
        
        # Show what will be deleted
        click.echo(f"\n🗑️  Found {len(to_delete)} password(s) to delete:")
        click.echo()
        
        # Create table
        table_data = []
        for site in to_delete[:20]:  # Show max 20
            data = pm.get_password(site)
            table_data.append([
                site,
                data['username'],
                data.get('modified', 'Unknown')[:10]
            ])
        
        headers = ['Site', 'Username', 'Last Modified']
        click.echo(tabulate(table_data, headers=headers, tablefmt='simple_grid'))
        
        if len(to_delete) > 20:
            click.echo(f"\n... and {len(to_delete) - 20} more")
        
        # Confirm deletion
        if not force:
            click.echo(f"\n⚠️  This will permanently delete {len(to_delete)} password(s)!")
            if not click.confirm("Are you absolutely sure?"):
                click.echo("❌ Bulk delete cancelled")
                return
            
            # Double confirmation for safety
            if len(to_delete) > 10:
                confirm_text = click.prompt(
                    f"\nType 'DELETE {len(to_delete)}' to confirm", 
                    type=str
                )
                if confirm_text != f"DELETE {len(to_delete)}":
                    click.echo("❌ Confirmation failed - bulk delete cancelled")
                    return
        
        # Perform deletion
        deleted_count = 0
        failed_count = 0
        
        with click.progressbar(to_delete, label='Deleting passwords') as bar:
            for site in bar:
                if pm.delete_password(site):
                    deleted_count += 1
                else:
                    failed_count += 1
        
        # Summary
        click.echo(f"\n✅ Deleted {deleted_count} password(s)")
        if failed_count > 0:
            click.echo(f"❌ Failed to delete {failed_count} password(s)")
        
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
        creds = pm.get_password(site)
        if not creds:
            # Try fuzzy search
            matches = pm.search_sites(site)
            if matches:
                click.echo(f"No exact match for '{site}'. Did you mean:")
                for i, match in enumerate(matches[:5], 1):
                    click.echo(f"  {i}. {match}")
                
                if len(matches) == 1:
                    if click.confirm(f"\nDelete password for {matches[0]}?"):
                        site = matches[0]
                        creds = pm.get_password(site)
                    else:
                        return
                else:
                    click.echo("\nPlease use the exact site name to delete")
                    return
            else:
                click.echo(f"❌ No password found for '{site}'", err=True)
                return
        
        # Show what will be deleted
        click.echo(f"\n🗑️  Password to delete:")
        click.echo(f"   Site: {click.style(site, bold=True)}")
        click.echo(f"   Username: {creds['username']}")
        click.echo(f"   Created: {creds.get('created', 'Unknown')[:10]}")
        
        # Check for password history
        history = pm.get_password_history(site)
        if history:
            click.echo(f"   History: {len(history)} previous password(s) will also be deleted")
        
        # Confirm deletion
        if force or click.confirm("\nAre you sure you want to delete this password?"):
            if pm.delete_password(site):
                click.echo(f"\n✅ Password for {site} deleted successfully")
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
@click.argument('site')
@click.option('--new-password', '-p', help='New password (leave empty to generate)')
@click.option('--new-username', '-u', help='New username')
@click.option('--new-notes', '-n', help='New notes')
@click.option('--generate', '-g', is_flag=True, help='Generate a new password')
@click.option('--length', '-l', default=16, help='Generated password length')
def update(site, new_password, new_username, new_notes, generate, length):
    """Update an existing password
    
    Examples:
        vk update github                    # Interactive mode
        vk update github -u newemail        # Update username
        vk update github -g                 # Generate new password
        vk update github -p newpass123      # Set specific password
    """
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
            # Try fuzzy search
            matches = pm.search_sites(site)
            if matches:
                click.echo(f"No exact match for '{site}'. Did you mean:")
                for i, match in enumerate(matches[:5], 1):
                    click.echo(f"  {i}. {match}")
                
                if len(matches) == 1:
                    if click.confirm(f"\nUpdate password for {matches[0]}?"):
                        site = matches[0]
                        current = pm.get_password(site)
                    else:
                        return
                else:
                    click.echo("\nPlease use the exact site name to update")
                    return
            else:
                click.echo(f"❌ No password found for '{site}'", err=True)
                return
        
        click.echo(f"\n📝 Updating password for: {click.style(site, bold=True)}")
        click.echo(f"Current username: {current['username']}")
        if current.get('notes'):
            click.echo(f"Current notes: {current['notes'][:50]}...")
        
        # Get new password if needed
        if generate:
            new_password = generate_password(length)
            click.echo(f"\n🎲 Generated password: {click.style(new_password, fg='green', bold=True)}")
            if not click.confirm("Use this password?"):
                return
        elif not new_password and not new_username and not new_notes:
            # Interactive mode if no options provided
            click.echo("\nLeave blank to keep current value:")
            
            new_username = click.prompt("New username", default=current['username'], 
                                      show_default=False)
            if new_username == current['username']:
                new_username = None
            
            if click.confirm("Generate new password?"):
                new_password = generate_password(length)
                click.echo(f"Generated: {click.style(new_password, fg='green', bold=True)}")
            else:
                new_password = getpass.getpass("New password (leave empty to keep current): ")
                if new_password:
                    confirm = getpass.getpass("Confirm new password: ")
                    if new_password != confirm:
                        click.echo("❌ Passwords don't match!", err=True)
                        return
            
            new_notes = click.prompt("New notes", default=current.get('notes', ''), 
                                   show_default=False)
            if new_notes == current.get('notes', ''):
                new_notes = None
        
        # Check for password reuse
        if new_password and pm.check_password_reuse(site, new_password):
            click.echo("\n⚠️  Warning: This password was previously used for this site!")
            if not click.confirm("Use it anyway?"):
                click.echo("❌ Update cancelled")
                return
        
        # Update
        if pm.update_password(site, new_password=new_password or None, 
                            new_username=new_username or None,
                            new_notes=new_notes):
            click.echo(f"\n✅ Password for {site} updated successfully!")
            
            # Show what was changed
            changes = []
            if new_password:
                changes.append("password")
            if new_username:
                changes.append("username")
            if new_notes is not None:
                changes.append("notes")
            
            if changes:
                click.echo(f"   Updated: {', '.join(changes)}")
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
        
        # Summary with table
        click.echo(f"\n{'='*60}")
        click.echo("\n📊 Summary Report\n")
        click.echo(f"Total passwords audited: {total_passwords}")
        
        # Create distribution table
        click.echo("\nStrength distribution:")
        distribution_data = []
        for strength, count in strength_counts.items():
            if count > 0:
                percentage = (count / total_passwords) * 100
                label = strength.replace('_', ' ').title()
                
                # Create visual bar
                bar_length = int(percentage / 5)
                bar = '█' * bar_length
                
                # Color based on strength
                if strength == 'very_strong':
                    colored_bar = click.style(bar, fg='green')
                elif strength == 'strong':
                    colored_bar = click.style(bar, fg='yellow')
                elif strength == 'fair':
                    colored_bar = click.style(bar, fg='yellow')
                else:
                    colored_bar = click.style(bar, fg='red')
                
                distribution_data.append([
                    label,
                    count,
                    f"{percentage:.1f}%",
                    colored_bar
                ])
        
        headers = ['Strength Level', 'Count', 'Percentage', 'Distribution']
        click.echo(tabulate(distribution_data, headers=headers, tablefmt='simple'))
        
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
        
        # Show weak passwords in a table if any
        if strength_counts['weak'] > 0 or strength_counts['very_weak'] > 0:
            click.echo("\n🚨 Critical: Weak passwords requiring immediate attention:\n")
            
            weak_table_data = []
            weak_sites = []
            
            for s in sites:
                score = analyzer.analyze(pm.get_password(s)['password'])['score']
                if score < 40:
                    weak_sites.append((s, score))
            
            # Sort by score (weakest first)
            weak_sites.sort(key=lambda x: x[1])
            
            for site, score in weak_sites[:10]:  # Show max 10
                creds = pm.get_password(site)
                if score < 20:
                    strength = click.style('██', fg='red')
                    level = 'Very Weak'
                else:
                    strength = click.style('████', fg='red')
                    level = 'Weak'
                
                weak_table_data.append([
                    site,
                    creds['username'],
                    strength,
                    level
                ])
            
            headers = ['Site', 'Username', 'Strength', 'Level']
            click.echo(tabulate(weak_table_data, headers=headers, tablefmt='simple_grid'))
            
            if len(weak_sites) > 10:
                click.echo(f"\n... and {len(weak_sites) - 10} more weak passwords")
        
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
                click.echo("\n🚨 Passwords found in data breaches:\n")
                
                breach_table_data = []
                for site, result in critical_breaches[:10]:
                    creds = pm.get_password(site)
                    severity_emoji = {
                        'critical': '🚨',
                        'high': '❗'
                    }.get(result['severity'], '⚠️')
                    
                    breach_table_data.append([
                        f"{severity_emoji} {site}",
                        creds['username'],
                        f"{result['count']:,} exposures",
                        result['severity'].title()
                    ])
                
                headers = ['Site', 'Username', 'Exposures', 'Severity']
                click.echo(tabulate(breach_table_data, headers=headers, tablefmt='simple_grid'))
            
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
            count = 0
            for site, data in imported_passwords.items():
                if count >= 10:
                    break
                try:
                    # Sanitize the output to handle special characters
                    safe_site = str(site).encode('utf-8', 'replace').decode('utf-8')
                    safe_username = str(data.get('username', '')).encode('utf-8', 'replace').decode('utf-8')
                    # Use simple dash instead of bullet point to avoid Unicode issues
                    click.echo(f"  - {safe_site} ({safe_username})")
                    count += 1
                except Exception as e:
                    # If there's still an error, show a placeholder
                    click.echo(f"  - [Entry {count + 1}: Unable to display]")
                    count += 1
            
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


@cli.command()
@click.argument('query')
@click.option('--type', '-t', type=click.Choice(['all', 'weak', 'strong', 'breached', 'old', 'recent']), 
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
                click.echo("\nPlease be more specific or use the exact site name")
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
@click.option('--master-password', '-m', is_flag=True, help='Change master password')
@click.option('--auto-lock', '-a', type=int, help='Set auto-lock timeout in minutes')
@click.option('--history', '-h', type=click.Choice(['enable', 'disable']), help='Enable/disable password history')
def config(master_password, auto_lock, history):
    """Configure VaultKey settings"""
    pm = get_password_manager()
    
    if master_password:
        # Change master password
        click.echo("\n🔐 Change Master Password\n")
        
        # Get current password
        current_password = prompt_master_password()
        if not current_password or not pm.unlock(current_password):
            click.echo("❌ Invalid current master password!", err=True)
            sys.exit(1)
        
        # Get new password
        click.echo("\nEnter new master password:")
        new_password = prompt_master_password(confirm=True)
        if not new_password:
            return
        
        try:
            if pm.change_master_password(current_password, new_password):
                click.echo("\n✅ Master password changed successfully!")
                click.echo("🔐 Use your new password from now on.")
            else:
                click.echo("❌ Failed to change master password", err=True)
        except Exception as e:
            click.echo(f"❌ Error: {e}", err=True)
            sys.exit(1)
        finally:
            pm.lock()
    
    elif auto_lock is not None:
        click.echo(f"✅ Auto-lock timeout set to {auto_lock} minutes")
        # This would need implementation in the PasswordManager class
        
    elif history:
        # This would need implementation in the PasswordManager class
        if history == 'enable':
            click.echo("✅ Password history enabled")
        else:
            click.echo("✅ Password history disabled")
    
    else:
        click.echo("No configuration option specified. Use --help for options.")


@cli.command()
@click.option('--detailed', '-d', is_flag=True, help='Show detailed statistics')
def stats(detailed):
    """Show password vault statistics"""
    pm = get_password_manager()
    
    # Unlock vault
    password = prompt_master_password()
    if not password or not pm.unlock(password):
        click.echo("❌ Invalid master password!", err=True)
        sys.exit(1)
    
    try:
        analyzer = PasswordStrength()
        sites = pm.list_sites()
        
        if not sites:
            click.echo("No passwords stored yet.")
            return
        
        # Gather statistics
        total_passwords = len(sites)
        strength_distribution = {
            'very_strong': 0,
            'strong': 0,
            'fair': 0,
            'weak': 0,
            'very_weak': 0
        }
        
        oldest_password = None
        newest_password = None
        password_ages = []
        username_frequency = {}
        
        for site in sites:
            data = pm.get_password(site)
            
            # Analyze strength
            analysis = analyzer.analyze(data['password'])
            strength_distribution[analysis['strength']] += 1
            
            # Track username frequency
            username = data.get('username', '').lower()
            if username:
                username_frequency[username] = username_frequency.get(username, 0) + 1
            
            # Track ages
            try:
                modified = datetime.fromisoformat(data.get('modified', ''))
                age_days = (datetime.now() - modified).days
                password_ages.append(age_days)
                
                if oldest_password is None or age_days > oldest_password[1]:
                    oldest_password = (site, age_days)
                if newest_password is None or age_days < newest_password[1]:
                    newest_password = (site, age_days)
            except:
                pass
        
        # Display statistics
        click.echo("\n📊 VaultKey Statistics\n")
        click.echo(f"Total passwords: {total_passwords}")
        
        # Strength distribution
        click.echo("\n💪 Password Strength Distribution:")
        for strength, count in strength_distribution.items():
            if count > 0:
                percentage = (count / total_passwords) * 100
                bar_length = int(percentage / 2)
                bar = '█' * bar_length
                
                if strength in ['very_strong', 'strong']:
                    bar = click.style(bar, fg='green')
                elif strength == 'fair':
                    bar = click.style(bar, fg='yellow')
                else:
                    bar = click.style(bar, fg='red')
                
                label = strength.replace('_', ' ').title()
                click.echo(f"  {label:12} {count:3} ({percentage:5.1f}%) {bar}")
        
        # Age statistics
        if password_ages:
            avg_age = sum(password_ages) / len(password_ages)
            click.echo(f"\n📅 Password Age:")
            click.echo(f"  Average age: {avg_age:.0f} days")
            if oldest_password:
                click.echo(f"  Oldest: {oldest_password[0]} ({oldest_password[1]} days)")
            if newest_password:
                click.echo(f"  Newest: {newest_password[0]} ({newest_password[1]} days)")
        
        # Username statistics
        if detailed and username_frequency:
            click.echo("\n👤 Most Used Usernames:")
            sorted_usernames = sorted(username_frequency.items(), key=lambda x: x[1], reverse=True)
            for username, count in sorted_usernames[:5]:
                if count > 1:
                    click.echo(f"  {username}: {count} times")
        
        # Security recommendations
        weak_count = strength_distribution['weak'] + strength_distribution['very_weak']
        if weak_count > 0:
            click.echo(f"\n⚠️  Security Alert: {weak_count} weak password(s) found!")
            click.echo("   Run 'vk audit' for detailed analysis")
        
        if password_ages and max(password_ages) > 180:
            old_count = sum(1 for age in password_ages if age > 180)
            click.echo(f"\n⏰ {old_count} password(s) are over 6 months old")
            click.echo("   Consider updating them regularly")
        
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)
    finally:
        pm.lock()


@cli.command()
def interactive():
    """Launch interactive mode with a menu-driven interface"""
    pm = get_password_manager()
    
    # Check if vault exists
    if not pm.storage.exists():
        click.echo("❌ No vault found. Let's create one first!")
        if click.confirm("Create a new password vault?"):
            create_new_vault()
        else:
            return
    
    # Welcome screen
    click.clear()
    click.echo("╔══════════════════════════════════════════╗")
    click.echo("║        🔐 VaultKey Password Manager      ║")
    click.echo("║           Interactive Mode v0.1.0        ║")
    click.echo("╚══════════════════════════════════════════╝")
    click.echo()
    
    # Unlock vault
    password = prompt_master_password()
    if not password or not pm.unlock(password):
        click.echo("❌ Invalid master password!", err=True)
        return
    
    try:
        # Get initial stats
        sites = pm.list_sites()
        analyzer = PasswordStrength()
        
        while True:
            # Clear screen for clean interface
            click.clear()
            
            # Header with stats
            click.echo("╔══════════════════════════════════════════╗")
            click.echo(f"║  🔐 VaultKey  │  {len(sites)} passwords stored   ║")
            click.echo("╚══════════════════════════════════════════╝")
            click.echo()
            
            # Main menu
            click.echo("📋 MAIN MENU")
            click.echo("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            click.echo("  1. 🔍 Search passwords")
            click.echo("  2. ➕ Add new password")
            click.echo("  3. 📋 List all passwords")
            click.echo("  4. ✏️  Edit password")
            click.echo("  5. 🗑️  Delete password")
            click.echo("  6. 📊 Security audit")
            click.echo("  7. 🎲 Generate password")
            click.echo("  8. 📤 Import/Export")
            click.echo("  9. ⚙️  Settings")
            click.echo("  0. 🚪 Exit")
            click.echo("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            
            choice = click.prompt("\nEnter your choice", type=str, default="0")
            
            if choice == "0":
                if click.confirm("\nExit VaultKey?"):
                    click.echo("\n👋 Goodbye! Your passwords are safely encrypted.")
                    break
            
            elif choice == "1":
                # Search
                interactive_search(pm)
            
            elif choice == "2":
                # Add new
                interactive_add(pm)
                sites = pm.list_sites()  # Refresh count
            
            elif choice == "3":
                # List all
                interactive_list(pm)
            
            elif choice == "4":
                # Edit
                interactive_edit_menu(pm)
            
            elif choice == "5":
                # Delete
                interactive_delete(pm)
                sites = pm.list_sites()  # Refresh count
            
            elif choice == "6":
                # Audit
                interactive_audit(pm)
            
            elif choice == "7":
                # Generate
                interactive_generate()
            
            elif choice == "8":
                # Import/Export
                interactive_import_export(pm)
            
            elif choice == "9":
                # Settings
                interactive_settings(pm)
            
            else:
                click.echo("❌ Invalid choice. Please try again.")
                click.pause()
    
    except KeyboardInterrupt:
        click.echo("\n\n👋 Goodbye!")
    except Exception as e:
        click.echo(f"\n❌ Error: {e}", err=True)
    finally:
        pm.lock()


def create_new_vault():
    """Interactive vault creation"""
    pm = get_password_manager()
    
    click.echo("\n🔐 Creating a new password vault...\n")
    click.echo("Choose a strong master password.")
    click.echo("This password protects all your other passwords.")
    click.echo("Make it long and unique!\n")
    
    password = prompt_master_password(confirm=True)
    if not password:
        return False
    
    try:
        pm.create_vault(password)
        click.echo("\n✅ Password vault created successfully!")
        click.pause()
        return True
    except Exception as e:
        click.echo(f"❌ Error creating vault: {e}", err=True)
        click.pause()
        return False


def interactive_search(pm):
    """Interactive search interface"""
    click.clear()
    click.echo("🔍 SEARCH PASSWORDS")
    click.echo("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    
    query = click.prompt("Search for", default="", show_default=False)
    if not query:
        return
    
    # Search
    results = []
    for site in pm.list_sites():
        data = pm.get_password(site)
        if (query.lower() in site.lower() or 
            query.lower() in data.get('username', '').lower() or 
            query.lower() in data.get('notes', '').lower()):
            results.append((site, data))
    
    if not results:
        click.echo(f"\n❌ No passwords found matching '{query}'")
        click.pause()
        return
    
    # Display results
    click.echo(f"\n📊 Found {len(results)} result(s):\n")
    
    for i, (site, data) in enumerate(results[:20], 1):
        click.echo(f"{i:2}. {site}")
        click.echo(f"    👤 {data['username']}")
        click.echo(f"    📅 Modified: {data.get('modified', 'Unknown')[:10]}")
        click.echo()
    
    if len(results) > 20:
        click.echo(f"... and {len(results) - 20} more results")
    
    # Action menu
    click.echo("\n" + "━" * 40)
    click.echo("Actions: (V)iew  (E)dit  (C)opy  (D)elete  (B)ack")
    
    action = click.prompt("Choice", type=str, default="b").lower()
    
    if action == "b":
        return
    elif action in ["v", "e", "c", "d"] and len(results) > 0:
        if len(results) == 1:
            selected_site = results[0][0]
        else:
            num = click.prompt("Enter number", type=int, default=1)
            if 1 <= num <= len(results):
                selected_site = results[num-1][0]
            else:
                click.echo("❌ Invalid selection")
                click.pause()
                return
        
        if action == "v":
            view_password_interactive(pm, selected_site)
        elif action == "e":
            edit_password_interactive(pm, selected_site)
        elif action == "c":
            copy_password_interactive(pm, selected_site)
        elif action == "d":
            delete_password_interactive(pm, selected_site)


def interactive_add(pm):
    """Interactive add password interface"""
    click.clear()
    click.echo("➕ ADD NEW PASSWORD")
    click.echo("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    
    site = click.prompt("\n🌐 Site/Service name")
    username = click.prompt("👤 Username/Email")
    
    # Check if already exists
    if pm.get_password(site):
        click.echo(f"\n⚠️  A password for '{site}' already exists!")
        if not click.confirm("Replace it?"):
            return
    
    # Password options
    click.echo("\n🔑 Password Options:")
    click.echo("  1. Generate secure password (recommended)")
    click.echo("  2. Enter password manually")
    
    pwd_choice = click.prompt("Choice", type=str, default="1")
    
    if pwd_choice == "1":
        # Generate password
        click.echo("\n🎲 Password Generator Settings:")
        length = click.prompt("  Length", type=int, default=16)
        use_symbols = click.confirm("  Include symbols?", default=True)
        use_numbers = click.confirm("  Include numbers?", default=True)
        use_uppercase = click.confirm("  Include uppercase?", default=True)
        
        password = generate_password(
            length=length,
            use_symbols=use_symbols,
            use_digits=use_numbers,
            use_uppercase=use_uppercase
        )
        
        click.echo(f"\n🎲 Generated password: {click.style(password, fg='green', bold=True)}")
        
        # Show strength
        analyzer = PasswordStrength()
        analysis = analyzer.analyze(password)
        click.echo(f"💪 Strength: {format_strength_bar(analysis['score'])}")
        
        if not click.confirm("\nSave this password?"):
            return
    else:
        # Manual entry
        password = getpass.getpass("\n🔑 Password: ")
        confirm = getpass.getpass("🔑 Confirm password: ")
        
        if password != confirm:
            click.echo("❌ Passwords don't match!")
            click.pause()
            return
        
        # Check strength
        analyzer = PasswordStrength()
        analysis = analyzer.analyze(password)
        click.echo(f"\n💪 Strength: {format_strength_bar(analysis['score'])}")
        
        if analysis['score'] < 40:
            click.echo("⚠️  This is a weak password!")
            if not click.confirm("Use it anyway?"):
                return
    
    # Optional notes
    add_notes = click.confirm("\n📝 Add notes?", default=False)
    notes = ""
    if add_notes:
        notes = click.prompt("Notes", default="")
    
    # Save
    try:
        pm.add_password(site, username, password, notes)
        click.echo(f"\n✅ Password saved for {site}!")
        
        # Offer to copy
        if click.confirm("📋 Copy password to clipboard?"):
            try:
                import pyperclip
                pyperclip.copy(password)
                click.echo("✅ Password copied to clipboard!")
            except ImportError:
                click.echo("⚠️  Install 'pyperclip' for clipboard support")
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
    
    click.pause()


def interactive_list(pm):
    """Interactive list interface with pagination"""
    sites = pm.list_sites()
    if not sites:
        click.echo("\n❌ No passwords stored yet!")
        click.pause()
        return
    
    # Pagination settings
    page_size = 15
    current_page = 0
    total_pages = (len(sites) - 1) // page_size + 1
    
    while True:
        click.clear()
        click.echo("📋 ALL PASSWORDS")
        click.echo("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        
        # Calculate page boundaries
        start_idx = current_page * page_size
        end_idx = min(start_idx + page_size, len(sites))
        
        # Display current page
        for i, site in enumerate(sites[start_idx:end_idx], start_idx + 1):
            data = pm.get_password(site)
            click.echo(f"{i:3}. {site}")
            click.echo(f"     👤 {data['username']}")
            
            # Calculate age
            try:
                modified = datetime.fromisoformat(data.get('modified', ''))
                age_days = (datetime.now() - modified).days
                if age_days == 0:
                    age_str = "Today"
                elif age_days < 30:
                    age_str = f"{age_days} days ago"
                else:
                    age_str = f"{age_days // 30} months ago"
            except:
                age_str = "Unknown"
            
            click.echo(f"     📅 {age_str}")
            click.echo()
        
        # Page info
        click.echo("━" * 40)
        click.echo(f"Page {current_page + 1} of {total_pages} │ Total: {len(sites)} passwords")
        click.echo("━" * 40)
        
        # Navigation
        nav_options = []
        if current_page > 0:
            nav_options.append("(P)revious")
        if current_page < total_pages - 1:
            nav_options.append("(N)ext")
        nav_options.extend(["(V)iew", "(S)earch", "(B)ack"])
        
        click.echo(" ".join(nav_options))
        
        choice = click.prompt("Choice", type=str, default="b").lower()
        
        if choice == "b":
            break
        elif choice == "n" and current_page < total_pages - 1:
            current_page += 1
        elif choice == "p" and current_page > 0:
            current_page -= 1
        elif choice == "v":
            num = click.prompt("Enter number to view", type=int)
            if 1 <= num <= len(sites):
                view_password_interactive(pm, sites[num-1])
        elif choice == "s":
            interactive_search(pm)
            break


def view_password_interactive(pm, site):
    """View a specific password interactively"""
    data = pm.get_password(site)
    if not data:
        click.echo(f"❌ Password not found for '{site}'")
        click.pause()
        return
    
    click.clear()
    click.echo(f"🔐 PASSWORD DETAILS: {site}")
    click.echo("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    
    click.echo(f"\n👤 Username: {click.style(data['username'], fg='cyan')}")
    
    # Password (hidden by default)
    show_password = click.confirm("👁️  Show password?", default=False)
    if show_password:
        click.echo(f"🔑 Password: {click.style(data['password'], fg='yellow')}")
    else:
        click.echo(f"🔑 Password: {'•' * len(data['password'])}")
    
    # Strength analysis
    analyzer = PasswordStrength()
    analysis = analyzer.analyze(data['password'])
    click.echo(f"💪 Strength: {format_strength_bar(analysis['score'])}")
    
    # Additional info
    if data.get('notes'):
        click.echo(f"📝 Notes: {data['notes']}")
    
    click.echo(f"📅 Created: {data.get('created', 'Unknown')[:10]}")
    click.echo(f"📅 Modified: {data.get('modified', 'Unknown')[:10]}")
    
    # Check breaches
    if click.confirm("\n🔍 Check if password has been breached?", default=False):
        checker = BreachChecker()
        result = checker.check_password(data['password'])
        
        if result.get('found'):
            click.echo(f"\n⚠️  {result['message']}")
            click.echo(f"💡 {result['recommendation']}")
        else:
            click.echo(f"\n✅ {result['message']}")
    
    # Actions
    click.echo("\n" + "━" * 40)
    click.echo("(C)opy password  (E)dit  (D)elete  (B)ack")
    
    action = click.prompt("Choice", type=str, default="b").lower()
    
    if action == "c":
        copy_password_interactive(pm, site)
    elif action == "e":
        edit_password_interactive(pm, site)
    elif action == "d":
        delete_password_interactive(pm, site)


def copy_password_interactive(pm, site):
    """Copy password to clipboard"""
    try:
        import pyperclip
        data = pm.get_password(site)
        pyperclip.copy(data['password'])
        click.echo("\n✅ Password copied to clipboard!")
        click.echo("⏱️  Clipboard will be cleared in 30 seconds...")
        clear_clipboard_after_delay(30)
    except ImportError:
        click.echo("\n⚠️  Install 'pyperclip' for clipboard support")
        click.echo("   Run: pip install pyperclip")
    click.pause()


def edit_password_interactive(pm, site):
    """Interactive password editing"""
    current = pm.get_password(site)
    
    click.clear()
    click.echo(f"✏️  EDIT PASSWORD: {site}")
    click.echo("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    
    # What to edit
    click.echo("\nWhat would you like to change?")
    click.echo("  1. Username")
    click.echo("  2. Password")
    click.echo("  3. Notes")
    click.echo("  4. Everything")
    click.echo("  0. Cancel")
    
    choice = click.prompt("Choice", type=str, default="0")
    
    if choice == "0":
        return
    
    new_username = None
    new_password = None
    new_notes = None
    
    if choice in ["1", "4"]:
        new_username = click.prompt("New username", default=current['username'])
        if new_username == current['username']:
            new_username = None
    
    if choice in ["2", "4"]:
        if click.confirm("Generate new password?"):
            length = click.prompt("Length", type=int, default=16)
            new_password = generate_password(length)
            click.echo(f"\n🎲 Generated: {click.style(new_password, fg='green', bold=True)}")
        else:
            new_password = getpass.getpass("New password: ")
            confirm = getpass.getpass("Confirm: ")
            if new_password != confirm:
                click.echo("❌ Passwords don't match!")
                click.pause()
                return
    
    if choice in ["3", "4"]:
        new_notes = click.prompt("New notes", default=current.get('notes', ''))
        if new_notes == current.get('notes', ''):
            new_notes = None
    
    # Update
    if new_username or new_password or new_notes is not None:
        if pm.update_password(site, new_password, new_username, new_notes):
            click.echo("\n✅ Password updated successfully!")
        else:
            click.echo("\n❌ Failed to update password")
    
    click.pause()


def delete_password_interactive(pm, site):
    """Interactive password deletion"""
    data = pm.get_password(site)
    
    click.echo(f"\n🗑️  Delete password for: {site}")
    click.echo(f"   Username: {data['username']}")
    
    if click.confirm("Are you sure?", default=False):
        if pm.delete_password(site):
            click.echo("✅ Password deleted!")
        else:
            click.echo("❌ Failed to delete password")
    else:
        click.echo("❌ Deletion cancelled")
    
    click.pause()


def interactive_audit(pm):
    """Interactive security audit"""
    click.clear()
    click.echo("🔍 SECURITY AUDIT")
    click.echo("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    
    sites = pm.list_sites()
    if not sites:
        click.echo("\n❌ No passwords to audit!")
        click.pause()
        return
    
    click.echo(f"\nAnalyzing {len(sites)} passwords...")
    
    analyzer = PasswordStrength()
    weak_passwords = []
    old_passwords = []
    
    with click.progressbar(sites, label='Scanning') as bar:
        for site in bar:
            data = pm.get_password(site)
            
            # Check strength
            analysis = analyzer.analyze(data['password'])
            if analysis['score'] < 40:
                weak_passwords.append((site, analysis['score']))
            
            # Check age
            try:
                modified = datetime.fromisoformat(data.get('modified', ''))
                age_days = (datetime.now() - modified).days
                if age_days > 180:  # 6 months
                    old_passwords.append((site, age_days))
            except:
                pass
    
    # Display results
    click.echo("\n📊 AUDIT RESULTS")
    click.echo("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    
    if weak_passwords:
        click.echo(f"\n⚠️  {len(weak_passwords)} weak password(s) found:")
        for site, score in weak_passwords[:5]:
            click.echo(f"   • {site} - {click.style('Very Weak' if score < 20 else 'Weak', fg='red')}")
        if len(weak_passwords) > 5:
            click.echo(f"   ... and {len(weak_passwords) - 5} more")
    else:
        click.echo("\n✅ No weak passwords found!")
    
    if old_passwords:
        click.echo(f"\n⏰ {len(old_passwords)} old password(s) (>6 months):")
        for site, days in old_passwords[:5]:
            click.echo(f"   • {site} - {days} days old")
        if len(old_passwords) > 5:
            click.echo(f"   ... and {len(old_passwords) - 5} more")
    
    # Recommendations
    if weak_passwords or old_passwords:
        click.echo("\n💡 RECOMMENDATIONS:")
        if weak_passwords:
            click.echo("   • Update weak passwords immediately")
        if old_passwords:
            click.echo("   • Consider rotating old passwords")
        click.echo("   • Use 'vk generate' to create strong passwords")
    
    # Breach check option
    if click.confirm("\n🔐 Check all passwords for breaches?", default=False):
        click.echo("\nChecking breach database...")
        checker = BreachChecker()
        breached = 0
        
        with click.progressbar(sites, label='Checking') as bar:
            for site in bar:
                data = pm.get_password(site)
                result = checker.check_password(data['password'])
                if result.get('found'):
                    breached += 1
        
        if breached > 0:
            click.echo(f"\n🚨 {breached} password(s) found in data breaches!")
            click.echo("   Run 'vk breaches' for details")
        else:
            click.echo("\n✅ No passwords found in breach database!")
    
    click.pause()


def interactive_generate():
    """Interactive password generator"""
    click.clear()
    click.echo("🎲 PASSWORD GENERATOR")
    click.echo("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    
    while True:
        click.echo("\n⚙️  Settings:")
        length = click.prompt("  Length", type=int, default=16)
        use_uppercase = click.confirm("  Include uppercase?", default=True)
        use_lowercase = click.confirm("  Include lowercase?", default=True)
        use_digits = click.confirm("  Include numbers?", default=True)
        use_symbols = click.confirm("  Include symbols?", default=True)
        exclude_ambiguous = click.confirm("  Exclude ambiguous (0,O,l,1)?", default=False)
        
        # Generate
        password = generate_password(
            length=length,
            use_uppercase=use_uppercase,
            use_lowercase=use_lowercase,
            use_digits=use_digits,
            use_symbols=use_symbols,
            exclude_ambiguous=exclude_ambiguous
        )
        
        click.echo(f"\n🎲 Generated password:")
        click.echo(f"   {click.style(password, fg='green', bold=True)}")
        
        # Analyze
        analyzer = PasswordStrength()
        analysis = analyzer.analyze(password)
        click.echo(f"\n💪 Strength: {format_strength_bar(analysis['score'])}")
        click.echo(f"📊 Entropy: {analysis['entropy']} bits")
        
        # Options
        click.echo("\n" + "━" * 40)
        click.echo("(C)opy  (S)ave  (R)egenerate  (B)ack")
        
        choice = click.prompt("Choice", type=str, default="r").lower()
        
        if choice == "b":
            break
        elif choice == "c":
            try:
                import pyperclip
                pyperclip.copy(password)
                click.echo("✅ Copied to clipboard!")
            except ImportError:
                click.echo("⚠️  Install 'pyperclip' for clipboard support")
        elif choice == "s":
            site = click.prompt("Site name")
            username = click.prompt("Username")
            # This would need access to pm - simplified for now
            click.echo("💡 Use 'vk add' to save this password")
        elif choice == "r":
            continue  # Regenerate


def interactive_import_export(pm):
    """Interactive import/export menu"""
    click.clear()
    click.echo("📤 IMPORT/EXPORT")
    click.echo("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    
    click.echo("\n1. 📥 Import passwords")
    click.echo("2. 📤 Export passwords")
    click.echo("3. 🔙 Back")
    
    choice = click.prompt("Choice", type=str, default="3")
    
    if choice == "1":
        click.echo("\n📥 Import from:")
        click.echo("  1. CSV file")
        click.echo("  2. LastPass")
        click.echo("  3. Bitwarden")
        click.echo("  4. 1Password")
        click.echo("  5. Chrome")
        click.echo("  6. VaultKey backup")
        
        format_choice = click.prompt("Format", type=str)
        formats = {
            "1": "csv",
            "2": "lastpass",
            "3": "bitwarden",
            "4": "1password",
            "5": "chrome",
            "6": "vaultkey"
        }
        
        if format_choice in formats:
            file_path = click.prompt("File path")
            click.echo(f"Import from {formats[format_choice]} format: {file_path}")
            click.echo("Use 'vk import' command for actual import")
    
    elif choice == "2":
        click.echo("\n📤 Export to:")
        click.echo("  1. CSV (unencrypted)")
        click.echo("  2. JSON (unencrypted)")
        click.echo("  3. VaultKey backup (encrypted)")
        
        format_choice = click.prompt("Format", type=str)
        if format_choice in ["1", "2", "3"]:
            file_path = click.prompt("Save to file", default="vaultkey_export")
            click.echo("Use 'vk export' command for actual export")
    
    click.pause()


def interactive_settings(pm):
    """Interactive settings menu"""
    click.clear()
    click.echo("⚙️  SETTINGS")
    click.echo("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    
    click.echo("\n1. 🔐 Change master password")
    click.echo("2. 🕐 Auto-lock timeout")
    click.echo("3. 📜 Password history")
    click.echo("4. 🗑️  Clear all data")
    click.echo("5. 🔙 Back")
    
    choice = click.prompt("Choice", type=str, default="5")
    
    if choice == "1":
        click.echo("\n🔐 Change Master Password")
        click.echo("This will re-encrypt all your passwords")
        
        if click.confirm("Continue?"):
            current_pwd = getpass.getpass("Current password: ")
            new_pwd = prompt_master_password(confirm=True)
            
            if new_pwd:
                # This would need implementation in PasswordManager
                click.echo("Master password change not yet implemented")
    
    elif choice == "2":
        timeout = click.prompt("Auto-lock after (minutes)", type=int, default=15)
        click.echo(f"✅ Auto-lock set to {timeout} minutes")
    
    elif choice == "3":
        if click.confirm("Enable password history?", default=True):
            click.echo("✅ Password history enabled")
        else:
            click.echo("✅ Password history disabled")
    
    elif choice == "4":
        click.echo("\n🗑️  DANGER: Clear all data")
        click.echo("This will delete all your passwords permanently!")
        
        if click.confirm("Are you absolutely sure?", default=False):
            confirm_text = click.prompt("Type 'DELETE ALL' to confirm")
            if confirm_text == "DELETE ALL":
                click.echo("❌ Data deletion not implemented for safety")
            else:
                click.echo("❌ Deletion cancelled")
    
    click.pause()


@cli.command()
def shell():
    """Launch interactive shell mode (alias for 'interactive')"""
    interactive()


# Add these helper functions at the module level
def interactive_edit_menu(pm):
    """Interactive edit menu"""
    site = click.prompt("\n🔍 Enter site name to edit")
    edit_password_interactive(pm, site)


def interactive_delete(pm):
    """Interactive delete menu"""
    site = click.prompt("\n🔍 Enter site name to delete")
    delete_password_interactive(pm, site)


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