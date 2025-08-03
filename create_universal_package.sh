#!/bin/bash
# create_universal_package.sh - Creates a package for both Windows and Mac

echo "📦 Creating Universal VaultKey Package..."

# Create package structure
PACKAGE_DIR=~/Desktop/VaultKey-Universal
rm -rf $PACKAGE_DIR
mkdir -p $PACKAGE_DIR/{Windows,Mac,Documentation}

# Copy Mac executable
echo "📋 Adding Mac version..."
cp dist/VaultKey $PACKAGE_DIR/Mac/VaultKey

# Create Mac launcher
cat > $PACKAGE_DIR/Mac/VaultKey.command << 'EOF'
#!/bin/bash
clear
echo "Starting VaultKey Password Manager..."
cd "$(dirname "$0")"
./VaultKey interactive
EOF
chmod +x $PACKAGE_DIR/Mac/VaultKey.command

# Create Windows launcher (batch file)
cat > $PACKAGE_DIR/Windows/VaultKey.bat << 'EOF'
@echo off
title VaultKey Password Manager
cls
echo Starting VaultKey Password Manager...
echo.
cd /d "%~dp0"
VaultKey.exe interactive
if errorlevel 1 (
    echo.
    echo Press any key to close...
    pause > nul
)
EOF

# Create Windows PowerShell launcher (alternative)
cat > $PACKAGE_DIR/Windows/VaultKey.ps1 << 'EOF'
# VaultKey Password Manager Launcher
Clear-Host
Write-Host "Starting VaultKey Password Manager..." -ForegroundColor Cyan
Set-Location $PSScriptRoot
.\VaultKey.exe interactive
if ($LASTEXITCODE -ne 0) {
    Write-Host "`nPress any key to close..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
EOF

# Create universal documentation
cat > $PACKAGE_DIR/START-HERE.txt << 'EOF'
═══════════════════════════════════════════════════════════
                  VAULTKEY PASSWORD MANAGER
                     Quick Start Guide
═══════════════════════════════════════════════════════════

Thank you for using VaultKey!

INSTALLATION INSTRUCTIONS:
─────────────────────────

FOR WINDOWS USERS:
1. Open the "Windows" folder
2. Copy the entire folder to your Desktop
3. Double-click "VaultKey.bat" to start
   (If that doesn't work, try right-clicking 
    VaultKey.ps1 → "Run with PowerShell")

FOR MAC USERS:
1. Open the "Mac" folder  
2. Copy the entire folder to your Desktop
3. Double-click "VaultKey.command" to start
   (If asked for permission, click "Open")

FIRST TIME SETUP:
─────────────────
1. Create a master password when prompted
2. WRITE IT DOWN - it cannot be recovered!
3. Start adding your passwords

See the Documentation folder for detailed instructions.

═══════════════════════════════════════════════════════════
EOF

# Create detailed guide
cat > $PACKAGE_DIR/Documentation/Complete-Guide.txt << 'EOF'
VAULTKEY COMPLETE USER GUIDE
============================

TABLE OF CONTENTS
-----------------
1. What is VaultKey?
2. Installation
3. First Time Setup
4. Daily Use
5. Tips & Best Practices
6. Troubleshooting
7. Security Information


1. WHAT IS VAULTKEY?
--------------------
VaultKey is a password manager that:
• Stores all your passwords securely
• Encrypts them with military-grade encryption
• Works completely offline (no internet needed)
• Helps you create strong passwords
• Makes logging in to websites easier


2. INSTALLATION
---------------
WINDOWS:
• Copy the Windows folder to your computer
• Double-click VaultKey.bat to start

MAC:
• Copy the Mac folder to your computer  
• Double-click VaultKey.command to start


3. FIRST TIME SETUP
-------------------
When you first start VaultKey:

a) You'll see a welcome screen with the VaultKey logo
b) Create your Master Password:
   • Make it at least 12 characters
   • Use a mix of letters, numbers, and symbols
   • Make it memorable but unique
   • Example: "MyDog$Buddy&Born2019!"
   • WRITE IT DOWN AND KEEP IT SAFE!
c) The program will create your encrypted vault


4. DAILY USE
------------
The Main Menu shows these options:

1. 🔍 Search Passwords - Find a saved password
2. ➕ Add Password - Save a new password  
3. 📋 Browse Vault - See all passwords
4. 🔐 Quick Copy - Copy a password fast

ADDING A PASSWORD:
• Press 2
• Enter the website (e.g., "gmail.com")
• Enter your username/email
• Choose to generate a strong password (recommended!)
• VaultKey saves it securely

GETTING A PASSWORD:
• Press 4 for Quick Copy
• Type part of the website name
• Password is copied to clipboard
• Just paste it where needed!


5. TIPS & BEST PRACTICES
------------------------
✓ Always use generated passwords (they're stronger)
✓ Give each account a unique password
✓ Update passwords every few months
✓ Never share your master password
✓ Back up your vault file occasionally
✓ Use the search feature - it's fast!


6. TROUBLESHOOTING
------------------
"Won't Open" (Windows):
• Right-click VaultKey.bat → Run as Administrator
• Check if antivirus is blocking it
• Try the PowerShell version instead

"Won't Open" (Mac):
• Right-click → Open (bypasses security warning)
• Go to System Preferences → Security → Open Anyway
• Make sure the file has execute permissions

"Forgot Master Password":
• Unfortunately, it cannot be recovered
• You'll need to start fresh with a new vault
• This is what keeps your passwords secure!

"Can't Find a Password":
• Try searching with just part of the name
• Check if you typed it differently
• Browse all passwords with option 3


7. SECURITY INFORMATION
-----------------------
• Encryption: AES-256 (military-grade)
• Your master password is NEVER stored
• All data stays on YOUR computer
• No internet connection required
• Open source and auditable

Your passwords are safe with VaultKey!
EOF

# Create quick reference cards
cat > $PACKAGE_DIR/Documentation/Quick-Reference-Windows.txt << 'EOF'
WINDOWS QUICK REFERENCE
=======================
Start: Double-click VaultKey.bat
Add Password: Press 2
Find Password: Press 1
Copy Password: Press 4
Exit: Press 0

Shortcut: Create a desktop shortcut to VaultKey.bat
EOF

cat > $PACKAGE_DIR/Documentation/Quick-Reference-Mac.txt << 'EOF'
MAC QUICK REFERENCE
===================
Start: Double-click VaultKey.command
Add Password: Press 2
Find Password: Press 1  
Copy Password: Press 4
Exit: Press 0

Tip: Add to Dock for easy access
EOF

# Create installation helper for Windows
cat > $PACKAGE_DIR/Windows/Install-Windows.bat << 'EOF'
@echo off
echo Installing VaultKey...
echo.

:: Create desktop shortcut
set DESKTOP=%USERPROFILE%\Desktop
copy VaultKey.bat "%DESKTOP%\VaultKey.lnk" 2>nul

:: Create Start Menu entry
set STARTMENU=%APPDATA%\Microsoft\Windows\Start Menu\Programs
mkdir "%STARTMENU%\VaultKey" 2>nul
copy VaultKey.bat "%STARTMENU%\VaultKey\VaultKey.lnk" 2>nul

echo Installation complete!
echo.
echo You can now:
echo - Use the desktop shortcut
echo - Find VaultKey in your Start Menu
echo - Run VaultKey.bat from this folder
echo.
pause
EOF

echo "✅ Universal package structure created!"
echo ""
echo "⚠️  IMPORTANT: You still need to add the Windows executable!"
echo "   Options:"
echo "   1. Build on a Windows machine/VM"
echo "   2. Use GitHub Actions to build"
echo "   3. Use Wine on Mac (less reliable)"
echo ""
echo "📁 Package location: $PACKAGE_DIR"