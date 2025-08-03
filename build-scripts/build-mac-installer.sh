#!/bin/bash
echo "🔨 Building VaultKey macOS Installer..."
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
if [ ! -f "$PROJECT_ROOT/dist/VaultKey" ]; then
    echo "❌ Error: No executable found at dist/VaultKey"
    echo "   Run PyInstaller first or download from GitHub Actions"
    exit 1
fi
BUILD_DIR="$PROJECT_ROOT/dist/mac-installer"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"/{build/usr/local/bin,scripts,resources}
echo "📁 Working directory: $BUILD_DIR"
cp "$PROJECT_ROOT/dist/VaultKey" "$BUILD_DIR/build/usr/local/bin/vaultkey"
chmod +x "$BUILD_DIR/build/usr/local/bin/vaultkey"
cd "$BUILD_DIR/build/usr/local/bin"
ln -s vaultkey VaultKey
ln -s vaultkey vk
cd "$BUILD_DIR"
cat > scripts/postinstall << 'EOFSCRIPT'
#!/bin/bash
# Create command aliases
ln -sf /usr/local/bin/vaultkey /usr/local/bin/VaultKey
ln -sf /usr/local/bin/vaultkey /usr/local/bin/vk
APP_DIR="/Applications/VaultKey.app"
mkdir -p "$APP_DIR/Contents/MacOS"
mkdir -p "$APP_DIR/Contents/Resources"
cat > "$APP_DIR/Contents/MacOS/VaultKey" << 'EOFAPP'
#!/bin/bash
osascript -e 'tell app "Terminal" to do script "/usr/local/bin/vk interactive"'
EOFAPP
chmod +x "$APP_DIR/Contents/MacOS/VaultKey"
cat > "$APP_DIR/Contents/Info.plist" << 'EOFPLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>VaultKey</string>
    <key>CFBundleIdentifier</key>
    <string>com.vaultkey.app</string>
    <key>CFBundleName</key>
    <string>VaultKey</string>
    <key>CFBundleDisplayName</key>
    <string>VaultKey Password Manager</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>LSMinimumSystemVersion</key>
    <string>10.10</string>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
EOFPLIST
cat > "$HOME/Desktop/VaultKey.command" << 'EOFCMD'
#!/bin/bash
/usr/local/bin/vk interactive
EOFCMD
chmod +x "$HOME/Desktop/VaultKey.command"
echo "VaultKey has been installed successfully!"
exit 0
EOFSCRIPT
chmod +x scripts/postinstall
cat > resources/welcome.txt << 'EOFWELCOME'
Welcome to VaultKey Password Manager!

This installer will:
- Install VaultKey with these commands:
  - vk (short version)
  - vaultkey (full version)
  - VaultKey (capital version)
- Create VaultKey app in your Applications folder  
- Add a shortcut to your Desktop
- Make VaultKey available from Terminal

After installation you can use any of:
- vk interactive
- vaultkey interactive
- VaultKey interactive

First time? Run 'vk init' to create your vault!
EOFWELCOME
cat > resources/readme.txt << 'EOFREADME'
VaultKey Password Manager
========================

Quick Start:
1. Open Terminal or click VaultKey in Applications
2. Run: vk init (first time only)
3. Create a master password (REMEMBER IT!)
4. Start adding passwords!

Available Commands:
All these commands work the same:
- vk              - Short version
- vaultkey        - Full version  
- VaultKey        - Capital version

Common Usage:
- vk interactive    - Start interactive mode
- vk add           - Add a password
- vk get <site>    - Get a password
- vk search <term> - Search passwords
- vk cp <site>     - Copy password to clipboard

Examples:
- vk add github
- vk cp gmail
- vk search amazon

Your passwords are encrypted locally.
They never leave your computer!
EOFREADME
echo "📦 Building component package..."
pkgbuild --root build \
         --scripts scripts \
         --identifier com.vaultkey.cli \
         --version 1.0.0 \
         --install-location / \
         VaultKey-component.pkg
echo "📦 Building final installer..."
productbuild --package VaultKey-component.pkg \
             --identifier com.vaultkey \
             --version 1.0.0 \
             --resources resources \
             VaultKey-Installer.pkg
rm VaultKey-component.pkg
OUTPUT_DIR="$PROJECT_ROOT/dist/installers"
mkdir -p "$OUTPUT_DIR"
mv VaultKey-Installer.pkg "$OUTPUT_DIR/"
echo "💿 Creating DMG..."
DMG_DIR="$BUILD_DIR/dmg"
mkdir -p "$DMG_DIR"
cp "$OUTPUT_DIR/VaultKey-Installer.pkg" "$DMG_DIR/"
cp resources/readme.txt "$DMG_DIR/README.txt"
cat > "$DMG_DIR/How to Install.txt" << 'EOFINSTALL'
How to Install VaultKey
======================

1. Double-click "VaultKey-Installer.pkg"
2. Follow the installation wizard
3. Enter your Mac password when prompted
4. Installation complete!

You can now use VaultKey with any of these commands:
- vk              (recommended - short and easy!)
- vaultkey        (full command)
- VaultKey        (capital version)

Quick Start:
- Open Terminal
- Type: vk init
- Create your master password
- Start using: vk interactive

Or find VaultKey in your Applications folder!
EOFINSTALL
hdiutil create -volname "VaultKey Installer" \
               -srcfolder "$DMG_DIR" \
               -ov -format UDZO \
               "$OUTPUT_DIR/VaultKey-Installer.dmg"
rm -rf "$BUILD_DIR"
echo ""
echo "✅ Build complete!"
echo ""
echo "📦 Installer package: $OUTPUT_DIR/VaultKey-Installer.pkg"
echo "💿 DMG installer: $OUTPUT_DIR/VaultKey-Installer.dmg"
echo ""
echo "The installer creates these commands:"
echo "  • vk (short version)"
echo "  • vaultkey (full version)"
echo "  • VaultKey (capital version)"
echo ""
echo "Share either file with your family - they just double-click to install!"
