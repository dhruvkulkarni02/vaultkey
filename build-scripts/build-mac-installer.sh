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
cd "$BUILD_DIR"
cat > scripts/postinstall << 'EOFSCRIPT'
#!/bin/bash
APP_DIR="/Applications/VaultKey.app"
mkdir -p "$APP_DIR/Contents/MacOS"
mkdir -p "$APP_DIR/Contents/Resources"
cat > "$APP_DIR/Contents/MacOS/VaultKey" << 'EOFAPP'
#!/bin/bash
osascript -e 'tell app "Terminal" to do script "/usr/local/bin/vaultkey interactive"'
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
/usr/local/bin/vaultkey interactive
EOFCMD
chmod +x "$HOME/Desktop/VaultKey.command"
echo "VaultKey has been installed successfully!"
exit 0
EOFSCRIPT
chmod +x scripts/postinstall
cat > resources/welcome.txt << 'EOFWELCOME'
Welcome to VaultKey Password Manager!

This installer will:
- Install the 'vaultkey' command to /usr/local/bin
- Create VaultKey app in your Applications folder  
- Add a shortcut to your Desktop
- Make VaultKey available from Terminal

After installation:
- Type 'vaultkey' in Terminal from anywhere
- Double-click VaultKey in Applications
- Or use the Desktop shortcut

First time? Run 'vaultkey init' to create your vault!
EOFWELCOME
cat > resources/readme.txt << 'EOFREADME'
VaultKey Password Manager
========================

Quick Start:
1. Open Terminal or click VaultKey in Applications
2. Run: vaultkey init (first time only)
3. Create a master password (REMEMBER IT!)
4. Start adding passwords!

Commands:
- vaultkey interactive    - Start interactive mode
- vaultkey add           - Add a password
- vaultkey get <site>    - Get a password
- vaultkey search <term> - Search passwords

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

You can now:
- Find VaultKey in Applications
- Use 'vaultkey' command in Terminal
- Click the Desktop shortcut

First time? Type: vaultkey init
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
echo "Share either file with your family - they just double-click to install!"
