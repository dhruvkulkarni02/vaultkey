#!/bin/bash
# Global Installation Script for VaultKey

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_status "Installing VaultKey globally..."

# Check if pip is available
if ! command -v pip3 &> /dev/null; then
    print_error "pip3 not found. Please install Python 3 and pip first."
    exit 1
fi

# Install from current directory
pip3 install --user .

print_success "VaultKey installed globally!"
echo ""
echo "🎉 You can now use these commands from anywhere:"
echo "   vaultkey --help"
echo "   vk --help"
echo ""
echo "💡 If commands are not found, you may need to add ~/.local/bin to your PATH:"
echo "   echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.zshrc"
echo "   source ~/.zshrc"
