#!/bin/bash
# Publish VaultKey to PyPI or TestPyPI

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check arguments
if [[ $# -eq 0 ]]; then
    echo "Usage: ./publish.sh [test|prod]"
    echo ""
    echo "  test  - Upload to TestPyPI (recommended first)"
    echo "  prod  - Upload to PyPI (production)"
    exit 1
fi

MODE=$1

# Check if dist/ exists
if [[ ! -d "dist" ]]; then
    print_error "No dist/ directory found. Run ./build.sh first."
    exit 1
fi

# Check if files exist in dist/
if [[ -z "$(ls -A dist/)" ]]; then
    print_error "No files in dist/ directory. Run ./build.sh first."
    exit 1
fi

# Check if twine is available (prefer venv version)
if [[ -f "./venv/bin/twine" ]]; then
    TWINE_CMD="./venv/bin/twine"
    print_status "Using virtual environment twine"
elif command -v twine &> /dev/null; then
    TWINE_CMD="twine"
    print_status "Using system twine"
else
    print_error "twine not found. Install with: pip install twine"
    exit 1
fi

if [[ "$MODE" == "test" ]]; then
    print_status "📤 Uploading to TestPyPI..."
    print_warning "This will upload to TestPyPI (test.pypi.org)"
    read -p "Continue? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        $TWINE_CMD upload --repository testpypi dist/*
        print_success "✅ Uploaded to TestPyPI!"
        echo ""
        echo "🧪 Test installation:"
        echo "pip install --index-url https://test.pypi.org/simple/ vaultkey-cli"
        echo ""
        echo "🔗 View on TestPyPI:"
        echo "https://test.pypi.org/project/vaultkey-cli/"
    else
        print_warning "Upload cancelled."
    fi

elif [[ "$MODE" == "prod" ]]; then
    print_status "📤 Uploading to PyPI (PRODUCTION)..."
    print_warning "⚠️  This will upload to PRODUCTION PyPI!"
    print_warning "⚠️  Make sure you've tested on TestPyPI first!"
    echo ""
    read -p "Are you absolutely sure? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        read -p "Type 'CONFIRM' to proceed: " confirm
        if [[ "$confirm" == "CONFIRM" ]]; then
            $TWINE_CMD upload dist/*
            print_success "🎉 Successfully uploaded to PyPI!"
            echo ""
            echo "🌟 Installation command:"
            echo "pip install vaultkey-cli"
            echo ""
            echo "🔗 View on PyPI:"
            echo "https://pypi.org/project/vaultkey-cli/"
            echo ""
            echo "🎯 Don't forget to:"
            echo "1. Create a GitHub release"
            echo "2. Update documentation"
            echo "3. Announce on social media"
        else
            print_warning "Upload cancelled - confirmation not matched."
        fi
    else
        print_warning "Upload cancelled."
    fi

else
    print_error "Invalid mode: $MODE"
    echo "Use 'test' or 'prod'"
    exit 1
fi
