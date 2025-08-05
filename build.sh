#!/bin/bash
# Build and upload script for VaultKey PyPI distribution

set -e  # Exit on any error

echo "🚀 VaultKey PyPI Build & Upload Script"
echo "======================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
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

# Check if virtual environment is activated
if [[ "$VIRTUAL_ENV" == "" ]]; then
    print_warning "Virtual environment not detected. Activating venv..."
    source venv/bin/activate
fi

# Install build dependencies
print_status "Installing build dependencies..."
pip install --upgrade build twine setuptools wheel

# Clean previous builds
print_status "Cleaning previous builds..."
rm -rf build/ dist/ *.egg-info/

# Run security checks (optional)
if command -v bandit &> /dev/null; then
    print_status "Running security analysis with bandit..."
    bandit -r vaultkey/ -f json -o security-report.json || print_warning "Security issues found, check security-report.json"
fi

# Build the package
print_status "Building package..."
python -m build

# Check the built package
print_status "Checking package..."
twine check dist/*

# Show build results
print_success "Build completed successfully!"
echo ""
echo "📦 Built packages:"
ls -la dist/

echo ""
echo "🔍 Package info:"
python -c "
import pkg_resources
from pathlib import Path

# Find the wheel file
wheel_file = next(Path('dist').glob('*.whl'))
print(f'Package: {wheel_file.name}')

# Extract package info
try:
    import zipfile
    with zipfile.ZipFile(wheel_file, 'r') as zip_ref:
        metadata = [f for f in zip_ref.namelist() if f.endswith('METADATA')]
        if metadata:
            with zip_ref.open(metadata[0]) as meta_file:
                content = meta_file.read().decode('utf-8')
                for line in content.split('\n')[:10]:  # First 10 lines
                    if line.strip():
                        print(line)
except Exception as e:
    print(f'Could not read metadata: {e}')
"

echo ""
echo "🎯 Next steps:"
echo "1. Test install: pip install dist/*.whl"
echo "2. Upload to TestPyPI: ./publish.sh test"
echo "3. Upload to PyPI: ./publish.sh prod"

print_success "Ready for publication! 🚀"
