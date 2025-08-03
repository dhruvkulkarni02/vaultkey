from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="vaultkey-cli",  # Add -cli to avoid name conflicts on PyPI
    version="0.1.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="A secure, locally-encrypted password manager with beautiful CLI",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/vaultkey",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: End Users/Desktop",
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Environment :: Console",
    ],
    python_requires=">=3.8",
    install_requires=[
        "cryptography>=41.0.0",
        "click>=8.0.0",
        "tabulate>=0.9.0",
        "pyperclip>=1.8.0",  # Include by default for better UX
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov",
            "black",
            "flake8",
            "build",  # For building distributions
            "twine",  # For uploading to PyPI
        ],
    },
    entry_points={
        "console_scripts": [
            "vaultkey=vaultkey.cli:cli",
            "vk=vaultkey.cli:cli",  # Short alias
        ],
    },
    keywords="password manager security encryption cli vault",
    project_urls={
        "Bug Reports": "https://github.com/yourusername/vaultkey/issues",
        "Source": "https://github.com/yourusername/vaultkey",
        "Documentation": "https://github.com/yourusername/vaultkey#readme",
    },
)