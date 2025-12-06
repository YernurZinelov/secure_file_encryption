"""
Entry point for the Secure File Encryption System.

This module launches the CLI interface which exposes:
- AES encryption/decryption
- RSA signing and verification
- SHA-256 hashing
- Key management operations
- Hybrid encryption (RSA-wrapped AES keys)
"""

from app.cli import run_cli

if __name__ == '__main__':
    run_cli()
