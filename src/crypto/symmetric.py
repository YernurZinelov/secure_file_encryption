"""
Symmetric cryptography module.

Provides:
- AES-256-GCM encryption/decryption
- Scrypt password-based key derivation
- SHA-256 file hashing
"""

import os
import hashlib
from typing import Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


# --------- Key derivation (Scrypt) ----------

"""
    Derive a 256-bit key from password using Scrypt KDF.

    Args:
        password (str): User password.
        salt (bytes): Optional existing salt. If None, a new salt is generated.

    Returns:
        (bytes, bytes): Tuple containing (key, salt).
    """

def derive_key(password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
    """
    Derive a 32-byte key from password using scrypt.
    Returns (key, salt).
    """
    if salt is None:
        salt = os.urandom(16)
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    key = kdf.derive(password.encode())
    return key, salt


# --------- Password-based file encryption (AES-GCM) ----------

"""
    Encrypt a file using AES-256-GCM.

    Args:
        filepath (str): Path to the file to encrypt.
        password (str): Password used to derive AES key.

    Returns:
        str: Path to the encrypted output file.
    """

def encrypt_file(filepath: str, password: str) -> str:
    """
    Password-based encryption. Output file contains: salt (16) || nonce (12) || ciphertext
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError("Input file not found.")

    with open(filepath, 'rb') as f:
        data = f.read()

    key, salt = derive_key(password)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)

    out_path = filepath + ".enc"
    with open(out_path, "wb") as f:
        f.write(salt + nonce + ciphertext)
    return out_path


"""
    Decrypt an AES-GCM encrypted file.

    Args:
        enc_filepath (str): Path to encrypted file.
        password (str): Password for key derivation.

    Returns:
        str: Path to decrypted file.
    """

def decrypt_file(enc_filepath: str, password: str) -> str:
    if not os.path.exists(enc_filepath):
        raise FileNotFoundError("Encrypted file not found.")

    with open(enc_filepath, "rb") as f:
        content = f.read()

    if len(content) < 28:
        raise ValueError("Invalid encrypted file format.")

    salt = content[:16]
    nonce = content[16:28]
    ciphertext = content[28:]

    key, _ = derive_key(password, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    out_path = enc_filepath.replace(".enc", ".dec")
    with open(out_path, "wb") as f:
        f.write(plaintext)
    return out_path


# --------- AES key based encryption (used for hybrid mode) ----------
def encrypt_file_with_aes_key(filepath: str, aes_key: bytes) -> str:
    """
    Encrypt using a provided AES key (32 bytes). Output: nonce || ciphertext
    Caller should store/encrypt AES key separately (hybrid).
    """
    if len(aes_key) != 32:
        raise ValueError("AES key must be 32 bytes (AES-256).")
    if not os.path.exists(filepath):
        raise FileNotFoundError("Input file not found.")

    with open(filepath, "rb") as f:
        data = f.read()

    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)

    out_path = filepath + ".kenc"  # indicates key-based encryption
    with open(out_path, "wb") as f:
        f.write(nonce + ciphertext)
    return out_path


def decrypt_file_with_aes_key(enc_filepath: str, aes_key: bytes) -> str:
    if len(aes_key) != 32:
        raise ValueError("AES key must be 32 bytes (AES-256).")
    if not os.path.exists(enc_filepath):
        raise FileNotFoundError("Encrypted file not found.")

    with open(enc_filepath, "rb") as f:
        content = f.read()

    if len(content) < 12:
        raise ValueError("Invalid encrypted file format.")

    nonce = content[:12]
    ciphertext = content[12:]
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    out_path = enc_filepath.replace(".kenc", ".dec")
    with open(out_path, "wb") as f:
        f.write(plaintext)
    return out_path


# --------- File hashing ----------

"""
    Compute SHA-256 hash of a file.

    Args:
        filepath (str): File path.

    Returns:
        str: Hex digest of file contents.
    """

def hash_file(filepath: str) -> str:
    if not os.path.exists(filepath):
        raise FileNotFoundError("File not found.")
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()
