# System Architecture Documentation

## 1. Overview

The Secure File Encryption System is structured into three primary layers:

1. **Application Layer (CLI)** – User interaction, input validation, error handling.  
2. **Cryptographic Layer** – AES, RSA, SHA-256, signatures, KDF, hybrid encryption.  
3. **Key Management System (KMS)** – Secure generation, storage, and retrieval of AES and RSA keys.

The system is fully modular: each cryptographic operation resides in a dedicated module.

---

## 2. Module Responsibilities

### 2.1 `app/cli.py`
- Main interface for the user  
- Calls cryptographic functions  
- Handles menus, prompts, errors  
- Orchestrates hybrid encryption workflow

### 2.2 `crypto/symmetric.py`
- AES-256-GCM encryption/decryption  
- Scrypt key derivation  
- File handling, salt/nonce management  
- Hashing via SHA-256  
- AES-key-based hybrid encryption functions

### 2.3 `crypto/asymmetric.py`
- RSA-2048 key generation  
- RSA-PSS digital signatures  
- RSA-OAEP encryption/decryption for AES keys  
- PEM serialization

### 2.4 `crypto/kms/key_manager.py`
- Creates and stores AES keys  
- Creates RSA private/public keypairs  
- Encrypts AES keys with RSA public keys  
- Decrypts AES keys using RSA private keys  
- Lists all stored keys  
- Ensures separation of key material

---

## 3. Data Flow (High-Level)

### Password-based Encryption

File → Scrypt(password) → AES-GCM encrypt → output.enc


### Password-based Decryption

output.enc → extract salt/nonce → Scrypt(password) → AES-GCM decrypt → file.dec


### Hybrid Encryption (KMS AES Key)

File → AES key (from KMS) → AES-GCM → file.kenc
AES key → RSA public key → encrypted_key.bin


### Signature Workflow

Sign: File → SHA-256 digest → RSA-PSS(private) → signature.sig
Verify: File + signature.sig + RSA public key → VALID / INVALID


---

## 4. File Formats

### AES-GCM with Password

[16 bytes salt] + [12 bytes nonce] + [ciphertext]


### AES-GCM with AES Key (KMS)

[12 bytes nonce] + [ciphertext]


### RSA-Encrypted AES Key

OAEP-encrypted key bytes


---

## 5. Extensibility

The system can easily be extended with:
- GUI frontend  
- Encrypted key vault for KMS  
- Switching AES-GCM → ChaCha20-Poly1305  
- ECDSA/Ed25519 signatures  
- Adding Argon2id KDF  
