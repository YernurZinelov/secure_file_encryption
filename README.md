# Secure File Encryption System

A Python-based cryptographic application that provides secure file encryption, decryption, digital signatures, hashing, and key management (KMS).  
The system supports both **password-based encryption (AES-GCM)** and **hybrid encryption** using **AES + RSA**.

---

## 🔐 Features

### Symmetric Cryptography
- AES-256-GCM authenticated encryption  
- Scrypt key derivation (password → AES key)  
- Nonce and salt generation  
- Secure file format: `salt || nonce || ciphertext`

### Asymmetric Cryptography
- RSA-2048 keypairs (private/public PEM files)  
- RSA-PSS digital signatures  
- RSA-OAEP encryption of AES keys (hybrid mode)

### Key Management System (KMS)
- AES key creation & storage  
- RSA keypair generation  
- RSA encryption & decryption of AES keys  
- Listing stored keys  
- File encryption using stored AES keys

### Integrity & Authentication
- SHA-256 hashing  
- Digital signature generation & verification

### Interface
- Fully interactive CLI  
- Error handling & validation

---

## 📁 Project Structure:

project/
│ README.md
│ architecture.md
│ security.md
│ user_manual.md
│ testing.md
│ LICENSE
│ requirements.txt
└── src/
├── main.py
├── app/
│ └── cli.py
└── crypto/
├── symmetric.py
├── asymmetric.py
└── kms/
└── key_manager.py


---

## ▶️ Installation

```bash
git clone <your_repo_link>
cd project
python -m venv venv
venv\Scripts\activate      # Windows
pip install -r requirements.txt


## ▶️ Run the Application

python src/main.py

(This will open an interactive menu with encryption, decryption, key generation, signatures, and hybrid encryption options).
