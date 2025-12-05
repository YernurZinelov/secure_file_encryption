# User Manual

## 1. Installation

python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt


---

## 2. Starting the Program

python src/main.py


This launches the interactive menu.

---

## 3. Available Operations

### 1. Encrypt File (Password)
Encrypt any file using AES-256-GCM:

1 → enter filepath → enter password
Output: file.ext.enc


### 2. Decrypt File (Password)

2 → enter .enc file → enter password
Output: file.ext.dec


### 3. Sign File

3 → enter file → enter private key filename
Output: file.sig


### 4. Verify Signature

4 → file → signature.sig → public key filename


### 5. Hash File (SHA-256)
Prints file hash.

### 6. Generate AES Key (KMS)

6 → enter key name
Creates: keys/<name>.aes


### 7. Generate RSA Keypair (KMS)

7 → enter name
Creates: <name>_private.pem + <name>_public.pem


### 8. List Keys
Displays all AES and RSA keys in `keys/`.

### 9. Encrypt File Using KMS AES Key (Hybrid)

9 → file → AES key name
Output: file.kenc


### 10. Encrypt AES Key with RSA Public Key

10 → AES key → RSA public key
Output: keyname.key.enc


### 11. Decrypt AES Key with RSA Private Key

11 → encrypted key → RSA private key


---

## 4. Notes
- RSA private keys are **not encrypted** — protect them.  
- `.kenc` files require AES key to decrypt.  
- `.enc` files require password to decrypt.
