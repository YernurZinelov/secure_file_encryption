# Security Analysis

## 1. Security Goals

- **Confidentiality:** AES-256-GCM for secure encryption.  
- **Integrity:** GCM authentication + SHA-256 hashing.  
- **Authenticity:** RSA-PSS digital signatures.  
- **Key Protection:** KMS manages AES and RSA keys.  
- **Secure Key Transport:** RSA-OAEP wraps AES keys (hybrid encryption).

---

## 2. Threat Model

### 2.1 Assets
- AES encryption keys  
- RSA private keys  
- Encrypted files  
- User passwords  

### 2.2 Adversaries
- Local attacker with access to file system  
- Network interceptor (if files are sent externally)  
- Malicious user attempting tampering or forgery  

### 2.3 Attack Vectors
- Password brute-force  
- File tampering  
- Replacement of public keys  
- Key theft (AES/RSA)  
- Replay attacks with old encrypted keys  
- Malicious signature injection

---

## 3. Security Assumptions

- User machine is not compromised (no malware).  
- RSA private keys are kept offline and protected.  
- Users choose sufficiently strong passwords.  
- Keys stored in `keys/` folder are protected by OS permissions.

---

## 4. Mitigation Strategies

| Threat | Mitigation |
|-------|------------|
| Password brute force | Scrypt KDF (memory-hard) |
| File tampering | AES-GCM integrity + SHA-256 |
| Signature forgery | RSA-PSS strong padding |
| Key theft | Separate AES/RSA key directories |
| Tampered AES key during transport | RSA-OAEP encryption |
| Incorrect public key use | Explicit user choice + warnings |

---

## 5. Potential Vulnerabilities

- Keys in `keys/` directory are unencrypted (user responsibility).  
- If attacker compromises OS, keys can be stolen.  
- User may choose weak password (KDF reduces risk but not eliminates).  
- CBC mode issues avoided because system uses GCM only.  

---

## 6. Security Recommendations

- Store RSA private keys in a secure offline directory.  
- Use long, unique passwords.  
- Delete decrypted files after use.  
- Enable file system encryption (BitLocker, etc.).  
- Rotate AES keys periodically.
