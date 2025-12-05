# Testing Documentation

## 1. Objective
To verify correct functionality of:
- Password-based AES encryption/decryption  
- Hybrid AES/RSA encryption  
- Digital signatures and verification  
- KMS key handling  
- Hashing and CLI behavior  

---

## 2. Environment
- Python 3.10+  
- Windows 10/11  
- cryptography 46.0.3  

---

## 3. Test Cases & Results

### 3.1 AES Password Encryption/Decryption
**Input:** text file with known content  
**Steps:**  
1 → encrypt using password  
2 → decrypt using same password  
**Expected:** decrypted file matches original  
**Result:** ✔ Pass

---

### 3.2 AES Password Wrong Password
Decrypt using incorrect password.  
**Expected:** decryption fails  
**Result:** ✔ Pass (AESGCM exception handled)

---

### 3.3 KMS AES Key Creation
6 → name = "testkey"  
**Expected:** keys/testkey.aes exists  
**Result:** ✔ Pass

---

### 3.4 Hybrid File Encryption
9 → use AES key  
**Expected:** output .kenc file  
**Result:** ✔ Pass

---

### 3.5 RSA Keypair Generation
7 → name = "alice"  
**Expected:** alice_private.pem and alice_public.pem  
**Result:** ✔ Pass

---

### 3.6 RSA Encryption of AES Key
10 → AES key + alice_public.pem  
**Expected:** .key.enc produced  
**Result:** ✔ Pass

---

### 3.7 RSA Decryption of AES Key
11 → encrypted key + alice_private.pem  
**Expected:** AES key restored  
**Result:** ✔ Pass

---

### 3.8 Digital Signatures
**Sign + Verify workflow** works; invalid signatures detect properly.  
✔ Pass

---

## 4. Additional Notes
- Manual testing performed for all CLI menu paths.  
- No unhandled exceptions encountered.  
- Error messages display correctly.
