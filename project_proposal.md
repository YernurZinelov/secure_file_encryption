# Project Proposal — Secure File Encryption System

## Team Members
- **Ernur Zinelov** — Lead Developer / Cryptography Engineer  
- **Shynggyskhan Kumkay** — Developer / Documentation & Testing Engineer  

## Project Option
**Option 2 — Secure File Encryption & Signing System**

## Project Title
Secure File Encryption and Digital Signature System

## Brief Description
This project implements a command-line tool that performs secure file encryption, decryption, hashing, and digital signing.  
It uses AES-256 for symmetric encryption, RSA-2048 for digital signatures, and a Key Management System (KMS) to securely generate and store cryptographic keys.

## Cryptographic Components
- AES-256-GCM — file encryption  
- Scrypt — password-based key derivation  
- RSA-2048 — keypair generation & signatures  
- SHA-256 — hashing  
- KMS — AES/RSA key storage and hybrid key wrapping  

## Architecture Overview

src/
├── main.py
├── app/
│ └── cli.py
├── crypto/
│ ├── symmetric.py
│ ├── asymmetric.py
│ └── kms/
│ └── key_manager.py
└── docs/
└── project_proposal.md


## Team Responsibilities
**Ernur Zinelov**
- AES encryption/decryption  
- RSA signing/verification  
- Hybrid encryption implementation  
- CLI logic & orchestration  
- Core cryptography code  

**Shynggyskhan Kumkay**
- Documentation (proposal, architecture, security analysis)  
- Manual + basic automated testing  
- GitHub repository setup & structure  
- Presentation slide preparation  

## Planned Features
- AES file encryption/decryption  
- RSA digital signatures  
- SHA-256 hashing  
- AES/RSA key generation  
- Hybrid encryption (AES key wrapped with RSA)  
- Full CLI interface with validation  

## Deliverables
- Public GitHub repository  
- Fully working code implementation  
- Documentation: README, architecture, security analysis, user guide  
- Presentation + demo  

