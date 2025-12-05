Project Proposal — Secure File Encryption System
Team Members

Ernur Zinelov — Lead Developer / Cryptography Engineer
GitHub: @yourusername

Shynggyskhan Kumkay — Developer / Documentation & Testing Engineer
GitHub: @teammateusername

Project Option

Option 2 — Secure File Encryption & Signing System

Project Title

Secure File Encryption and Digital Signature System

Brief Description

This project implements a secure file encryption and digital signing system using modern cryptographic algorithms.
Users can encrypt/decrypt files, generate and manage cryptographic keys, sign files, verify signatures, and compute hashes.
The system is fully terminal-based and uses a modular Python architecture.

Cryptographic Components

AES-256 (GCM) — authenticated symmetric encryption

Scrypt / Argon2 KDF — password-based key derivation

RSA-2048 — keypair for signing and key encryption

SHA-256 — hashing files and signature input

AES Key Storage (KMS) — secure key generation and management

Architecture Overview

The system is divided into modules:

CLI Interface: Handles user interaction and menu logic

Symmetric Crypto Module: AES-GCM encryption, decryption, hashing

Asymmetric Crypto Module: RSA keypair generation, signing, verification

KMS Module: Key Manager for AES and RSA

Utilities & Helpers: Non-essential helpers for modularity

The project follows a clean folder structure under the src/ directory.
