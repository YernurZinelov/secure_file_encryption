"""
Command-line interface for the Secure File Encryption System.

Handles:
- User input
- Calling cryptographic operations
- Key management interactions
- Output formatting and error handling
"""

import os
import sys
from crypto.symmetric import (
    encrypt_file,
    decrypt_file,
    hash_file,
    encrypt_file_with_aes_key,
    decrypt_file_with_aes_key,
)
from crypto.asymmetric import (
    generate_rsa_keys,
    sign_file,
    verify_file,
)
from crypto.kms.key_manager import KeyManager

# ensure keys dir exists
os.makedirs("keys", exist_ok=True)
kms = KeyManager(keys_dir="keys")

"""
    Print the main menu and return user's choice.
    """

def print_menu():
    print("\n=== Secure File Encryption System ===")
    print("1. Encrypt file (password-based)")
    print("2. Decrypt file (password-based)")
    print("3. Sign file")
    print("4. Verify signature")
    print("5. Calculate SHA-256 hash")
    print("6. Generate AES key (KMS)")
    print("7. Generate RSA keypair (KMS)")
    print("8. List stored keys (KMS)")
    print("9. Encrypt file using AES key from KMS (hybrid)")
    print("10. Encrypt AES key with RSA public key (KMS)")
    print("11. Decrypt AES key with RSA private key (KMS)")
    print("0. Exit")
    return input("Choose option: ")

"""
    Main loop for CLI interface.
    Controls user interaction and executes operations.
    """

def run_cli():
    while True:
        try:
            choice = print_menu()

            # ENCRYPT (password-based)
            if choice == "1":
                filepath = input("Enter file path: ").strip()
                password = input("Enter password: ")
                out = encrypt_file(filepath, password)
                print(f"Encrypted file saved as: {out}")

            # DECRYPT (password-based)
            elif choice == "2":
                filepath = input("Enter encrypted file path: ").strip()
                password = input("Enter password: ")
                out = decrypt_file(filepath, password)
                print(f"Decrypted file saved as: {out}")

            # SIGN
            elif choice == "3":
                filepath = input("Enter file path: ").strip()
                priv_key_path = input("Enter private key filename (in keys/, e.g. name_private.pem): ").strip()
                priv_key_path = os.path.join("keys", priv_key_path)
                signature = sign_file(filepath, priv_key_path)
                sig_file = filepath + ".sig"
                with open(sig_file, "wb") as f:
                    f.write(signature)
                print("Signature saved as:", sig_file)

            # VERIFY SIGNATURE
            elif choice == "4":
                filepath = input("Enter file path: ").strip()
                sig_path = input("Enter signature file path (.sig): ").strip()
                pub_key_name = input("Enter public key filename (in keys/, e.g. name_public.pem): ").strip()
                pub_key_path = os.path.join("keys", pub_key_name)
                if not os.path.exists(sig_path):
                    print("Signature file not found.")
                    continue
                with open(sig_path, "rb") as f:
                    sig = f.read()
                ok = verify_file(filepath, sig, pub_key_path)
                print("Signature valid!" if ok else "Signature INVALID")

            # HASH FILE
            elif choice == "5":
                filepath = input("Enter file path: ").strip()
                h = hash_file(filepath)
                print("SHA-256:", h)

            # KMS – AES KEY
            elif choice == "6":
                name = input("Enter AES key name: ").strip()
                path = kms.create_aes_key(name)
                print("AES key saved at:", path)

            # KMS – RSA KEYS
            elif choice == "7":
                name = input("Enter RSA key name prefix: ").strip()
                kms.create_rsa_keys(name)
                print("RSA keypair generated (in keys/). Filenames: "
                      f"{name}_private.pem, {name}_public.pem")

            # LIST KEYS
            elif choice == "8":
                print("Available keys in keys/:")
                for key in kms.list_keys():
                    print(" -", key)

            # ENCRYPT FILE WITH KMS AES KEY (hybrid full workflow)
            elif choice == "9":
                filepath = input("Enter file path to encrypt: ").strip()
                aes_name = input("Enter AES key name to use (in keys/, without extension): ").strip()
                try:
                    aes_key = kms.load_aes_key(aes_name)
                except FileNotFoundError as e:
                    print("AES key not found:", e)
                    continue
                out = encrypt_file_with_aes_key(filepath, aes_key)
                print("Encrypted (with KMS AES key) saved as:", out)
                print("Optionally encrypt the AES key with an RSA public key (menu 10).")

            # ENCRYPT AES KEY WITH RSA
            elif choice == "10":
                aes_key_name = input("Enter AES key name to encrypt (without extension): ").strip()
                rsa_pub_name = input("Enter RSA public key filename (in keys/, e.g. name_public.pem): ").strip()
                try:
                    aes_key = kms.load_aes_key(aes_key_name)
                except FileNotFoundError:
                    print("AES key not found.")
                    continue
                try:
                    encrypted_key = kms.encrypt_aes_key_with_rsa(aes_key, rsa_pub_name)
                except FileNotFoundError as e:
                    print("RSA public key not found:", e)
                    continue
                out_file = f"{aes_key_name}.key.enc"
                with open(out_file, "wb") as f:
                    f.write(encrypted_key)
                print("AES key encrypted with RSA public key ->", out_file)

            # DECRYPT AES KEY WITH RSA
            elif choice == "11":
                enc_file = input("Enter encrypted AES key file path: ").strip()
                rsa_priv_name = input("Enter RSA private key filename (in keys/, e.g. name_private.pem): ").strip()
                if not os.path.exists(enc_file):
                    print("Encrypted AES key file not found.")
                    continue
                with open(enc_file, "rb") as f:
                    encrypted_key = f.read()
                try:
                    aes_key = kms.decrypt_aes_key_with_rsa(encrypted_key, rsa_priv_name)
                except Exception as e:
                    print("Failed to decrypt AES key:", e)
                    continue
                print("AES key decrypted successfully (hex):", aes_key.hex())

            # EXIT
            elif choice == "0":
                print("Goodbye!")
                break

            else:
                print("Invalid option. Try again.")

        except KeyboardInterrupt:
            print("\nInterrupted. Exiting.")
            sys.exit(0)
        except Exception as e:
            print("Error:", e)
