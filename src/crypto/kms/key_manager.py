import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

class KeyManager:
    def __init__(self, keys_dir="keys"):
        self.keys_dir = keys_dir
        os.makedirs(self.keys_dir, exist_ok=True)

    # -----------------------------
    # AES KEY
    # -----------------------------
    def create_aes_key(self, name: str) -> str:
        key = os.urandom(32)  # AES-256
        path = os.path.join(self.keys_dir, f"{name}.aes")
        with open(path, "wb") as f:
            f.write(key)
        return path

    def load_aes_key(self, name: str) -> bytes:
        path = os.path.join(self.keys_dir, f"{name}.aes")
        if not os.path.exists(path):
            raise FileNotFoundError("AES key not found")
        with open(path, "rb") as f:
            return f.read()

    # -----------------------------
    # RSA KEYS
    # -----------------------------
    def create_rsa_keys(self, name: str, key_size: int = 2048) -> tuple:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        public_key = private_key.public_key()

        # save private
        priv_path = os.path.join(self.keys_dir, f"{name}_private.pem")
        with open(priv_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # save public
        pub_path = os.path.join(self.keys_dir, f"{name}_public.pem")
        with open(pub_path, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        return priv_path, pub_path

    def list_keys(self):
        try:
            return os.listdir(self.keys_dir)
        except Exception:
            return []

    # -----------------------------
    # Encrypt / Decrypt AES key using RSA (OAEP)
    # -----------------------------
    def encrypt_aes_key_with_rsa(self, aes_key: bytes, rsa_public_filename: str) -> bytes:
        pub_path = os.path.join(self.keys_dir, rsa_public_filename)
        if not os.path.exists(pub_path):
            raise FileNotFoundError("RSA public key not found.")
        with open(pub_path, "rb") as f:
            pub_pem = f.read()
        pub = serialization.load_pem_public_key(pub_pem)
        encrypted = pub.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted

    def decrypt_aes_key_with_rsa(self, encrypted_key: bytes, rsa_private_filename: str) -> bytes:
        priv_path = os.path.join(self.keys_dir, rsa_private_filename)
        if not os.path.exists(priv_path):
            raise FileNotFoundError("RSA private key not found.")
        with open(priv_path, "rb") as f:
            priv_pem = f.read()
        priv = serialization.load_pem_private_key(priv_pem, password=None)
        aes_key = priv.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return aes_key
