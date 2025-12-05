import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature

# --------- RSA key generation using cryptography ----------
def generate_rsa_keys(name: str, save_dir: str = "keys", key_size: int = 2048):
    os.makedirs(save_dir, exist_ok=True)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()

    priv_path = os.path.join(save_dir, f"{name}_private.pem")
    pub_path = os.path.join(save_dir, f"{name}_public.pem")

    with open(priv_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),  # could add password encryption
        ))

    with open(pub_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    return priv_path, pub_path


# --------- Sign file ----------
def sign_file(filepath: str, private_key_path: str) -> bytes:
    if not os.path.exists(filepath):
        raise FileNotFoundError("File to sign not found.")
    if not os.path.exists(private_key_path):
        raise FileNotFoundError("Private key not found.")

    with open(filepath, "rb") as f:
        data = f.read()
    with open(private_key_path, "rb") as f:
        priv_pem = f.read()

    priv = serialization.load_pem_private_key(priv_pem, password=None)
    signer = priv.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signer


# --------- Verify signature ----------
def verify_file(filepath: str, signature: bytes, public_key_path: str) -> bool:
    if not os.path.exists(filepath):
        raise FileNotFoundError("File to verify not found.")
    if not os.path.exists(public_key_path):
        raise FileNotFoundError("Public key not found.")

    with open(filepath, "rb") as f:
        data = f.read()
    with open(public_key_path, "rb") as f:
        pub_pem = f.read()

    pub = serialization.load_pem_public_key(pub_pem)
    try:
        pub.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
