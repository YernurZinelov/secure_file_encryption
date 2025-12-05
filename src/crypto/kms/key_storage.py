import os
from cryptography.fernet import Fernet

class KeyStorage:
    def __init__(self, storage_path="keys/"):
        self.storage_path = storage_path
        os.makedirs(storage_path, exist_ok=True)

        # master key for encrypting stored keys
        self.master_key_path = os.path.join(storage_path, "master.key")
        self.master_key = self._load_or_create_master_key()
        self.cipher = Fernet(self.master_key)

    def _load_or_create_master_key(self):
        if os.path.exists(self.master_key_path):
            return open(self.master_key_path, "rb").read()

        mk = Fernet.generate_key()
        with open(self.master_key_path, "wb") as f:
            f.write(mk)
        return mk

    def save_key(self, key_name, key_data):
        enc = self.cipher.encrypt(key_data)
        with open(os.path.join(self.storage_path, key_name), "wb") as f:
            f.write(enc)

    def load_key(self, key_name):
        data = open(os.path.join(self.storage_path, key_name), "rb").read()
        return self.cipher.decrypt(data)
