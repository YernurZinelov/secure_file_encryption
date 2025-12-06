from crypto.kms.key_manager import KeyManager
from crypto.asymmetric import sign_file, verify_file
import os

def test_sign_verify():
    # Setup key manager
    kms = KeyManager()
    kms.create_rsa_keys("test_rsa")

    # create file
    with open("msg.txt", "w") as f:
        f.write("testing")

    signature = sign_file("msg.txt", "keys/test_rsa_private.pem")
    assert verify_file("msg.txt", signature, "keys/test_rsa_public.pem")
