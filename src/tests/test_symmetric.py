import os
from crypto.symmetric import encrypt_file, decrypt_file, hash_file

def test_encrypt_decrypt():
    # create sample file
    with open("sample.txt", "w") as f:
        f.write("hello world")

    enc = encrypt_file("sample.txt", "password123")
    dec = decrypt_file(enc, "password123")

    assert os.path.exists(enc)
    assert os.path.exists(dec)

    with open(dec, "r") as f:
        assert f.read() == "hello world"


def test_hash():
    with open("sample2.txt", "w") as f:
        f.write("abc")

    h = hash_file("sample2.txt")
    assert len(h) == 64  # SHA-256 hex digest
