from crypto.kms.key_manager import KeyManager

def test_kms_aes_key():
    kms = KeyManager()
    kms.create_aes_key("testkey")
    key = kms.load_aes_key("testkey")
    assert len(key) == 32
