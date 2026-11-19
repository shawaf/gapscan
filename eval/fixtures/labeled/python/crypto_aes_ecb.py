from Crypto.Cipher import AES


def encrypt(key: bytes, data: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data.ljust(32, b" "))
