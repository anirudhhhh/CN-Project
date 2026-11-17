# common/crypto.py

def encrypt(data: bytes, shift: int = 3) -> bytes:
    """
    Encrypts byte data using a simple Caesar cipher.
    """
    return bytes((b + shift) % 256 for b in data)

def decrypt(data: bytes, shift: int = 3) -> bytes:
    """
    Decrypts byte data using a simple Caesar cipher.
    """
    return bytes((b - shift) % 256 for b in data)
