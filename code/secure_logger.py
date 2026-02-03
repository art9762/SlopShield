import os
import struct
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

class SecureLogger:
    def __init__(self, password: str):
        self.password = password.encode('utf-8')
        self.n = 16384
        self.r = 8
        self.p = 1

    def _derive_key(self, salt: bytes) -> bytes:
        kdf = Scrypt(
            salt=salt,
            length=32, 
            n=self.n,
            r=self.r,
            p=self.p,
        )
        return kdf.derive(self.password)

    def save(self, data: bytes, filepath: str):
        """
        Format: Salt (16b) | Nonce (12b) | Ciphertext (incl Tag)
        """
        salt = os.urandom(16)
        key = self._derive_key(salt)
        
        aesgcm = AESGCM(key)
        nonce = os.urandom(12) 
        
        ciphertext = aesgcm.encrypt(nonce, data, None)
        
        with open(filepath, 'wb') as f:
            f.write(salt)
            f.write(nonce)
            f.write(ciphertext)

    def load(self, filepath: str) -> bytes:
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Report file {filepath} not found.")

        with open(filepath, 'rb') as f:
            salt = f.read(16)
            nonce = f.read(12)
            ciphertext = f.read()

        key = self._derive_key(salt)
        aesgcm = AESGCM(key)

        try:
            return aesgcm.decrypt(nonce, ciphertext, None)
        except InvalidTag:
            raise ValueError("Decryption failed! Password incorrect or file corrupted/tampered.")