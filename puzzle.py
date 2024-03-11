# From: https://asecuritysite.com/encryption/pow

import base64
from cryptography.fernet import Fernet
from datetime import timedelta
from time import time
from hashlib import sha256

def generate_by_time(seed: str, delta: timedelta) -> tuple[str, int]:
    end = time() + delta.total_seconds()
    h = sha256(seed.encode()).digest()
    iters = 0
    while time() < end:
        h = sha256(h).digest()
        iters += 1
    return base64.urlsafe_b64encode(h), iters

def generate_by_iters(seed: str, iters: int) -> str:
    h = sha256(seed.encode()).digest()
    for _ in range(iters):
        h = sha256(h).digest()
    return base64.urlsafe_b64encode(h)

def encrypt(keyseed: str, delta: timedelta, message: str) -> tuple[str, int, str]:
    key, iterations = generate_by_time(keyseed, delta)
    encrypted = Fernet(key).encrypt(message.encode())
    return key, iterations, encrypted

def decrypt(keyseed: str, iterations: int, encrypted: str) -> tuple[str, str]:
    key = generate_by_iters(keyseed, iterations)
    decrypted = Fernet(key).decrypt(encrypted)
    return key, decrypted
