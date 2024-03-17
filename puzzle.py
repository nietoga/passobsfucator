# From: https://asecuritysite.com/encryption/pow

import base64
from typing import Callable
from cryptography.fernet import Fernet
from datetime import timedelta
from time import time
from hashlib import sha256


def generate_by_time(
    seed: str,
    delta: timedelta,
    progress_callback: Callable[[int], None] | None = None,
) -> tuple[str, int]:
    start = time()
    end = start + delta.total_seconds()

    h = sha256(seed.encode()).digest()
    iters = 0

    current = start
    while current < end:
        h = sha256(h).digest()

        if progress_callback:
            progress = int((current - start) * 100 / (end - start))
            progress_callback(min(progress, 100))

        current = time()
        iters += 1

    return base64.urlsafe_b64encode(h), iters


def generate_by_iters(
    seed: str,
    iters: int,
    progress_callback: Callable[[int], None] | None = None,
) -> str:
    h = sha256(seed.encode()).digest()

    for i in range(iters):
        h = sha256(h).digest()

        if progress_callback:
            progress = int((i + 1) * 100 / iters)
            progress_callback(progress)

    return base64.urlsafe_b64encode(h)


def encrypt(
    keyseed: str,
    delta: timedelta,
    message: str,
    progress_callback: Callable[[int], None] | None = None,
) -> tuple[str, int, str]:
    key, iterations = generate_by_time(keyseed, delta, progress_callback)
    encrypted = Fernet(key).encrypt(message.encode())
    return key, iterations, encrypted


def decrypt(
    keyseed: str,
    iterations: int,
    encrypted: str,
    progress_callback: Callable[[int], None] | None = None,
) -> tuple[str, str]:
    key = generate_by_iters(keyseed, iterations, progress_callback)
    decrypted = Fernet(key).decrypt(encrypted)
    return key, decrypted
