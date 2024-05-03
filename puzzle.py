# From: https://asecuritysite.com/encryption/pow

import base64
from typing import Callable
from cryptography.fernet import Fernet
from datetime import timedelta
from time import time
from hashlib import sha256


def generate_by_time(
    seed: bytes,
    delta: timedelta,
    progress_callback: Callable[[int], None] | None = None,
) -> tuple[bytes, int]:
    start = time()
    end = start + delta.total_seconds()

    h = sha256(seed).digest()
    iters = 0

    current = start
    while current < end:
        h = sha256(h).digest()

        if progress_callback:
            progress = int((current - start) * 100 / (end - start))
            progress_callback(min(progress, 100))

        current = time()
        iters += 1

    if progress_callback:
        progress_callback(100)

    return base64.urlsafe_b64encode(h), iters


def generate_by_iters(
    seed: bytes,
    iters: int,
    progress_callback: Callable[[int], None] | None = None,
) -> bytes:
    h = sha256(seed).digest()

    for i in range(iters):
        h = sha256(h).digest()

        if progress_callback:
            progress = int((i + 1) * 100 / iters)
            progress_callback(progress)

    if progress_callback:
        progress_callback(100)

    return base64.urlsafe_b64encode(h)


def encrypt(
    keyseed: bytes,
    delta: timedelta,
    message: bytes,
    progress_callback: Callable[[int], None] | None = None,
) -> tuple[bytes, int, bytes]:
    key, iterations = generate_by_time(keyseed, delta, progress_callback)
    encrypted = Fernet(key).encrypt(message)
    return key, iterations, encrypted


def decrypt(
    keyseed: bytes,
    iterations: int,
    encrypted: bytes,
    progress_callback: Callable[[int], None] | None = None,
) -> tuple[bytes, bytes]:
    key = generate_by_iters(keyseed, iterations, progress_callback)
    decrypted = Fernet(key).decrypt(encrypted)
    return key, decrypted
