"""Time-lock puzzle via sequential SHA-256 proof-of-work.

Reference: https://asecuritysite.com/encryption/pow
"""

import base64
from datetime import timedelta
from hashlib import scrypt, sha256
from secrets import token_bytes
from time import monotonic
from typing import Callable

from cryptography.fernet import Fernet

ALGORITHM_SHA256_CHAIN = "sha256-chain"
ALGORITHM_SCRYPT = "scrypt"

# How often to sample wall-clock time and fire progress callbacks in the
# tight hashing loop. Checking time() every iteration is measurably slow;
# checking every TICK_INTERVAL iterations keeps overhead negligible.
_TICK_INTERVAL = 5_000


def _hash_chain(seed: bytes, count: int) -> bytes:
    """Run *count* sequential SHA-256 hashes starting from *seed*."""
    h = sha256(seed).digest()
    for _ in range(count):
        h = sha256(h).digest()
    return h


def _validate_scrypt_params(n: int, r: int, p: int) -> None:
    """Validate scrypt work-factor parameters."""
    if n < 2 or (n & (n - 1)) != 0:
        raise ValueError("scrypt n must be a power of two and >= 2")
    if r < 1:
        raise ValueError("scrypt r must be >= 1")
    if p < 1:
        raise ValueError("scrypt p must be >= 1")


def generate_scrypt_key(seed: bytes, salt: bytes, n: int, r: int, p: int) -> bytes:
    """Derive a Fernet-compatible key using scrypt (memory-hard)."""
    _validate_scrypt_params(n, r, p)
    key = scrypt(seed, salt=salt, n=n, r=r, p=p, dklen=32)
    return base64.urlsafe_b64encode(key)


def generate_by_time(
    seed: bytes,
    delta: timedelta,
    progress_callback: Callable[[int], None] | None = None,
) -> tuple[bytes, int]:
    """Hash *seed* repeatedly for *delta* seconds and return the key + iteration count.

    Args:
        seed: Starting bytes for the hash chain.
        delta: How long to run the hashing loop.
        progress_callback: Optional callable receiving progress in [0, 100].

    Returns:
        A tuple of (url-safe base-64 key, number of iterations performed).
    """
    duration = delta.total_seconds()
    start = monotonic()
    end = start + duration

    h = sha256(seed).digest()
    iters = 0
    last_progress = -1

    while True:
        # Run a batch of iterations before checking the clock.
        for _ in range(_TICK_INTERVAL):
            h = sha256(h).digest()
        iters += _TICK_INTERVAL

        now = monotonic()
        if now >= end:
            break

        if progress_callback:
            progress = min(int((now - start) * 100 / duration), 99)
            if progress != last_progress:
                last_progress = progress
                progress_callback(progress)

    if progress_callback:
        progress_callback(100)

    return base64.urlsafe_b64encode(h), iters


def generate_by_iters(
    seed: bytes,
    iters: int,
    progress_callback: Callable[[int], None] | None = None,
) -> bytes:
    """Reproduce a hash-chain key by running exactly *iters* hashes.

    Args:
        seed: Starting bytes for the hash chain.
        iters: Number of sequential SHA-256 rounds to perform.
        progress_callback: Optional callable receiving progress in [0, 100].

    Returns:
        The url-safe base-64 encoded final hash (Fernet-compatible key).
    """
    h = sha256(seed).digest()
    last_progress = -1

    for i in range(0, iters, _TICK_INTERVAL):
        batch = min(_TICK_INTERVAL, iters - i)
        for _ in range(batch):
            h = sha256(h).digest()

        if progress_callback:
            progress = min(int((i + batch) * 100 / iters), 100)
            if progress != last_progress:
                last_progress = progress
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
    """Time-lock encrypt *message* using a hash-chain key derived from *keyseed*.

    Args:
        keyseed: Seed bytes used to derive the Fernet key.
        delta: CPU time budget for key derivation (same budget required to decrypt).
        message: Plaintext bytes to encrypt.
        progress_callback: Optional callable receiving progress in [0, 100].

    Returns:
        A tuple of (derived key, iteration count, Fernet ciphertext).
    """
    key, iterations = generate_by_time(keyseed, delta, progress_callback)
    encrypted = Fernet(key).encrypt(message)
    return key, iterations, encrypted


def decrypt(
    keyseed: bytes,
    iterations: int,
    encrypted: bytes,
    progress_callback: Callable[[int], None] | None = None,
) -> tuple[bytes, bytes]:
    """Reproduce the hash-chain key and decrypt *encrypted*.

    Args:
        keyseed: Same seed used during encryption.
        iterations: Iteration count returned by :func:`encrypt`.
        encrypted: Fernet ciphertext produced by :func:`encrypt`.
        progress_callback: Optional callable receiving progress in [0, 100].

    Returns:
        A tuple of (derived key, plaintext bytes).
    """
    key = generate_by_iters(keyseed, iterations, progress_callback)
    decrypted = Fernet(key).decrypt(encrypted)
    return key, decrypted


def encrypt_scrypt(
    keyseed: bytes,
    message: bytes,
    n: int = 2**14,
    r: int = 8,
    p: int = 1,
    salt: bytes | None = None,
    progress_callback: Callable[[int], None] | None = None,
) -> tuple[bytes, bytes, bytes]:
    """Encrypt message using an scrypt-derived key."""
    chosen_salt = salt or token_bytes(16)
    if progress_callback:
        progress_callback(0)
    key = generate_scrypt_key(keyseed, chosen_salt, n=n, r=r, p=p)
    encrypted = Fernet(key).encrypt(message)
    if progress_callback:
        progress_callback(100)
    return key, chosen_salt, encrypted


def decrypt_scrypt(
    keyseed: bytes,
    encrypted: bytes,
    salt: bytes,
    n: int = 2**14,
    r: int = 8,
    p: int = 1,
    progress_callback: Callable[[int], None] | None = None,
) -> tuple[bytes, bytes]:
    """Decrypt message using an scrypt-derived key."""
    if progress_callback:
        progress_callback(0)
    key = generate_scrypt_key(keyseed, salt=salt, n=n, r=r, p=p)
    decrypted = Fernet(key).decrypt(encrypted)
    if progress_callback:
        progress_callback(100)
    return key, decrypted
