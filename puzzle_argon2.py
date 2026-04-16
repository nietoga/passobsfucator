"""Argon2id-based time-lock puzzle.

Unlike the SHA-256 chain, Argon2id is *memory-hard*: each iteration requires
filling a large memory block, which makes GPU and ASIC acceleration far less
effective.  The decryptor must re-run Argon2 with the stored parameters, which
takes approximately the same wall-clock time as encryption did.

Key differences from the SHA-256 chain
---------------------------------------
- Memory-hard: ~64 MiB of RAM must be accessed for each derivation.
- Parameters are stored in the JSON, so old ciphertexts always decrypt
  correctly even if library defaults change.
- No seed / iteration count — only salt + Argon2 tuning knobs.
"""

import base64
import os
from time import monotonic

from argon2.low_level import Type, hash_secret_raw
from cryptography.fernet import Fernet

# ---------------------------------------------------------------------------
# Default Argon2id parameters
# ---------------------------------------------------------------------------
# 64 MiB memory cost keeps derivation fast enough for low time_cost values
# while still being expensive for parallel GPU/ASIC attacks.
DEFAULT_MEMORY_COST_KB: int = 65_536  # 64 MiB
DEFAULT_PARALLELISM: int = 1           # sequential → predictable timing
_HASH_LEN: int = 32                    # bytes → 256-bit Fernet key


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _derive_key(
    salt: bytes,
    time_cost: int,
    memory_cost_kb: int = DEFAULT_MEMORY_COST_KB,
    parallelism: int = DEFAULT_PARALLELISM,
) -> bytes:
    """Return a URL-safe base-64 Fernet key derived via Argon2id."""
    raw = hash_secret_raw(
        secret=b"",           # security is purely temporal, not knowledge-based
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost_kb,
        parallelism=parallelism,
        hash_len=_HASH_LEN,
        type=Type.ID,
    )
    return base64.urlsafe_b64encode(raw)


def _calibrate(
    target_seconds: float,
    memory_cost_kb: int = DEFAULT_MEMORY_COST_KB,
    parallelism: int = DEFAULT_PARALLELISM,
) -> tuple[bytes, int]:
    """Choose *time_cost* so that key derivation takes ~*target_seconds*.

    Measures a single-pass baseline on this machine, then scales linearly.

    Returns:
        (salt, time_cost)
    """
    salt = os.urandom(16)

    # Measure a baseline with time_cost=1
    start = monotonic()
    hash_secret_raw(
        secret=b"",
        salt=salt,
        time_cost=1,
        memory_cost=memory_cost_kb,
        parallelism=parallelism,
        hash_len=_HASH_LEN,
        type=Type.ID,
    )
    baseline = monotonic() - start

    # Scale to hit the target (minimum 1 pass)
    time_cost = max(1, round(target_seconds / baseline))
    return salt, time_cost


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def encrypt(
    target_seconds: float,
    message: bytes,
    memory_cost_kb: int = DEFAULT_MEMORY_COST_KB,
    parallelism: int = DEFAULT_PARALLELISM,
) -> tuple[bytes, int, int, int, bytes]:
    """Calibrate Argon2id parameters for *target_seconds*, then encrypt *message*.

    Args:
        target_seconds: Desired CPU time budget for key derivation.
        message: Plaintext bytes to encrypt.
        memory_cost_kb: Argon2 memory parameter in KiB (default 64 MiB).
        parallelism: Argon2 parallelism lanes (keep at 1 for sequential timing).

    Returns:
        (salt, time_cost, memory_cost_kb, parallelism, ciphertext)
        All parameters needed for decryption are returned so callers can store them.
    """
    salt, time_cost = _calibrate(target_seconds, memory_cost_kb, parallelism)
    key = _derive_key(salt, time_cost, memory_cost_kb, parallelism)
    ciphertext = Fernet(key).encrypt(message)
    return salt, time_cost, memory_cost_kb, parallelism, ciphertext


def decrypt(
    salt: bytes,
    time_cost: int,
    ciphertext: bytes,
    memory_cost_kb: int = DEFAULT_MEMORY_COST_KB,
    parallelism: int = DEFAULT_PARALLELISM,
) -> bytes:
    """Re-derive the Argon2id key and decrypt *ciphertext*.

    Args:
        salt: Random salt stored during encryption.
        time_cost: Argon2 time_cost stored during encryption.
        ciphertext: Fernet ciphertext produced by :func:`encrypt`.
        memory_cost_kb: Must match the value used during encryption.
        parallelism: Must match the value used during encryption.

    Returns:
        Plaintext bytes.
    """
    key = _derive_key(salt, time_cost, memory_cost_kb, parallelism)
    return Fernet(key).decrypt(ciphertext)
