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
- Progress is time-based (hash runs in a background thread); the bar is an
  estimate and may sit at 99% for a moment if the machine is slower than
  expected.
"""

import base64
import os
import threading
from time import monotonic
from typing import Callable

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
_PROGRESS_POLL_INTERVAL: float = 0.05  # seconds between progress updates


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _run_hash_in_thread(
    salt: bytes,
    time_cost: int,
    memory_cost_kb: int,
    parallelism: int,
) -> bytes:
    """Run hash_secret_raw and return the URL-safe base-64 encoded result."""
    raw = hash_secret_raw(
        secret=b"",
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost_kb,
        parallelism=parallelism,
        hash_len=_HASH_LEN,
        type=Type.ID,
    )
    return base64.urlsafe_b64encode(raw)


def _derive_key(
    salt: bytes,
    time_cost: int,
    memory_cost_kb: int = DEFAULT_MEMORY_COST_KB,
    parallelism: int = DEFAULT_PARALLELISM,
    expected_seconds: float | None = None,
    progress_callback: Callable[[int], None] | None = None,
) -> bytes:
    """Derive a Fernet key via Argon2id, optionally driving a progress callback.

    When *progress_callback* is provided the hash runs on a background thread
    while the calling thread polls elapsed time against *expected_seconds* to
    report estimated progress in [0, 100].  The bar is capped at 99 until the
    hash finishes, then jumps to 100.

    If *expected_seconds* is ``None`` but a callback is provided, progress
    is reported as 0 → 100 only (start and finish).
    """
    if progress_callback is None:
        return _run_hash_in_thread(salt, time_cost, memory_cost_kb, parallelism)

    result: list[bytes] = []
    error: list[BaseException] = []

    def _worker() -> None:
        try:
            result.append(
                _run_hash_in_thread(salt, time_cost, memory_cost_kb, parallelism)
            )
        except BaseException as exc:  # noqa: BLE001
            error.append(exc)

    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()
    start = monotonic()
    progress_callback(0)

    while True:
        thread.join(timeout=_PROGRESS_POLL_INTERVAL)
        if not thread.is_alive():
            break
        if expected_seconds:
            elapsed = monotonic() - start
            pct = min(int(elapsed * 100 / expected_seconds), 99)
            progress_callback(pct)

    progress_callback(100)

    if error:
        raise error[0]
    return result[0]


def _calibrate(
    target_seconds: float,
    memory_cost_kb: int = DEFAULT_MEMORY_COST_KB,
    parallelism: int = DEFAULT_PARALLELISM,
) -> tuple[bytes, int, float]:
    """Choose *time_cost* so that key derivation takes ~*target_seconds*.

    Measures a single-pass baseline on this machine, then scales linearly.

    Returns:
        (salt, time_cost, estimated_seconds)
        *estimated_seconds* is the predicted derivation time on this machine.
    """
    salt = os.urandom(16)

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

    time_cost = max(1, round(target_seconds / baseline))
    estimated_seconds = baseline * time_cost
    return salt, time_cost, estimated_seconds


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def encrypt(
    target_seconds: float,
    message: bytes,
    memory_cost_kb: int = DEFAULT_MEMORY_COST_KB,
    parallelism: int = DEFAULT_PARALLELISM,
    progress_callback: Callable[[int], None] | None = None,
) -> tuple[bytes, int, int, int, float, bytes]:
    """Calibrate Argon2id parameters for *target_seconds*, then encrypt *message*.

    Args:
        target_seconds: Desired CPU time budget for key derivation.
        message: Plaintext bytes to encrypt.
        memory_cost_kb: Argon2 memory parameter in KiB (default 64 MiB).
        parallelism: Argon2 parallelism lanes (keep at 1 for sequential timing).
        progress_callback: Optional callable receiving progress in [0, 100].
            Progress is time-based (an estimate), not exact.

    Returns:
        (salt, time_cost, memory_cost_kb, parallelism, estimated_seconds, ciphertext)
    """
    salt, time_cost, estimated_seconds = _calibrate(
        target_seconds, memory_cost_kb, parallelism
    )
    key = _derive_key(
        salt, time_cost, memory_cost_kb, parallelism, estimated_seconds, progress_callback
    )
    ciphertext = Fernet(key).encrypt(message)
    return salt, time_cost, memory_cost_kb, parallelism, estimated_seconds, ciphertext


def decrypt(
    salt: bytes,
    time_cost: int,
    ciphertext: bytes,
    memory_cost_kb: int = DEFAULT_MEMORY_COST_KB,
    parallelism: int = DEFAULT_PARALLELISM,
    expected_seconds: float | None = None,
    progress_callback: Callable[[int], None] | None = None,
) -> bytes:
    """Re-derive the Argon2id key and decrypt *ciphertext*.

    Args:
        salt: Random salt stored during encryption.
        time_cost: Argon2 time_cost stored during encryption.
        ciphertext: Fernet ciphertext produced by :func:`encrypt`.
        memory_cost_kb: Must match the value used during encryption.
        parallelism: Must match the value used during encryption.
        expected_seconds: Estimated derivation time (stored in the JSON during
            encryption).  Used to drive the progress bar; omit if unavailable.
        progress_callback: Optional callable receiving progress in [0, 100].

    Returns:
        Plaintext bytes.
    """
    key = _derive_key(
        salt, time_cost, memory_cost_kb, parallelism, expected_seconds, progress_callback
    )
    return Fernet(key).decrypt(ciphertext)
