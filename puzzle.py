"""Time-lock key-derivation strategies used for encryption/decryption."""

import base64
from abc import ABC, abstractmethod
from datetime import timedelta
from hashlib import scrypt, sha256
from secrets import token_bytes
from time import monotonic
from typing import Callable

from cryptography.fernet import Fernet

ALGORITHM_SHA256_CHAIN = "sha256-chain"
ALGORITHM_SCRYPT = "scrypt"

ProgressCallback = Callable[[int], None] | None

# How often to sample wall-clock time and fire progress callbacks in the
# SHA-256 tight loop. Checking time() every iteration is measurably slow.
_TICK_INTERVAL = 5_000


def _emit_progress(progress_callback: ProgressCallback, value: int) -> None:
    """Emit clamped progress updates when a callback exists."""
    if progress_callback:
        progress_callback(max(0, min(value, 100)))


def _validate_work_units(work_units: int) -> None:
    """Validate replayable work units."""
    if work_units < 1:
        raise ValueError("work_units must be >= 1")


def _validate_scrypt_params(n: int, r: int, p: int) -> None:
    """Validate scrypt work-factor parameters."""
    if n < 2 or (n & (n - 1)) != 0:
        raise ValueError("scrypt n must be a power of two and >= 2")
    if r < 1:
        raise ValueError("scrypt r must be >= 1")
    if p < 1:
        raise ValueError("scrypt p must be >= 1")


class TimeLockStrategy(ABC):
    """Base strategy for time-lock key derivation."""

    name: str

    @abstractmethod
    def derive_by_time(
        self,
        seed: bytes,
        delta: timedelta,
        progress_callback: ProgressCallback = None,
    ) -> tuple[bytes, int]:
        """Derive key for approximately *delta* seconds and return key + work units."""

    @abstractmethod
    def derive_by_work(
        self,
        seed: bytes,
        work_units: int,
        progress_callback: ProgressCallback = None,
    ) -> bytes:
        """Reproduce key by replaying exactly *work_units* operations."""

    def extra_payload(self) -> dict:
        """Return algorithm-specific metadata for encrypted JSON payloads."""
        return {}


class Sha256ChainStrategy(TimeLockStrategy):
    """Sequential SHA-256 chain strategy."""

    name = ALGORITHM_SHA256_CHAIN

    def derive_by_time(
        self,
        seed: bytes,
        delta: timedelta,
        progress_callback: ProgressCallback = None,
    ) -> tuple[bytes, int]:
        duration = delta.total_seconds()
        start = monotonic()
        end = start + duration

        h = sha256(seed).digest()
        iters = 0
        last_progress = -1
        _emit_progress(progress_callback, 0)

        while True:
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

        _emit_progress(progress_callback, 100)
        return base64.urlsafe_b64encode(h), iters

    def derive_by_work(
        self,
        seed: bytes,
        work_units: int,
        progress_callback: ProgressCallback = None,
    ) -> bytes:
        _validate_work_units(work_units)
        if work_units < 1:
            raise ValueError("work_units must be >= 1")

        h = sha256(seed).digest()
        last_progress = -1
        _emit_progress(progress_callback, 0)

        for i in range(0, work_units, _TICK_INTERVAL):
            batch = min(_TICK_INTERVAL, work_units - i)
            for _ in range(batch):
                h = sha256(h).digest()

            if progress_callback:
                progress = min(int((i + batch) * 100 / work_units), 100)
                if progress != last_progress:
                    last_progress = progress
                    progress_callback(progress)

        _emit_progress(progress_callback, 100)
        return base64.urlsafe_b64encode(h)


class ScryptStrategy(TimeLockStrategy):
    """Memory-hard scrypt strategy executed sequentially as a time-lock puzzle."""

    name = ALGORITHM_SCRYPT

    def __init__(self, n: int = 2**14, r: int = 8, p: int = 1, salt: bytes | None = None):
        _validate_scrypt_params(n, r, p)
        self.n = n
        self.r = r
        self.p = p
        self.salt = salt or token_bytes(16)

    def _round(self, value: bytes) -> bytes:
        return scrypt(value, salt=self.salt, n=self.n, r=self.r, p=self.p, dklen=32)

    def derive_by_time(
        self,
        seed: bytes,
        delta: timedelta,
        progress_callback: ProgressCallback = None,
    ) -> tuple[bytes, int]:
        duration = delta.total_seconds()
        start = monotonic()
        end = start + duration
        material = seed
        rounds = 0
        last_progress = -1
        _emit_progress(progress_callback, 0)

        while True:
            material = self._round(material)
            rounds += 1

            now = monotonic()
            if now >= end:
                break

            if progress_callback:
                progress = min(int((now - start) * 100 / duration), 99)
                if progress != last_progress:
                    last_progress = progress
                    progress_callback(progress)

        _emit_progress(progress_callback, 100)
        return base64.urlsafe_b64encode(material), rounds

    def derive_by_work(
        self,
        seed: bytes,
        work_units: int,
        progress_callback: ProgressCallback = None,
    ) -> bytes:
        _validate_work_units(work_units)
        if work_units < 1:
            raise ValueError("work_units must be >= 1")

        material = seed
        last_progress = -1
        _emit_progress(progress_callback, 0)
        for i in range(work_units):
            material = self._round(material)
            if progress_callback:
                progress = min(int((i + 1) * 100 / work_units), 100)
                if progress != last_progress:
                    last_progress = progress
                    progress_callback(progress)

        _emit_progress(progress_callback, 100)
        return base64.urlsafe_b64encode(material)

    def extra_payload(self) -> dict:
        return {
            "scrypt": {
                "n": self.n,
                "r": self.r,
                "p": self.p,
                "salt": base64.urlsafe_b64encode(self.salt).decode(),
            }
        }


def build_strategy(
    algorithm: str,
    *,
    scrypt_n: int = 2**14,
    scrypt_r: int = 8,
    scrypt_p: int = 1,
    scrypt_salt: bytes | None = None,
) -> TimeLockStrategy:
    """Build strategy instance for the selected algorithm."""
    if algorithm == ALGORITHM_SHA256_CHAIN:
        return Sha256ChainStrategy()
    if algorithm == ALGORITHM_SCRYPT:
        return ScryptStrategy(
            n=scrypt_n,
            r=scrypt_r,
            p=scrypt_p,
            salt=scrypt_salt,
        )
    raise ValueError("Unsupported algorithm. Use 'sha256-chain' or 'scrypt'.")


def encrypt_with_strategy(
    keyseed: bytes,
    delta: timedelta,
    message: bytes,
    strategy: TimeLockStrategy,
    progress_callback: ProgressCallback = None,
) -> tuple[bytes, int, bytes, dict]:
    """Time-lock encrypt using the provided strategy."""
    key, work_units = strategy.derive_by_time(keyseed, delta, progress_callback)
    encrypted = Fernet(key).encrypt(message)
    return key, work_units, encrypted, strategy.extra_payload()


def decrypt_with_strategy(
    keyseed: bytes,
    work_units: int,
    encrypted: bytes,
    strategy: TimeLockStrategy,
    progress_callback: ProgressCallback = None,
) -> tuple[bytes, bytes]:
    """Reproduce the strategy key and decrypt encrypted payload."""
    key = strategy.derive_by_work(keyseed, work_units, progress_callback)
    decrypted = Fernet(key).decrypt(encrypted)
    return key, decrypted


def generate_by_time(
    seed: bytes,
    delta: timedelta,
    progress_callback: ProgressCallback = None,
) -> tuple[bytes, int]:
    """Backward-compatible SHA-256 time-lock key derivation."""
    strategy = Sha256ChainStrategy()
    return strategy.derive_by_time(seed, delta, progress_callback)


def generate_by_iters(
    seed: bytes,
    iters: int,
    progress_callback: ProgressCallback = None,
) -> bytes:
    """Backward-compatible SHA-256 work replay key derivation."""
    strategy = Sha256ChainStrategy()
    return strategy.derive_by_work(seed, iters, progress_callback)


def encrypt(
    keyseed: bytes,
    delta: timedelta,
    message: bytes,
    progress_callback: ProgressCallback = None,
) -> tuple[bytes, int, bytes]:
    """Backward-compatible SHA-256 encrypt wrapper."""
    strategy = Sha256ChainStrategy()
    key, work_units, encrypted, _ = encrypt_with_strategy(
        keyseed,
        delta,
        message,
        strategy=strategy,
        progress_callback=progress_callback,
    )
    return key, work_units, encrypted


def decrypt(
    keyseed: bytes,
    iterations: int,
    encrypted: bytes,
    progress_callback: ProgressCallback = None,
) -> tuple[bytes, bytes]:
    """Backward-compatible SHA-256 decrypt wrapper."""
    strategy = Sha256ChainStrategy()
    return decrypt_with_strategy(
        keyseed,
        iterations,
        encrypted,
        strategy=strategy,
        progress_callback=progress_callback,
    )
