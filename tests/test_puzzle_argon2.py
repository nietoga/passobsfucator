"""Tests for the Argon2id time-lock puzzle module."""

import pytest

import puzzle_argon2

MESSAGE = b"secret-message"

# Use tiny parameters so tests run fast (well under 1 second each)
_FAST_MEMORY = 8  # 8 KiB — minimum valid for argon2-cffi
_FAST_TIME = 1


def _fast_encrypt(message: bytes = MESSAGE) -> tuple:
    """Encrypt with fast parameters (bypasses calibration)."""
    import os
    salt = os.urandom(16)
    from argon2.low_level import Type, hash_secret_raw
    import base64
    from cryptography.fernet import Fernet

    raw = hash_secret_raw(
        secret=b"",
        salt=salt,
        time_cost=_FAST_TIME,
        memory_cost=_FAST_MEMORY,
        parallelism=1,
        hash_len=32,
        type=Type.ID,
    )
    key = base64.urlsafe_b64encode(raw)
    ciphertext = Fernet(key).encrypt(message)
    return salt, _FAST_TIME, _FAST_MEMORY, 1, ciphertext


class TestDeriveKey:
    def test_returns_valid_fernet_key(self) -> None:
        import os, base64
        salt = os.urandom(16)
        key = puzzle_argon2._derive_key(salt, _FAST_TIME, _FAST_MEMORY)
        decoded = base64.urlsafe_b64decode(key)
        assert len(decoded) == 32

    def test_deterministic(self) -> None:
        import os
        salt = os.urandom(16)
        k1 = puzzle_argon2._derive_key(salt, _FAST_TIME, _FAST_MEMORY)
        k2 = puzzle_argon2._derive_key(salt, _FAST_TIME, _FAST_MEMORY)
        assert k1 == k2

    def test_different_salts_give_different_keys(self) -> None:
        import os
        k1 = puzzle_argon2._derive_key(os.urandom(16), _FAST_TIME, _FAST_MEMORY)
        k2 = puzzle_argon2._derive_key(os.urandom(16), _FAST_TIME, _FAST_MEMORY)
        assert k1 != k2

    def test_different_time_costs_give_different_keys(self) -> None:
        import os
        salt = os.urandom(16)
        k1 = puzzle_argon2._derive_key(salt, 1, _FAST_MEMORY)
        k2 = puzzle_argon2._derive_key(salt, 2, _FAST_MEMORY)
        assert k1 != k2

    def test_different_memory_costs_give_different_keys(self) -> None:
        import os
        salt = os.urandom(16)
        k1 = puzzle_argon2._derive_key(salt, _FAST_TIME, 8)
        k2 = puzzle_argon2._derive_key(salt, _FAST_TIME, 16)
        assert k1 != k2


class TestEncryptDecrypt:
    def test_round_trip(self) -> None:
        salt, time_cost, memory_cost_kb, parallelism, ciphertext = _fast_encrypt()
        decrypted = puzzle_argon2.decrypt(salt, time_cost, ciphertext, memory_cost_kb, parallelism)
        assert decrypted == MESSAGE

    def test_ciphertext_differs_from_plaintext(self) -> None:
        _, _, _, _, ciphertext = _fast_encrypt()
        assert ciphertext != MESSAGE

    def test_wrong_salt_raises(self) -> None:
        import os
        from cryptography.fernet import InvalidToken
        salt, time_cost, memory_cost_kb, parallelism, ciphertext = _fast_encrypt()
        with pytest.raises(InvalidToken):
            puzzle_argon2.decrypt(os.urandom(16), time_cost, ciphertext, memory_cost_kb, parallelism)

    def test_wrong_time_cost_raises(self) -> None:
        from cryptography.fernet import InvalidToken
        salt, time_cost, memory_cost_kb, parallelism, ciphertext = _fast_encrypt()
        with pytest.raises(InvalidToken):
            puzzle_argon2.decrypt(salt, time_cost + 1, ciphertext, memory_cost_kb, parallelism)

    def test_encrypt_returns_correct_types(self) -> None:
        salt, time_cost, memory_cost_kb, parallelism, ciphertext = _fast_encrypt()
        assert isinstance(salt, bytes)
        assert isinstance(time_cost, int)
        assert isinstance(memory_cost_kb, int)
        assert isinstance(parallelism, int)
        assert isinstance(ciphertext, bytes)

    def test_parameters_stored_match_defaults(self) -> None:
        """Memory cost and parallelism returned should match defaults."""
        # Use the real encrypt() with a tiny target so calibration runs fast
        salt, time_cost, memory_cost_kb, parallelism, _ = puzzle_argon2.encrypt(
            target_seconds=0.001,
            message=MESSAGE,
            memory_cost_kb=_FAST_MEMORY,
        )
        assert memory_cost_kb == _FAST_MEMORY
        assert parallelism == 1
        assert isinstance(time_cost, int) and time_cost >= 1


class TestCalibrate:
    def test_returns_bytes_salt_and_int_time_cost(self) -> None:
        salt, time_cost = puzzle_argon2._calibrate(0.001, _FAST_MEMORY)
        assert isinstance(salt, bytes) and len(salt) == 16
        assert isinstance(time_cost, int) and time_cost >= 1

    def test_calibrate_produces_unique_salts(self) -> None:
        salt1, _ = puzzle_argon2._calibrate(0.001, _FAST_MEMORY)
        salt2, _ = puzzle_argon2._calibrate(0.001, _FAST_MEMORY)
        assert salt1 != salt2
