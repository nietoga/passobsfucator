"""Tests for the Argon2id time-lock puzzle module."""

import os

import pytest

import puzzle_argon2

MESSAGE = b"secret-message"

# Tiny parameters so tests finish in milliseconds
_FAST_MEMORY = 8   # 8 KiB — minimum valid for argon2-cffi
_FAST_TIME = 1


# ---------------------------------------------------------------------------
# Helper: encrypt with fast (non-default) parameters
# ---------------------------------------------------------------------------

def _fast_encrypt(message: bytes = MESSAGE) -> tuple:
    """Encrypt using minimal Argon2 parameters (bypasses calibration)."""
    import base64
    from argon2.low_level import Type, hash_secret_raw
    from cryptography.fernet import Fernet

    salt = os.urandom(16)
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


# ---------------------------------------------------------------------------
# _derive_key
# ---------------------------------------------------------------------------

class TestDeriveKey:
    def test_returns_valid_fernet_key(self) -> None:
        import base64
        salt = os.urandom(16)
        key = puzzle_argon2._derive_key(salt, _FAST_TIME, _FAST_MEMORY)
        assert len(base64.urlsafe_b64decode(key)) == 32

    def test_deterministic(self) -> None:
        salt = os.urandom(16)
        assert (
            puzzle_argon2._derive_key(salt, _FAST_TIME, _FAST_MEMORY)
            == puzzle_argon2._derive_key(salt, _FAST_TIME, _FAST_MEMORY)
        )

    def test_different_salts_give_different_keys(self) -> None:
        k1 = puzzle_argon2._derive_key(os.urandom(16), _FAST_TIME, _FAST_MEMORY)
        k2 = puzzle_argon2._derive_key(os.urandom(16), _FAST_TIME, _FAST_MEMORY)
        assert k1 != k2

    def test_different_time_costs_give_different_keys(self) -> None:
        salt = os.urandom(16)
        assert (
            puzzle_argon2._derive_key(salt, 1, _FAST_MEMORY)
            != puzzle_argon2._derive_key(salt, 2, _FAST_MEMORY)
        )

    def test_different_memory_costs_give_different_keys(self) -> None:
        salt = os.urandom(16)
        assert (
            puzzle_argon2._derive_key(salt, _FAST_TIME, 8)
            != puzzle_argon2._derive_key(salt, _FAST_TIME, 16)
        )

    def test_progress_callback_called_when_provided(self) -> None:
        values: list[int] = []
        salt = os.urandom(16)
        puzzle_argon2._derive_key(
            salt, _FAST_TIME, _FAST_MEMORY,
            expected_seconds=10.0,
            progress_callback=values.append,
        )
        assert values, "callback should be called at least once"
        assert values[0] == 0
        assert values[-1] == 100

    def test_progress_values_monotonically_increasing(self) -> None:
        values: list[int] = []
        salt = os.urandom(16)
        puzzle_argon2._derive_key(
            salt, _FAST_TIME, _FAST_MEMORY,
            expected_seconds=10.0,
            progress_callback=values.append,
        )
        for a, b in zip(values, values[1:]):
            assert b >= a

    def test_progress_values_in_range(self) -> None:
        values: list[int] = []
        salt = os.urandom(16)
        puzzle_argon2._derive_key(
            salt, _FAST_TIME, _FAST_MEMORY,
            expected_seconds=10.0,
            progress_callback=values.append,
        )
        assert all(0 <= v <= 100 for v in values)

    def test_no_progress_callback_still_works(self) -> None:
        salt = os.urandom(16)
        key = puzzle_argon2._derive_key(salt, _FAST_TIME, _FAST_MEMORY)
        assert isinstance(key, bytes)


# ---------------------------------------------------------------------------
# encrypt / decrypt round-trips
# ---------------------------------------------------------------------------

class TestEncryptDecrypt:
    def test_round_trip(self) -> None:
        salt, time_cost, memory_cost_kb, parallelism, ciphertext = _fast_encrypt()
        decrypted = puzzle_argon2.decrypt(salt, time_cost, ciphertext, memory_cost_kb, parallelism)
        assert decrypted == MESSAGE

    def test_round_trip_with_progress(self) -> None:
        salt, time_cost, memory_cost_kb, parallelism, ciphertext = _fast_encrypt()
        values: list[int] = []
        decrypted = puzzle_argon2.decrypt(
            salt, time_cost, ciphertext, memory_cost_kb, parallelism,
            expected_seconds=10.0,
            progress_callback=values.append,
        )
        assert decrypted == MESSAGE
        assert values[-1] == 100

    def test_ciphertext_differs_from_plaintext(self) -> None:
        _, _, _, _, ciphertext = _fast_encrypt()
        assert ciphertext != MESSAGE

    def test_wrong_salt_raises(self) -> None:
        from cryptography.fernet import InvalidToken
        salt, time_cost, memory_cost_kb, parallelism, ciphertext = _fast_encrypt()
        with pytest.raises(InvalidToken):
            puzzle_argon2.decrypt(os.urandom(16), time_cost, ciphertext, memory_cost_kb, parallelism)

    def test_wrong_time_cost_raises(self) -> None:
        from cryptography.fernet import InvalidToken
        salt, time_cost, memory_cost_kb, parallelism, ciphertext = _fast_encrypt()
        with pytest.raises(InvalidToken):
            puzzle_argon2.decrypt(salt, time_cost + 1, ciphertext, memory_cost_kb, parallelism)

    def test_encrypt_returns_six_tuple(self) -> None:
        salt, time_cost, memory_cost_kb, parallelism, estimated_seconds, ciphertext = (
            puzzle_argon2.encrypt(
                target_seconds=0.001,
                message=MESSAGE,
                memory_cost_kb=_FAST_MEMORY,
            )
        )
        assert isinstance(salt, bytes) and len(salt) == 16
        assert isinstance(time_cost, int) and time_cost >= 1
        assert memory_cost_kb == _FAST_MEMORY
        assert parallelism == 1
        assert isinstance(estimated_seconds, float) and estimated_seconds > 0
        assert isinstance(ciphertext, bytes)

    def test_estimated_seconds_is_positive(self) -> None:
        *_, estimated_seconds, _ = puzzle_argon2.encrypt(
            target_seconds=0.001, message=MESSAGE, memory_cost_kb=_FAST_MEMORY
        )
        assert estimated_seconds > 0

    def test_encrypt_with_progress_callback(self) -> None:
        values: list[int] = []
        *_, ciphertext = puzzle_argon2.encrypt(
            target_seconds=0.001,
            message=MESSAGE,
            memory_cost_kb=_FAST_MEMORY,
            progress_callback=values.append,
        )
        assert values[-1] == 100
        assert isinstance(ciphertext, bytes)


# ---------------------------------------------------------------------------
# _calibrate
# ---------------------------------------------------------------------------

class TestCalibrate:
    def test_returns_salt_time_cost_and_estimate(self) -> None:
        salt, time_cost, estimated = puzzle_argon2._calibrate(0.001, _FAST_MEMORY)
        assert isinstance(salt, bytes) and len(salt) == 16
        assert isinstance(time_cost, int) and time_cost >= 1
        assert isinstance(estimated, float) and estimated > 0

    def test_calibrate_produces_unique_salts(self) -> None:
        salt1, *_ = puzzle_argon2._calibrate(0.001, _FAST_MEMORY)
        salt2, *_ = puzzle_argon2._calibrate(0.001, _FAST_MEMORY)
        assert salt1 != salt2
