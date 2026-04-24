"""Tests for the time-lock puzzle module."""

import base64
from datetime import timedelta

import pytest

import puzzle


SEED = b"test-seed"
MESSAGE = b"secret-message"


class TestGenerateByIters:
    def test_returns_valid_base64_key(self) -> None:
        key = puzzle.generate_by_iters(SEED, iters=1000)
        # Should be decodable as URL-safe base64 and usable as a Fernet key
        decoded = base64.urlsafe_b64decode(key)
        assert len(decoded) == 32

    def test_deterministic(self) -> None:
        key1 = puzzle.generate_by_iters(SEED, iters=5000)
        key2 = puzzle.generate_by_iters(SEED, iters=5000)
        assert key1 == key2

    def test_different_seeds_give_different_keys(self) -> None:
        key1 = puzzle.generate_by_iters(b"seed-a", iters=5000)
        key2 = puzzle.generate_by_iters(b"seed-b", iters=5000)
        assert key1 != key2

    def test_different_iters_give_different_keys(self) -> None:
        key1 = puzzle.generate_by_iters(SEED, iters=5000)
        key2 = puzzle.generate_by_iters(SEED, iters=10000)
        assert key1 != key2

    def test_progress_callback_called(self) -> None:
        progress_values: list[int] = []
        puzzle.generate_by_iters(SEED, iters=10000, progress_callback=progress_values.append)
        assert progress_values, "Callback should be called at least once"
        assert progress_values[-1] == 100

    def test_progress_values_are_monotonically_increasing(self) -> None:
        progress_values: list[int] = []
        puzzle.generate_by_iters(SEED, iters=50_000, progress_callback=progress_values.append)
        for a, b in zip(progress_values, progress_values[1:]):
            assert b >= a, "Progress should never decrease"

    def test_progress_values_in_range(self) -> None:
        progress_values: list[int] = []
        puzzle.generate_by_iters(SEED, iters=20_000, progress_callback=progress_values.append)
        assert all(0 <= v <= 100 for v in progress_values)


class TestGenerateByTime:
    def test_returns_key_and_positive_iters(self) -> None:
        key, iters = puzzle.generate_by_time(SEED, timedelta(seconds=0.1))
        assert isinstance(key, bytes)
        assert iters > 0

    def test_iters_is_multiple_of_tick_interval(self) -> None:
        _, iters = puzzle.generate_by_time(SEED, timedelta(seconds=0.1))
        assert iters % puzzle._TICK_INTERVAL == 0

    def test_progress_callback_reaches_100(self) -> None:
        progress_values: list[int] = []
        puzzle.generate_by_time(
            SEED, timedelta(seconds=0.1), progress_callback=progress_values.append
        )
        assert progress_values[-1] == 100


class TestEncryptDecrypt:
    def test_round_trip(self) -> None:
        _, iters, ciphertext = puzzle.encrypt(SEED, timedelta(seconds=0.1), MESSAGE)
        _, decrypted = puzzle.decrypt(SEED, iters, ciphertext)
        assert decrypted == MESSAGE

    def test_ciphertext_differs_from_plaintext(self) -> None:
        _, _, ciphertext = puzzle.encrypt(SEED, timedelta(seconds=0.1), MESSAGE)
        assert ciphertext != MESSAGE

    def test_wrong_seed_raises(self) -> None:
        _, iters, ciphertext = puzzle.encrypt(SEED, timedelta(seconds=0.1), MESSAGE)
        from cryptography.fernet import InvalidToken
        with pytest.raises(InvalidToken):
            puzzle.decrypt(b"wrong-seed", iters, ciphertext)

    def test_wrong_iters_raises(self) -> None:
        _, iters, ciphertext = puzzle.encrypt(SEED, timedelta(seconds=0.1), MESSAGE)
        from cryptography.fernet import InvalidToken
        with pytest.raises(InvalidToken):
            puzzle.decrypt(SEED, iters + puzzle._TICK_INTERVAL, ciphertext)

    def test_encrypt_returns_bytes(self) -> None:
        key, iters, ciphertext = puzzle.encrypt(SEED, timedelta(seconds=0.1), MESSAGE)
        assert isinstance(key, bytes)
        assert isinstance(iters, int)
        assert isinstance(ciphertext, bytes)


class TestScrypt:
    def test_generate_scrypt_key_returns_valid_fernet_key(self) -> None:
        key = puzzle.generate_scrypt_key(
            b"scrypt-seed",
            salt=b"0123456789abcdef",
            n=2**14,
            r=8,
            p=1,
        )
        decoded = base64.urlsafe_b64decode(key)
        assert len(decoded) == 32

    def test_generate_scrypt_key_deterministic_with_same_inputs(self) -> None:
        key1 = puzzle.generate_scrypt_key(
            b"seed",
            salt=b"0123456789abcdef",
            n=2**14,
            r=8,
            p=1,
        )
        key2 = puzzle.generate_scrypt_key(
            b"seed",
            salt=b"0123456789abcdef",
            n=2**14,
            r=8,
            p=1,
        )
        assert key1 == key2

    def test_generate_scrypt_key_changes_when_salt_changes(self) -> None:
        key1 = puzzle.generate_scrypt_key(
            b"seed",
            salt=b"salt-000000000001",
            n=2**14,
            r=8,
            p=1,
        )
        key2 = puzzle.generate_scrypt_key(
            b"seed",
            salt=b"salt-000000000002",
            n=2**14,
            r=8,
            p=1,
        )
        assert key1 != key2

    def test_encrypt_decrypt_scrypt_round_trip(self) -> None:
        _, salt, ciphertext = puzzle.encrypt_scrypt(
            b"scrypt-seed",
            MESSAGE,
            n=2**14,
            r=8,
            p=1,
            salt=b"0123456789abcdef",
        )
        _, decrypted = puzzle.decrypt_scrypt(
            b"scrypt-seed",
            ciphertext,
            salt=salt,
            n=2**14,
            r=8,
            p=1,
        )
        assert decrypted == MESSAGE

    def test_encrypt_scrypt_invalid_n_raises(self) -> None:
        with pytest.raises(ValueError, match="power of two"):
            puzzle.encrypt_scrypt(
                b"scrypt-seed",
                MESSAGE,
                n=1000,
                r=8,
                p=1,
            )
