"""Tests for the random password generator."""

import string

import pytest

import randpass


class TestGenerate:
    def test_default_length(self) -> None:
        pw = randpass.generate()
        assert len(pw) == 10

    def test_custom_length(self) -> None:
        for length in (4, 8, 16, 32, 64):
            assert len(randpass.generate(length)) == length

    def test_contains_lowercase(self) -> None:
        pw = randpass.generate(20)
        assert any(c in string.ascii_lowercase for c in pw)

    def test_contains_uppercase(self) -> None:
        pw = randpass.generate(20)
        assert any(c in string.ascii_uppercase for c in pw)

    def test_contains_digit(self) -> None:
        pw = randpass.generate(20)
        assert any(c in string.digits for c in pw)

    def test_contains_punctuation(self) -> None:
        pw = randpass.generate(20)
        assert any(c in string.punctuation for c in pw)

    def test_all_chars_are_printable(self) -> None:
        pw = randpass.generate(50)
        assert all(c in string.printable for c in pw)

    def test_passwords_are_unique(self) -> None:
        """Two independently generated passwords should (almost certainly) differ."""
        passwords = {randpass.generate(20) for _ in range(20)}
        # Probability of collision is astronomically low for length-20 passwords.
        assert len(passwords) > 1

    def test_minimum_length_raises(self) -> None:
        with pytest.raises(ValueError, match="at least 4"):
            randpass.generate(3)

    def test_minimum_length_boundary(self) -> None:
        pw = randpass.generate(4)
        assert len(pw) == 4
