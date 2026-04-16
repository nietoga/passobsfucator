"""Cryptographically secure random password generator."""

import secrets
import string

_LOWERCASE = string.ascii_lowercase
_UPPERCASE = string.ascii_uppercase
_DIGITS = string.digits
_PUNCTUATION = string.punctuation
_ALL_CHARS = _LOWERCASE + _UPPERCASE + _DIGITS + _PUNCTUATION


def generate(length: int = 10) -> str:
    """Generate a cryptographically secure random password.

    The password is guaranteed to contain at least one character from each
    character class (lowercase, uppercase, digit, punctuation) when length >= 4.

    Args:
        length: Desired password length (minimum 4).

    Returns:
        A random password string of the requested length.

    Raises:
        ValueError: If length is less than 4.
    """
    if length < 4:
        raise ValueError("Password length must be at least 4")

    # Guarantee at least one character from each class
    mandatory = [
        secrets.choice(_LOWERCASE),
        secrets.choice(_UPPERCASE),
        secrets.choice(_DIGITS),
        secrets.choice(_PUNCTUATION),
    ]
    rest = [secrets.choice(_ALL_CHARS) for _ in range(length - 4)]
    password = mandatory + rest
    secrets.SystemRandom().shuffle(password)
    return "".join(password)
