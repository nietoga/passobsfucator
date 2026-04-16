# passobfuscator

Encrypt plain text with a time-lock so that decryption requires a configurable
amount of CPU time. The original motivation was to keep a gaming account password
inaccessible during self-imposed breaks — without fully losing access.

## How it works

During encryption the tool runs a sequential SHA-256 hash chain for the
requested number of seconds and counts the iterations it managed to complete.
The final hash is used as a [Fernet](https://cryptography.io/en/latest/fernet/)
symmetric key to encrypt the plaintext. The iteration count is stored alongside
the ciphertext.

Decryption replays _exactly_ the same number of hash rounds (starting from the
same seed) to reconstruct the key. Because each round depends on the previous
one, the work cannot be parallelised — decryption therefore takes approximately
the same wall-clock time as encryption did on the same hardware.

## Requirements

- Python ≥ 3.11
- [uv](https://docs.astral.sh/uv/) (recommended) **or** pip

## Installation

```bash
# Clone the repo
git clone https://github.com/nietoga/passobsfucator.git
cd passobsfucator

# Install with uv (creates an isolated virtual environment automatically)
uv sync

# Or with pip
pip install .
```

## Usage

### Generate a random password

```bash
python main.py generate-password --length 16
# or via uv:
uv run python main.py generate-password --length 16
```

### Encrypt a value

```bash
# Default: 1 hour of decryption time
python main.py encrypt 'MyS3cr3t!' --time-in-seconds 3600 --output-file encrypted.json

# Quick demo (10-second lock)
python main.py encrypt 'MyS3cr3t!' --time-in-seconds 10 --output-file encrypted.json
```

> **Note**: encryption takes the same amount of CPU time as decryption will.

### Decrypt a value

```bash
python main.py decrypt encrypted.json
```

### End-to-end demo

```bash
# 1. Generate a password and encrypt it with a 10-second lock
python main.py generate-password --length 16 > raw.txt
python main.py encrypt "$(cat raw.txt)" --time-in-seconds 10 --output-file locked.json
rm raw.txt           # discard the plaintext

# 2. (wait however long you like)

# 3. Recover the password — takes ~10 s of CPU time
python main.py decrypt locked.json
```

## Development

```bash
# Install all dependencies (including dev extras)
uv sync

# Run tests
uv run pytest
# or
python -m pytest tests/ -v
```

## Project layout

```
.
├── main.py          # CLI (typer): generate-password, encrypt, decrypt
├── puzzle.py        # Time-lock core: hash-chain key derivation + Fernet encrypt/decrypt
├── randpass.py      # Cryptographically secure password generator (secrets module)
├── progress.py      # tqdm progress-bar helper
├── tests/           # pytest test suite
├── pyproject.toml   # Project metadata & dependencies (uv / pip)
└── uv.lock          # Reproducible dependency lock file
```
