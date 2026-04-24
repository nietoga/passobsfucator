# passobfuscator

Encrypt plaintext with a key-derivation puzzle so decryption takes deliberate
work. The tool supports both:

- `sha256-chain`: sequential time-lock hashing (CPU-bound)
- `scrypt`: memory-hard KDF (more resistant to GPU/ASIC acceleration)

## How it works

### 1) `sha256-chain` (time-lock mode)

Encryption runs a sequential SHA-256 chain for the requested wall-clock
duration and stores the resulting `work_units`. Decryption reproduces exactly
that many rounds to rebuild the key.

### 2) `scrypt` (memory-hard time-lock mode)

Encryption repeatedly applies `scrypt(seed, salt, n, r, p)` for the requested
time budget and stores `work_units` plus the scrypt parameters/salt in output
JSON. Decryption replays exactly the same number of sequential rounds.

Both modes then use a [Fernet](https://cryptography.io/en/latest/fernet/) key
to encrypt/decrypt payload data.

## Requirements

- Python >= 3.11
- [uv](https://docs.astral.sh/uv/) (required workflow for this repo)

## Installation

```bash
# Clone the repo
git clone https://github.com/nietoga/passobsfucator.git
cd passobsfucator

# Install dependencies from pyproject.toml/uv.lock
uv sync
```

## Usage (always via uv)

### Generate a random password

```bash
uv run python main.py generate-password --length 16
```

### Encrypt with default time-lock (`sha256-chain`)

```bash
uv run python main.py encrypt 'MyS3cr3t!' --time-in-seconds 10 --output-file locked.json
```

### Encrypt with memory-hard `scrypt`

```bash
uv run python main.py encrypt 'MyS3cr3t!' \
  --algorithm scrypt \
  --time-in-seconds 10 \
  --scrypt-n 16384 \
  --scrypt-r 8 \
  --scrypt-p 1 \
  --output-file locked-scrypt.json
```

### Decrypt

```bash
uv run python main.py decrypt locked.json
uv run python main.py decrypt locked-scrypt.json
```

### Show progress bar (disabled by default)

```bash
uv run python main.py encrypt 'MyS3cr3t!' --time-in-seconds 10 --show-progress
uv run python main.py decrypt locked.json --show-progress
```

## Output JSON formats

### `sha256-chain`

```json
{
  "algorithm": "sha256-chain",
  "seed": "example-seed",
  "work_units": 12345000,
  "encrypted": "..."
}
```

### `scrypt`

```json
{
  "algorithm": "scrypt",
  "seed": "example-seed",
  "work_units": 24,
  "scrypt": {
    "n": 16384,
    "r": 8,
    "p": 1,
    "salt": "base64-url-safe-salt"
  },
  "encrypted": "..."
}
```

## Development

```bash
uv sync
uv run pytest tests -v
```

## Project layout

```text
.
├── main.py          # CLI (Typer): generate-password, encrypt, decrypt
├── puzzle.py        # Key-derivation + Fernet encrypt/decrypt (sha256-chain, scrypt)
├── randpass.py      # Cryptographically secure password generator (secrets module)
├── progress.py      # tqdm progress-bar helper
├── tests/           # pytest suite
├── pyproject.toml   # Project metadata + dependencies
└── uv.lock          # Locked dependency set for uv
```
