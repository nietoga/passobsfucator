# passobfuscator

A Python CLI tool that time-lock encrypts sensitive values (like passwords) by requiring a configurable amount of CPU work to decrypt.

## Project Structure

```
.
├── main.py          # CLI entry point (typer): generate-password, encrypt, decrypt
├── puzzle.py        # Hash-chain key derivation + Fernet encrypt/decrypt
├── randpass.py      # Cryptographically secure password generator (secrets module)
├── progress.py      # tqdm progress-bar helper with context manager support
├── tests/           # pytest test suite
├── pyproject.toml   # Project metadata, dependencies, tool config (uv/pip)
├── uv.lock          # Reproducible lock file
└── README.md
```

## Technologies

- **Language**: Python 3.12
- **Package management**: uv (pyproject.toml + uv.lock)
- **CLI**: typer ≥ 0.12.0
- **Cryptography**: cryptography library (Fernet), hashlib SHA-256, hashlib scrypt
- **Progress**: tqdm
- **Testing**: pytest + pytest-cov

## Running

```bash
uv run python main.py --help
uv run python main.py generate-password --length 16
uv run python main.py encrypt 'secret' --time-in-seconds 10 --output-file locked.json
uv run python main.py decrypt locked.json
```

## Testing

```bash
uv run pytest tests/ -v
```

## Workflow

"Start application" runs `uv run python main.py --help` as a console workflow.

## Key Design Decisions

- `randpass.py` uses `secrets` (not `random`) for cryptographic security.
- `puzzle.py` batches SHA-256 iterations in groups of 5,000 before checking the clock, keeping progress-callback overhead negligible.
- `puzzle.py` also supports memory-hard `scrypt`, which is more resistant to commodity GPU attacks than pure hash chains.
- `main.py` uses `None` as the seed default (not a function call evaluated at import time) to ensure each invocation gets a fresh seed.
- `progress.py` implements the context manager protocol so callers can use `with ProgressBar() as pb:`.
