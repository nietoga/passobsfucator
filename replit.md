# Time-Lock Encryption Tool

A Python CLI tool that obfuscates sensitive information (like passwords) by requiring a specific amount of computational time to decrypt it.

## Purpose

The tool uses a Proof-of-Work (PoW) mechanism based on SHA-256 hashing to time-lock encrypted data. The primary use case is preventing impulsive access to accounts (e.g., gaming accounts) by requiring a forced waiting period equal to the original encryption time.

## Project Structure

```
.
├── main.py        # CLI entry point (generate-password, encrypt, decrypt commands)
├── puzzle.py      # Core time-lock puzzle logic (PoW via SHA-256 hashing)
├── randpass.py    # Random password generation utility
├── progress.py    # tqdm progress bar wrapper
├── requirements.txt
└── README.md
```

## Technologies

- **Language**: Python 3.12
- **CLI**: typer
- **Cryptography**: cryptography (Fernet), hashlib (SHA-256)
- **Progress**: tqdm

## Usage

```bash
# Generate a random password
python main.py generate-password

# Encrypt a value (default: 1 hour decryption time)
python main.py encrypt "mypassword" --time-in-seconds 10

# Decrypt from a file
python main.py decrypt output.json
```

## Workflow

The app runs as a console CLI tool. The "Start application" workflow shows the help screen.
