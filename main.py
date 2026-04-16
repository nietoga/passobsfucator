"""CLI entry-point for the time-lock password obfuscation tool."""

import json
from datetime import timedelta
from enum import Enum
from pathlib import Path
from typing import Annotated, Optional

import typer

import puzzle
import puzzle_argon2
import randpass
from progress import ProgressBar

app = typer.Typer(help="Password obfuscation utility using time-lock encryption.")

# Algorithm identifier written into / read from the JSON payload.
# Old files without this field are treated as sha256 for backward compatibility.
_ALGORITHM_KEY = "algorithm"
_DEFAULT_ALGORITHM = "sha256"


class Algorithm(str, Enum):
    """Supported time-lock algorithms."""

    sha256 = "sha256"
    argon2 = "argon2"


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@app.command()
def generate_password(
    length: Annotated[int, typer.Option(help="Password length (minimum 4).")] = 10,
) -> None:
    """Generate a cryptographically secure random password."""
    try:
        password = randpass.generate(length)
    except ValueError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(password)


@app.command()
def encrypt(
    value: Annotated[str, typer.Argument(help="Plaintext value to encrypt.")],
    time_in_seconds: Annotated[
        int, typer.Option(help="CPU seconds required to decrypt.")
    ] = 3600,
    algorithm: Annotated[
        Algorithm,
        typer.Option(
            help=(
                "Key-derivation algorithm.  "
                "sha256: sequential SHA-256 chain (fast, not ASIC-resistant).  "
                "argon2: Argon2id memory-hard KDF (resistant to GPU/ASIC attacks)."
            ),
            case_sensitive=False,
        ),
    ] = Algorithm.sha256,
    seed: Annotated[
        Optional[str],
        typer.Option(
            help="[sha256 only] Custom seed (generated randomly when omitted)."
        ),
    ] = None,
    output_file: Annotated[
        Optional[Path],
        typer.Option(help="Write JSON output here instead of stdout."),
    ] = None,
) -> None:
    """Encrypt VALUE so that decryption requires ~TIME_IN_SECONDS of CPU time.

    Both encryption and decryption consume approximately the same amount of time.
    Choose --algorithm argon2 for resistance against GPU and ASIC acceleration.
    """
    if algorithm is Algorithm.sha256:
        output = _encrypt_sha256(value, time_in_seconds, seed)
    else:
        output = _encrypt_argon2(value, time_in_seconds)

    _write_output(output, output_file)


@app.command()
def decrypt(
    input_file: Annotated[
        Path, typer.Argument(help="JSON file produced by the encrypt command.")
    ],
    output_file: Annotated[
        Optional[Path],
        typer.Option(help="Write JSON output here instead of stdout."),
    ] = None,
) -> None:
    """Decrypt a value previously encrypted with the encrypt command.

    The algorithm is detected automatically from the input file.
    """
    try:
        payload = json.loads(input_file.read_text())
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        typer.echo(f"Error reading {input_file}: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    detected = payload.get(_ALGORITHM_KEY, _DEFAULT_ALGORITHM)

    if detected == Algorithm.sha256:
        output = _decrypt_sha256(payload)
    elif detected == Algorithm.argon2:
        output = _decrypt_argon2(payload)
    else:
        typer.echo(f"Error: unknown algorithm '{detected}' in {input_file}", err=True)
        raise typer.Exit(code=1)

    _write_output(output, output_file)


# ---------------------------------------------------------------------------
# SHA-256 chain helpers
# ---------------------------------------------------------------------------


def _encrypt_sha256(value: str, time_in_seconds: int, seed: Optional[str]) -> dict:
    chosen_seed = seed or randpass.generate(10)
    delta = timedelta(seconds=time_in_seconds)

    with ProgressBar() as pb:
        _, iters, encrypted = puzzle.encrypt(
            chosen_seed.encode(), delta, value.encode(), pb.set_progress
        )

    return {
        _ALGORITHM_KEY: Algorithm.sha256,
        "seed": chosen_seed,
        "iters": iters,
        "encrypted": encrypted.decode(),
    }


def _decrypt_sha256(payload: dict) -> dict:
    seed: str = payload["seed"]
    iters: int = payload["iters"]
    encrypted: str = payload["encrypted"]

    with ProgressBar() as pb:
        _, decrypted = puzzle.decrypt(
            seed.encode(), iters, encrypted.encode(), pb.set_progress
        )

    return {"algorithm": Algorithm.sha256, "seed": seed, "decrypted": decrypted.decode()}


# ---------------------------------------------------------------------------
# Argon2id helpers
# ---------------------------------------------------------------------------


def _encrypt_argon2(value: str, time_in_seconds: int) -> dict:
    typer.echo("Calibrating Argon2id parameters…", err=True)
    with ProgressBar() as pb:
        salt, time_cost, memory_cost_kb, parallelism, estimated_seconds, ciphertext = (
            puzzle_argon2.encrypt(
                target_seconds=float(time_in_seconds),
                message=value.encode(),
                progress_callback=pb.set_progress,
            )
        )

    return {
        _ALGORITHM_KEY: Algorithm.argon2,
        "salt": salt.hex(),
        "time_cost": time_cost,
        "memory_cost_kb": memory_cost_kb,
        "parallelism": parallelism,
        "estimated_seconds": round(estimated_seconds, 2),
        "encrypted": ciphertext.decode(),
    }


def _decrypt_argon2(payload: dict) -> dict:
    salt = bytes.fromhex(payload["salt"])
    time_cost: int = payload["time_cost"]
    memory_cost_kb: int = payload.get("memory_cost_kb", puzzle_argon2.DEFAULT_MEMORY_COST_KB)
    parallelism: int = payload.get("parallelism", puzzle_argon2.DEFAULT_PARALLELISM)
    estimated_seconds: float | None = payload.get("estimated_seconds")
    ciphertext: str = payload["encrypted"]

    with ProgressBar() as pb:
        decrypted = puzzle_argon2.decrypt(
            salt=salt,
            time_cost=time_cost,
            ciphertext=ciphertext.encode(),
            memory_cost_kb=memory_cost_kb,
            parallelism=parallelism,
            expected_seconds=estimated_seconds,
            progress_callback=pb.set_progress,
        )

    return {"algorithm": Algorithm.argon2, "decrypted": decrypted.decode()}


# ---------------------------------------------------------------------------
# Shared output helper
# ---------------------------------------------------------------------------


def _write_output(data: dict, output_file: Optional[Path]) -> None:
    text = json.dumps(data, indent=4)
    if output_file is None:
        typer.echo(text)
    else:
        output_file.write_text(text)


if __name__ == "__main__":
    app()
