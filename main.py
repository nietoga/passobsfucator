"""CLI entry-point for the time-lock password obfuscation tool."""

import json
from datetime import timedelta
from pathlib import Path
from typing import Annotated, Optional

import typer

import puzzle
import randpass
from progress import ProgressBar

app = typer.Typer(help="Password obfuscation utility using time-lock encryption.")


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
    seed: Annotated[
        Optional[str],
        typer.Option(help="Custom seed (generated randomly when omitted)."),
    ] = None,
    output_file: Annotated[
        Optional[Path],
        typer.Option(help="Write JSON output here instead of stdout."),
    ] = None,
) -> None:
    """Encrypt VALUE so that decryption requires ~TIME_IN_SECONDS of CPU time.

    Both encryption and decryption consume approximately the same amount of time.
    The exact decryption time may vary slightly depending on the machine's speed.
    """
    chosen_seed = seed or randpass.generate(10)
    delta = timedelta(seconds=time_in_seconds)

    with ProgressBar() as progress_bar:
        _, iters, encrypted = puzzle.encrypt(
            chosen_seed.encode(), delta, value.encode(), progress_bar.set_progress
        )

    output = {
        "seed": chosen_seed,
        "iters": iters,
        "encrypted": encrypted.decode(),
    }

    if output_file is None:
        typer.echo(json.dumps(output, indent=4))
    else:
        output_file.write_text(json.dumps(output, indent=4))


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
    """Decrypt a value previously encrypted with the encrypt command."""
    try:
        payload = json.loads(input_file.read_text())
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        typer.echo(f"Error reading {input_file}: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    seed: str = payload["seed"]
    iters: int = payload["iters"]
    encrypted: str = payload["encrypted"]

    with ProgressBar() as progress_bar:
        _, decrypted = puzzle.decrypt(
            seed.encode(), iters, encrypted.encode(), progress_bar.set_progress
        )

    output = {
        "seed": seed,
        "decrypted": decrypted.decode(),
    }

    if output_file is None:
        typer.echo(json.dumps(output, indent=4))
    else:
        output_file.write_text(json.dumps(output, indent=4))


if __name__ == "__main__":
    app()
