"""CLI entry-point for the time-lock password obfuscation tool."""

import base64
import binascii
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
    algorithm: Annotated[
        str,
        typer.Option(
            help=(
                "Key-derivation algorithm: 'sha256-chain' (time-lock) "
                "or 'scrypt' (memory-hard, more resistant to GPU attacks)."
            )
        ),
    ] = puzzle.ALGORITHM_SHA256_CHAIN,
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
    scrypt_n: Annotated[
        int,
        typer.Option(
            help="scrypt N cost parameter (power of two; only for --algorithm scrypt)."
        ),
    ] = 2**14,
    scrypt_r: Annotated[
        int,
        typer.Option(help="scrypt r block-size parameter (only for scrypt)."),
    ] = 8,
    scrypt_p: Annotated[
        int,
        typer.Option(help="scrypt p parallelization parameter (only for scrypt)."),
    ] = 1,
) -> None:
    """Encrypt VALUE so that decryption requires ~TIME_IN_SECONDS of CPU time.

    Both encryption and decryption consume approximately the same amount of time.
    The exact decryption time may vary slightly depending on the machine's speed.
    """
    chosen_seed = seed or randpass.generate(10)

    if algorithm == puzzle.ALGORITHM_SHA256_CHAIN:
        delta = timedelta(seconds=time_in_seconds)
        with ProgressBar() as progress_bar:
            _, iters, encrypted = puzzle.encrypt(
                chosen_seed.encode(), delta, value.encode(), progress_bar.set_progress
            )

        output = {
            "algorithm": puzzle.ALGORITHM_SHA256_CHAIN,
            "seed": chosen_seed,
            "iters": iters,
            "encrypted": encrypted.decode(),
        }
    elif algorithm == puzzle.ALGORITHM_SCRYPT:
        try:
            with ProgressBar() as progress_bar:
                _, salt, encrypted = puzzle.encrypt_scrypt(
                    chosen_seed.encode(),
                    value.encode(),
                    n=scrypt_n,
                    r=scrypt_r,
                    p=scrypt_p,
                    progress_callback=progress_bar.set_progress,
                )
        except ValueError as exc:
            typer.echo(f"Error: {exc}", err=True)
            raise typer.Exit(code=1) from exc

        output = {
            "algorithm": puzzle.ALGORITHM_SCRYPT,
            "seed": chosen_seed,
            "scrypt": {
                "n": scrypt_n,
                "r": scrypt_r,
                "p": scrypt_p,
                "salt": base64.urlsafe_b64encode(salt).decode(),
            },
            "encrypted": encrypted.decode(),
        }
    else:
        typer.echo(
            "Error: Unsupported algorithm. Use 'sha256-chain' or 'scrypt'.",
            err=True,
        )
        raise typer.Exit(code=1)

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

    algorithm = payload.get("algorithm", puzzle.ALGORITHM_SHA256_CHAIN)

    try:
        seed: str = payload["seed"]
        encrypted: str = payload["encrypted"]
    except KeyError as exc:
        typer.echo(f"Error reading {input_file}: missing required field {exc}", err=True)
        raise typer.Exit(code=1) from exc

    try:
        if algorithm == puzzle.ALGORITHM_SHA256_CHAIN:
            iters = int(payload["iters"])
            with ProgressBar() as progress_bar:
                _, decrypted = puzzle.decrypt(
                    seed.encode(), iters, encrypted.encode(), progress_bar.set_progress
                )
        elif algorithm == puzzle.ALGORITHM_SCRYPT:
            scrypt_params = payload["scrypt"]
            n = int(scrypt_params["n"])
            r = int(scrypt_params["r"])
            p = int(scrypt_params["p"])
            salt = base64.urlsafe_b64decode(scrypt_params["salt"].encode())
            with ProgressBar() as progress_bar:
                _, decrypted = puzzle.decrypt_scrypt(
                    seed.encode(),
                    encrypted.encode(),
                    salt=salt,
                    n=n,
                    r=r,
                    p=p,
                    progress_callback=progress_bar.set_progress,
                )
        else:
            typer.echo(
                "Error reading input file: unsupported algorithm. "
                "Use 'sha256-chain' or 'scrypt'.",
                err=True,
            )
            raise typer.Exit(code=1)
    except (KeyError, TypeError, ValueError, binascii.Error) as exc:
        typer.echo(f"Error reading {input_file}: malformed encryption payload ({exc})", err=True)
        raise typer.Exit(code=1) from exc

    output = {"algorithm": algorithm, "seed": seed, "decrypted": decrypted.decode()}

    if output_file is None:
        typer.echo(json.dumps(output, indent=4))
    else:
        output_file.write_text(json.dumps(output, indent=4))


if __name__ == "__main__":
    app()
