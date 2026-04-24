"""CLI entry-point for the time-lock password obfuscation tool."""

import base64
import binascii
import json
from contextlib import nullcontext
from datetime import timedelta
from pathlib import Path
from typing import Annotated, Optional

import typer

import puzzle
import randpass
from progress import ProgressBar

app = typer.Typer(help="Password obfuscation utility using time-lock encryption.")


def _progress_context(show_progress: bool) -> tuple[object, puzzle.ProgressCallback]:
    """Return a context manager and callback based on progress-bar preference."""
    if show_progress:
        progress_bar = ProgressBar()
        return progress_bar, progress_bar.set_progress
    return nullcontext(), None


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
    show_progress: Annotated[
        bool,
        typer.Option(
            "--show-progress",
            help="Show tqdm progress bar during key derivation.",
        ),
    ] = False,
) -> None:
    """Encrypt VALUE so that decryption requires ~TIME_IN_SECONDS of CPU time.

    Both encryption and decryption consume approximately the same amount of time.
    The exact decryption time may vary slightly depending on the machine's speed.
    """
    chosen_seed = seed or randpass.generate(10)
    delta = timedelta(seconds=time_in_seconds)

    try:
        strategy = puzzle.build_strategy(
            algorithm,
            scrypt_n=scrypt_n,
            scrypt_r=scrypt_r,
            scrypt_p=scrypt_p,
        )
    except ValueError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    progress_context, progress_callback = _progress_context(show_progress)
    with progress_context:
        _, work_units, encrypted, strategy_payload = puzzle.encrypt_with_strategy(
            chosen_seed.encode(),
            delta,
            value.encode(),
            strategy=strategy,
            progress_callback=progress_callback,
        )

    output = {
        "algorithm": strategy.name,
        "seed": chosen_seed,
        "work_units": work_units,
        "encrypted": encrypted.decode(),
        **strategy_payload,
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
    show_progress: Annotated[
        bool,
        typer.Option(
            "--show-progress",
            help="Show tqdm progress bar during key derivation replay.",
        ),
    ] = False,
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
        # Backward compatibility: old payloads used "iters", new payloads use "work_units".
        work_units = int(payload["work_units"] if "work_units" in payload else payload["iters"])

        strategy_kwargs: dict[str, int | bytes | None] = {}
        if algorithm == puzzle.ALGORITHM_SCRYPT:
            scrypt_params = payload["scrypt"]
            strategy_kwargs = {
                "scrypt_n": int(scrypt_params["n"]),
                "scrypt_r": int(scrypt_params["r"]),
                "scrypt_p": int(scrypt_params["p"]),
                "scrypt_salt": base64.urlsafe_b64decode(scrypt_params["salt"].encode()),
            }

        strategy = puzzle.build_strategy(algorithm, **strategy_kwargs)
        progress_context, progress_callback = _progress_context(show_progress)
        with progress_context:
            _, decrypted = puzzle.decrypt_with_strategy(
                seed.encode(),
                work_units,
                encrypted.encode(),
                strategy=strategy,
                progress_callback=progress_callback,
            )
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
