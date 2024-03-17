from datetime import timedelta
from progress import ProgressBar

import randpass
import puzzle
import typer

app = typer.Typer(help="Password obsfucation utility.")


@app.command()
def generate(length: int) -> None:
    """
    Generate a random password with a given length.
    """
    password = randpass.generate(length)
    print(password)


@app.command()
def encrypt(seed: str, time: int, value: str) -> None:
    """
    Encrypt a value with the intention to decrypt it later spending X amount of time.
    """
    delta = timedelta(seconds=time)
    progress_bar = ProgressBar()
    _, iters, encrypted = puzzle.encrypt(seed, delta, value, progress_bar.set_progress)
    print(iters)
    print(encrypted)


@app.command()
def decrypt(seed: str, iters: int, value: str) -> None:
    """
    Decrypt a value encrypted with the encrypt command.
    """
    progress_bar = ProgressBar()
    _, decrypted = puzzle.decrypt(seed, iters, value, progress_bar.set_progress)
    print(decrypted)


if __name__ == "__main__":
    app()
