from datetime import timedelta
from progress import ProgressBar
from datetime import datetime
import json

import randpass
import puzzle
import typer

app = typer.Typer(help="Password obsfucation utility.")


@app.command()
def generate_password(length: int = 10) -> None:
    """
    Generate a random password with a given length.
    """
    password = randpass.generate(length)
    print(password)


@app.command()
def encrypt(
    value: str,
    time_in_seconds: int = 3600,
    seed: str = randpass.generate(10),
    output_file: str = "",
) -> None:
    """
    Encrypt a value with the intention to decrypt it later spending X amount of time.
    Keep in mind it takes X time to encrypt it and it might take a little more or a little less time to decrypt it.
    That will depend on processor's capacity and laptop usage during decyrpt.
    """
    delta = timedelta(seconds=time_in_seconds)
    progress_bar = ProgressBar()
    _, iters, encrypted = puzzle.encrypt(seed, delta, value, progress_bar.set_progress)
    progress_bar.close()

    output_dict = {
        "seed": seed,
        "iters": iters,
        "encrypted": encrypted.decode(),
    }

    if not output_file:
        print(json.dumps(output_dict, indent=4))
    else:
        with open(output_file, "w") as output_file:
            json.dump(output_dict, output_file, indent=4)


@app.command()
def decrypt(
    input_file: str,
    output_file: str = "",
) -> None:
    """
    Decrypt a value encrypted with the encrypt command.
    """
    with open(input_file, "r") as input_file:
        input_dict = json.load(input_file)
        seed = input_dict["seed"]
        iters = input_dict["iters"]
        value = input_dict["encrypted"]

    start = datetime.now()
    progress_bar = ProgressBar()
    _, decrypted = puzzle.decrypt(seed, iters, value, progress_bar.set_progress)
    progress_bar.close()
    end = datetime.now()

    time_spent_in_seconds = int((end - start).total_seconds())

    output_dict = {
        "seed": seed,
        "time_in_seconds": time_spent_in_seconds,
        "decrypted": decrypted.decode(),
    }

    if not output_file:
        print(json.dumps(output_dict, indent=4))
    else:
        with open(output_file, "w") as output_file:
            json.dump(output_dict, output_file, indent=4)


if __name__ == "__main__":
    app()
