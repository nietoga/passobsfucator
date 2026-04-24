"""Integration tests for the Typer CLI."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from main import app

runner = CliRunner()


def _extract_json(text: str) -> dict:
    """Extract the JSON object from output that may contain tqdm progress noise."""
    start = text.find("{")
    end = text.rfind("}") + 1
    return json.loads(text[start:end])


class TestGeneratePasswordCommand:
    def test_default_length(self) -> None:
        result = runner.invoke(app, ["generate-password"])
        assert result.exit_code == 0
        # The password is the last non-empty line (tqdm goes to same stream in tests)
        lines = [ln for ln in result.output.splitlines() if ln.strip() and not ln.startswith("\r")]
        assert len(lines[-1].strip()) == 10

    def test_custom_length(self) -> None:
        result = runner.invoke(app, ["generate-password", "--length", "20"])
        assert result.exit_code == 0
        lines = [ln for ln in result.output.splitlines() if ln.strip() and not ln.startswith("\r")]
        assert len(lines[-1].strip()) == 20

    def test_too_short_exits_with_error(self) -> None:
        result = runner.invoke(app, ["generate-password", "--length", "3"])
        assert result.exit_code != 0


class TestEncryptCommand:
    def test_stdout_output(self) -> None:
        result = runner.invoke(
            app,
            ["encrypt", "mypassword", "--time-in-seconds", "1"],
        )
        assert result.exit_code == 0
        data = _extract_json(result.output)
        assert "seed" in data
        assert "iters" in data
        assert "encrypted" in data

    def test_output_file(self, tmp_path: Path) -> None:
        out = tmp_path / "enc.json"
        result = runner.invoke(
            app,
            ["encrypt", "mypassword", "--time-in-seconds", "1", "--output-file", str(out)],
        )
        assert result.exit_code == 0
        data = json.loads(out.read_text())
        assert data["encrypted"]

    def test_custom_seed_is_preserved(self) -> None:
        result = runner.invoke(
            app,
            ["encrypt", "mypassword", "--time-in-seconds", "1", "--seed", "myseed"],
        )
        assert result.exit_code == 0
        data = _extract_json(result.output)
        assert data["seed"] == "myseed"

    def test_iters_is_positive(self) -> None:
        result = runner.invoke(
            app,
            ["encrypt", "x", "--time-in-seconds", "1"],
        )
        assert result.exit_code == 0
        data = _extract_json(result.output)
        assert data["iters"] > 0

    def test_scrypt_stdout_output(self) -> None:
        result = runner.invoke(
            app,
            [
                "encrypt",
                "mypassword",
                "--algorithm",
                "scrypt",
                "--scrypt-n",
                "1024",
                "--scrypt-r",
                "8",
                "--scrypt-p",
                "1",
            ],
        )
        assert result.exit_code == 0
        data = _extract_json(result.output)
        assert data["algorithm"] == "scrypt"
        assert "scrypt" in data
        assert "salt" in data["scrypt"]
        assert "encrypted" in data

    def test_invalid_algorithm_exits_with_error(self) -> None:
        result = runner.invoke(app, ["encrypt", "x", "--algorithm", "unknown"])
        assert result.exit_code != 0


class TestDecryptCommand:
    def _encrypt_to_file(self, tmp_path: Path, plaintext: str = "secret") -> Path:
        enc_file = tmp_path / "enc.json"
        runner.invoke(
            app,
            ["encrypt", plaintext, "--time-in-seconds", "1", "--output-file", str(enc_file)],
        )
        return enc_file

    def test_round_trip_stdout(self, tmp_path: Path) -> None:
        enc_file = self._encrypt_to_file(tmp_path, "hello-world")
        result = runner.invoke(app, ["decrypt", str(enc_file)])
        assert result.exit_code == 0
        data = _extract_json(result.output)
        assert data["decrypted"] == "hello-world"

    def test_round_trip_output_file(self, tmp_path: Path) -> None:
        enc_file = self._encrypt_to_file(tmp_path, "hello-world")
        dec_file = tmp_path / "dec.json"
        result = runner.invoke(app, ["decrypt", str(enc_file), "--output-file", str(dec_file)])
        assert result.exit_code == 0
        data = json.loads(dec_file.read_text())
        assert data["decrypted"] == "hello-world"

    def test_missing_input_file_exits_with_error(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["decrypt", str(tmp_path / "nonexistent.json")])
        assert result.exit_code != 0

    def test_round_trip_with_scrypt(self, tmp_path: Path) -> None:
        enc_file = tmp_path / "enc_scrypt.json"
        encrypt_result = runner.invoke(
            app,
            [
                "encrypt",
                "gpu-resistant-secret",
                "--algorithm",
                "scrypt",
                "--scrypt-n",
                "1024",
                "--output-file",
                str(enc_file),
            ],
        )
        assert encrypt_result.exit_code == 0

        result = runner.invoke(app, ["decrypt", str(enc_file)])
        assert result.exit_code == 0
        data = _extract_json(result.output)
        assert data["algorithm"] == "scrypt"
        assert data["decrypted"] == "gpu-resistant-secret"

    def test_decrypt_unknown_algorithm_exits(self, tmp_path: Path) -> None:
        bad_payload = tmp_path / "bad.json"
        bad_payload.write_text(
            json.dumps(
                {
                    "algorithm": "unknown",
                    "seed": "seed",
                    "encrypted": "x",
                }
            )
        )
        result = runner.invoke(app, ["decrypt", str(bad_payload)])
        assert result.exit_code != 0
