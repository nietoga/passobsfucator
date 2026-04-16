"""Integration tests for the Typer CLI."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from main import app

runner = CliRunner()


def _extract_json(text: str) -> dict:
    """Extract the JSON object from output that may contain tqdm/stderr noise."""
    start = text.find("{")
    end = text.rfind("}") + 1
    return json.loads(text[start:end])


# ---------------------------------------------------------------------------
# generate-password
# ---------------------------------------------------------------------------


class TestGeneratePasswordCommand:
    def test_default_length(self) -> None:
        result = runner.invoke(app, ["generate-password"])
        assert result.exit_code == 0
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


# ---------------------------------------------------------------------------
# encrypt + decrypt (sha256)
# ---------------------------------------------------------------------------


class TestEncryptSha256Command:
    def test_stdout_output_has_required_fields(self) -> None:
        result = runner.invoke(app, ["encrypt", "mypassword", "--time-in-seconds", "1"])
        assert result.exit_code == 0
        data = _extract_json(result.output)
        assert data["algorithm"] == "sha256"
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
        assert data["algorithm"] == "sha256"
        assert data["encrypted"]

    def test_custom_seed_is_preserved(self) -> None:
        result = runner.invoke(
            app,
            ["encrypt", "mypassword", "--time-in-seconds", "1", "--seed", "myseed"],
        )
        assert result.exit_code == 0
        assert _extract_json(result.output)["seed"] == "myseed"

    def test_iters_is_positive(self) -> None:
        result = runner.invoke(app, ["encrypt", "x", "--time-in-seconds", "1"])
        assert result.exit_code == 0
        assert _extract_json(result.output)["iters"] > 0


class TestDecryptSha256Command:
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
        assert _extract_json(result.output)["decrypted"] == "hello-world"

    def test_round_trip_output_file(self, tmp_path: Path) -> None:
        enc_file = self._encrypt_to_file(tmp_path, "hello-world")
        dec_file = tmp_path / "dec.json"
        result = runner.invoke(app, ["decrypt", str(enc_file), "--output-file", str(dec_file)])
        assert result.exit_code == 0
        assert json.loads(dec_file.read_text())["decrypted"] == "hello-world"

    def test_missing_input_file_exits_with_error(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["decrypt", str(tmp_path / "nonexistent.json")])
        assert result.exit_code != 0

    def test_backward_compat_no_algorithm_field(self, tmp_path: Path) -> None:
        """Files without an 'algorithm' field should be treated as sha256."""
        enc_file = self._encrypt_to_file(tmp_path, "compat-test")
        payload = json.loads(enc_file.read_text())
        del payload["algorithm"]
        enc_file.write_text(json.dumps(payload))

        result = runner.invoke(app, ["decrypt", str(enc_file)])
        assert result.exit_code == 0
        assert _extract_json(result.output)["decrypted"] == "compat-test"


# ---------------------------------------------------------------------------
# encrypt + decrypt (argon2)
# ---------------------------------------------------------------------------


class TestEncryptArgon2Command:
    def test_stdout_output_has_required_fields(self) -> None:
        result = runner.invoke(
            app,
            ["encrypt", "mypassword", "--time-in-seconds", "1", "--algorithm", "argon2"],
        )
        assert result.exit_code == 0
        data = _extract_json(result.output)
        assert data["algorithm"] == "argon2"
        assert "salt" in data
        assert "time_cost" in data
        assert "memory_cost_kb" in data
        assert "parallelism" in data
        assert "estimated_seconds" in data
        assert "encrypted" in data

    def test_estimated_seconds_is_positive(self) -> None:
        result = runner.invoke(
            app,
            ["encrypt", "x", "--time-in-seconds", "1", "--algorithm", "argon2"],
        )
        assert result.exit_code == 0
        assert _extract_json(result.output)["estimated_seconds"] > 0

    def test_output_file(self, tmp_path: Path) -> None:
        out = tmp_path / "enc.json"
        result = runner.invoke(
            app,
            [
                "encrypt", "mypassword",
                "--time-in-seconds", "1",
                "--algorithm", "argon2",
                "--output-file", str(out),
            ],
        )
        assert result.exit_code == 0
        data = json.loads(out.read_text())
        assert data["algorithm"] == "argon2"
        assert data["encrypted"]

    def test_time_cost_is_positive(self) -> None:
        result = runner.invoke(
            app,
            ["encrypt", "x", "--time-in-seconds", "1", "--algorithm", "argon2"],
        )
        assert result.exit_code == 0
        assert _extract_json(result.output)["time_cost"] >= 1


class TestDecryptArgon2Command:
    def _encrypt_to_file(self, tmp_path: Path, plaintext: str = "secret") -> Path:
        enc_file = tmp_path / "enc.json"
        runner.invoke(
            app,
            [
                "encrypt", plaintext,
                "--time-in-seconds", "1",
                "--algorithm", "argon2",
                "--output-file", str(enc_file),
            ],
        )
        return enc_file

    def test_round_trip_stdout(self, tmp_path: Path) -> None:
        enc_file = self._encrypt_to_file(tmp_path, "hello-argon2")
        result = runner.invoke(app, ["decrypt", str(enc_file)])
        assert result.exit_code == 0
        assert _extract_json(result.output)["decrypted"] == "hello-argon2"

    def test_round_trip_with_progress(self, tmp_path: Path) -> None:
        """Decrypt should show a progress bar (estimated_seconds present in file)."""
        enc_file = self._encrypt_to_file(tmp_path, "progress-test")
        result = runner.invoke(app, ["decrypt", str(enc_file)])
        assert result.exit_code == 0

    def test_round_trip_output_file(self, tmp_path: Path) -> None:
        enc_file = self._encrypt_to_file(tmp_path, "hello-argon2")
        dec_file = tmp_path / "dec.json"
        result = runner.invoke(app, ["decrypt", str(enc_file), "--output-file", str(dec_file)])
        assert result.exit_code == 0
        assert json.loads(dec_file.read_text())["decrypted"] == "hello-argon2"

    def test_round_trip_without_estimated_seconds(self, tmp_path: Path) -> None:
        """Old Argon2 files without estimated_seconds should still decrypt fine."""
        enc_file = self._encrypt_to_file(tmp_path, "no-estimate")
        payload = json.loads(enc_file.read_text())
        payload.pop("estimated_seconds", None)
        enc_file.write_text(json.dumps(payload))

        result = runner.invoke(app, ["decrypt", str(enc_file)])
        assert result.exit_code == 0
        assert _extract_json(result.output)["decrypted"] == "no-estimate"

    def test_unknown_algorithm_in_file_exits_with_error(self, tmp_path: Path) -> None:
        enc_file = tmp_path / "bad.json"
        enc_file.write_text(json.dumps({"algorithm": "bcrypt", "encrypted": "x"}))
        result = runner.invoke(app, ["decrypt", str(enc_file)])
        assert result.exit_code != 0
