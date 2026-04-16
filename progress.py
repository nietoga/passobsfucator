"""tqdm-based progress bar helper."""

from tqdm import tqdm


class ProgressBar:
    """Wraps a tqdm bar and accepts monotonically-increasing percentage updates."""

    def __init__(self) -> None:
        self._percentage = 0
        self._pbar = tqdm(total=100, unit="%", leave=True)

    def set_progress(self, percentage: int) -> None:
        """Advance the bar to *percentage* (clamped to [0, 100])."""
        percentage = max(0, min(percentage, 100))
        delta = percentage - self._percentage
        if delta > 0:
            self._percentage = percentage
            self._pbar.update(delta)

    def close(self) -> None:
        """Close the underlying tqdm bar."""
        self._pbar.close()

    # Context manager support so callers can use `with ProgressBar() as pb:`
    def __enter__(self) -> "ProgressBar":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
