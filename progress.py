from tqdm import tqdm


class ProgressBar:
    def __init__(self) -> None:
        self._percentage = 0
        self._pbar = tqdm(range(100))

    def set_progress(self, percentage: int):
        percentage = max(min(percentage, 100), 0)
        change = percentage - self._percentage

        if change > 0:
            self._percentage = percentage
            self._pbar.update(change)
