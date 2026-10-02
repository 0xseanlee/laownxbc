#!/usr/bin/env python3

import sys
import time
from progress import Progress

class Progress:
    """
    Reusable terminal progress bar.

    Example:

        from progress import Progress

        p = Progress(total=1000000, label="Scanning")
        for i in range(1000000):
            ...
            p.update(i + 1)
        p.finish()
    """

    def __init__(
        self,
        total,
        label="Working",
        width=28,
        min_interval=0.25,
        stream=None,
        enabled=True,
    ):
        self.total = max(int(total), 1)
        self.label = str(label)
        self.width = max(int(width), 10)
        self.min_interval = float(min_interval)
        self.stream = stream or sys.stderr
        self.enabled = enabled

        self.start_time = time.monotonic()
        self.last_draw = 0.0
        self.current = 0

    @staticmethod
    def _time(seconds):
        if seconds is None:
            return "--:--"

        seconds = max(int(seconds), 0)

        if seconds < 60:
            return f"{seconds}s"

        minutes, seconds = divmod(seconds, 60)

        if minutes < 60:
            return f"{minutes:02d}:{seconds:02d}"

        hours, minutes = divmod(minutes, 60)

        return f"{hours:d}:{minutes:02d}:{seconds:02d}"

    def update(self, current, force=False):
        if not self.enabled:
            return

        current = min(max(int(current), 0), self.total)
        now = time.monotonic()

        if (
            not force
            and current < self.total
            and now - self.last_draw < self.min_interval
        ):
            return

        self.current = current
        self.last_draw = now

        ratio = current / self.total
        percent = ratio * 100

        filled = int(ratio * self.width)

        if filled >= self.width:
            bar = "=" * self.width
        else:
            bar = (
                "=" * filled
                + ">"
                + "." * max(self.width - filled - 1, 0)
            )

        elapsed = now - self.start_time

        if current > 0:
            rate = current / max(elapsed, 0.000001)
            remaining = self.total - current
            eta = remaining / rate if rate > 0 else None
        else:
            rate = 0
            eta = None

        line = (
            f"\r{self.label:<18} "
            f"[{bar}] "
            f"{percent:6.2f}% "
            f"{current:,}/{self.total:,} "
            f"| {rate:,.0f}/s "
            f"| ETA {self._time(eta)} "
            f"| elapsed {self._time(elapsed)}"
        )

        self.stream.write(line)
        self.stream.flush()

    def finish(self):
        self.update(self.total, force=True)

        if self.enabled:
            self.stream.write("\n")
            self.stream.flush()


def progress_range(
    start,
    stop=None,
    step=1,
    label="Working",
    width=28,
    min_interval=0.25,
):
    """
    Drop-in-ish replacement for range() with progress display.

    Example:

        for off in progress_range(
            0,
            len(data),
            4,
            label="ARM64 scan"
        ):
            ...
    """

    if stop is None:
        stop = start
        start = 0

    r = range(start, stop, step)
    total = len(r)

    p = Progress(
        total=total,
        label=label,
        width=width,
        min_interval=min_interval,
    )

    try:
        for index, value in enumerate(r, 1):
            yield value
            p.update(index)

    finally:
        if p.current < p.total:
            p.update(p.current, force=True)
            p.stream.write("\n")
            p.stream.flush()
        else:
            p.finish()