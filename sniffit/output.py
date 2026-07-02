"""Output helpers."""

from __future__ import annotations

from typing import TextIO


def emit(lines: list[str], log_file: TextIO) -> None:
    """Print formatted lines and append them to log file."""
    if not lines:
        return

    text = "\n".join(lines)
    print(text)
    print()

    log_file.write(text)
    log_file.write("\n\n")
