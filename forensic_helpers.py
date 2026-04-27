import os
import struct
from datetime import datetime, timezone, timedelta

FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def filetime_to_dt(filetime: int) -> str | None:
    """Convert a Windows FILETIME (100-nanosecond intervals since 1601) to an ISO 8601 UTC string."""
    if filetime == 0:
        return None
    try:
        dt = FILETIME_EPOCH + timedelta(microseconds=filetime // 10)
        return str(dt)
    except (OverflowError, ValueError):
        return None


def format_file_size(size_bytes: int) -> str:
    """Convert a byte count to a human-readable size string."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 ** 2:
        return f"{size_bytes / 1024:.2f} KB"
    elif size_bytes < 1024 ** 3:
        return f"{size_bytes / 1024 ** 2:.2f} MB"
    else:
        return f"{size_bytes / 1024 ** 3:.2f} GB"


def extract_files(path: str, extension: str) -> list[str]:
    """Return a list of files in a directory matching the given extension."""
    return [os.path.join(path, f) for f in os.listdir(path) if f.lower().endswith(extension)]
