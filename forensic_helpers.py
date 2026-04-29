import os
import sys
import struct
import ctypes
from datetime import datetime, timezone, timedelta

FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def is_admin() -> bool:
    """Check if the script is running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def require_admin():
    """Exit with an error message if not running as administrator."""
    if not is_admin():
        print("Error: This script must be run as administrator.")
        sys.exit(1)


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


def extract_files(path: str, extension: str = "", prefix: str = "") -> list[str]:
    """Return a list of files in a directory matching the given extension and/or prefix."""
    return [
        os.path.join(path, f) for f in os.listdir(path)
        if (not extension or f.lower().endswith(extension))
        and (not prefix or f.lower().startswith(prefix.lower()))
    ]
