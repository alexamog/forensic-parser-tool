import os
import ctypes
import sys
import struct
from forensic_helpers import filetime_to_dt, format_file_size, extract_files


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


if not is_admin():
    print("Error: This script must be run as administrator.")
    sys.exit(1)

PF_FILE_DIR = os.path.join("C:\\", "Windows", "Prefetch")


def prefetch_parser(pf_files: list[str]) -> list[dict]:
    for pf_file in pf_files:
        try:
            with open(pf_file, "rb") as f:
                data = f.read()
        except Exception as e:
            print(e)


if __name__ == "__main__":
    is_admin()
    pf_files = extract_files(PF_FILE_DIR, ".pf")
    prefetch_parser(pf_files)
