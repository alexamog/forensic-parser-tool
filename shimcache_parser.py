import os
import json
import winreg
import struct
from forensic_helpers import filetime_to_dt, format_file_size, extract_files, require_admin

key_path = r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"


def shimcache_parser():

    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
    raw_data, _ = winreg.QueryValueEx(key, "AppCompatCache")
    for data in raw_data:
        struct.unpack_from("<I", data, 0)[0]


def main():
    shimcache_parser()


if __name__ == "__main__":
    main()
