import os
import json
import struct
from forensic_helpers import filetime_to_dt, format_file_size, extract_files

BIN_DIR = os.path.join("C:\\", "$Recycle.Bin")

WIN_VER = {
    1: "Vista/7/8",
    2: "Windows 10/11",
}


def metadata_file_parse(i_file_list):
    for metadata_file in i_file_list:
        with open(metadata_file, "rb") as f:
            data = f.read()
        win_ver = WIN_VER.get(struct.unpack_from('<Q', data, 0)[0], "Unknown")
        logical_file_size = format_file_size(struct.unpack_from('<Q', data, 8)[0])
        deletion_timestamp = filetime_to_dt(struct.unpack_from('<Q', data, 16)[0])
        print(deletion_timestamp)


def main():
    sid_dirs = [
        os.path.join(BIN_DIR, f) for f in os.listdir(BIN_DIR)
        if f.startswith("S-") and os.path.isdir(os.path.join(BIN_DIR, f))
    ]
    for path in sid_dirs:
        i_files = extract_files(path, prefix="$I")
        metadata_file_parse(i_files)


if __name__ == "__main__":
    main()
