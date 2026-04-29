import os
import json
import struct
from forensic_helpers import filetime_to_dt, format_file_size, extract_files, require_admin

require_admin()

BIN_DIR = os.path.join("C:\\", "$Recycle.Bin")

WIN_VER = {
    1: "Vista/7/8",
    2: "Windows 10/11",
}


def parse_i_file(metadata_file: str, sid: str) -> dict:
    with open(metadata_file, "rb") as f:
        data = f.read()

    version = struct.unpack_from('<Q', data, 0)[0]
    win_ver = WIN_VER.get(version, "Unknown")
    logical_file_size = format_file_size(struct.unpack_from('<Q', data, 8)[0])
    deletion_timestamp = filetime_to_dt(struct.unpack_from('<Q', data, 16)[0])

    if version == 1:
        path_data = data[24:]
        i = 0
        while i < len(path_data) - 1:
            if path_data[i] == 0 and path_data[i + 1] == 0:
                break
            i += 2
        original_path = path_data[:i].decode("utf-16-le")
    else:
        char_count = struct.unpack_from('<I', data, 24)[0]
        original_path = data[28:28 + char_count * 2].decode("utf-16-le")

    r_filename = "$R" + os.path.basename(metadata_file)[2:]
    r_file_present = os.path.exists(os.path.join(os.path.dirname(metadata_file), r_filename))

    return {
        "file": os.path.basename(metadata_file),
        "sid": sid,
        "os_version": win_ver,
        "original_path": original_path,
        "original_file_size": logical_file_size,
        "deletion_timestamp": deletion_timestamp,
        "r_file_present": r_file_present,
    }


def recycle_bin_parser(sid_dirs: list[str]) -> list[dict]:
    results = []
    for sid_dir in sid_dirs:
        sid = os.path.basename(sid_dir)
        i_files = extract_files(sid_dir, prefix="$I")
        for metadata_file in i_files:
            try:
                results.append(parse_i_file(metadata_file, sid))
            except Exception as e:
                results.append({"file": metadata_file, "error": str(e)})
    return results


def main():
    sid_dirs = [
        os.path.join(BIN_DIR, f) for f in os.listdir(BIN_DIR)
        if f.startswith("S-") and os.path.isdir(os.path.join(BIN_DIR, f))
    ]
    results = recycle_bin_parser(sid_dirs)
    os.makedirs("results", exist_ok=True)
    with open(os.path.join("results", "recycle_bin_results.json"), "w") as f:
        json.dump(results, f, indent=4)
    print("Results saved to: results/recycle_bin_results.json")


if __name__ == "__main__":
    main()
