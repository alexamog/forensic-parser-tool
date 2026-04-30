import os
import json
import winreg
import struct
from forensic_helpers import filetime_to_dt, require_admin

KEY_PATH = r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
ENTRY_SIGNATURE = b"10ts"


def shimcache_parser():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, KEY_PATH)
        raw_data, _ = winreg.QueryValueEx(key, "AppCompatCache")
        entry_offset = struct.unpack_from("<I", raw_data, 0)[0]
        results = []

        while entry_offset < len(raw_data) - 4:
            if raw_data[entry_offset:entry_offset + 4] != ENTRY_SIGNATURE:
                break
            path_length = struct.unpack_from(
                "<H", raw_data, entry_offset + 12)[0]
            path = raw_data[entry_offset + 14:entry_offset +
                            14 + path_length].decode("utf-16-le")
            last_modified = filetime_to_dt(struct.unpack_from(
                "<Q", raw_data, entry_offset + path_length + 14)[0])
            data_size = struct.unpack_from(
                "<I", raw_data, entry_offset+22 + path_length)[0]
            results.append({
                "path": path,
                "last_modified": last_modified,
            })
            entry_offset += path_length + data_size + 26
        return results
    except Exception as e:
        print(print(f"Error parsing Shimcache: {e}"))
        return []


def main():
    require_admin()
    results = shimcache_parser()
    os.makedirs("results", exist_ok=True)
    with open(os.path.join("results", "shimcache_results.json"), "w") as f:
        json.dump(results, f, indent=4)
    print(
        f"Parsed {len(results)} entries. Results saved to: results/shimcache_results.json")


if __name__ == "__main__":
    main()
