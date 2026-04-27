import os
import json
import struct
from forensic_helpers import filetime_to_dt, format_file_size, extract_files

username = os.getlogin()
WIN_RECENT = os.path.join("C:\\", "Users", username, "AppData", "Roaming", "Microsoft", "Windows", "Recent")
DRIVE_TYPES = {
    0: "Unknown",
    1: "No root directory",
    2: "Removable",
    3: "Fixed",
    4: "Network",
    5: "CD-ROM",
    6: "RAM disk",
}


def format_file_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 ** 2:
        return f"{size_bytes / 1024:.2f} KB"
    elif size_bytes < 1024 ** 3:
        return f"{size_bytes / 1024 ** 2:.2f} MB"
    else:
        return f"{size_bytes / 1024 ** 3:.2f} GB"


def lnk_parser(lnk_files: list[str]) -> list[dict]:
    results = []
    for lnk_file in lnk_files:
        try:
            with open(lnk_file, "rb") as f:
                data = f.read()

            # Fixed-offset fields from the Shell Link Header
            creation_time = filetime_to_dt(struct.unpack_from("<Q", data, 28)[0])
            last_access_time = filetime_to_dt(struct.unpack_from("<Q", data, 36)[0])
            last_written_time = filetime_to_dt(struct.unpack_from("<Q", data, 44)[0])
            logical_file_size = format_file_size(struct.unpack_from("<I", data, 52)[0])

            # Navigate past IDList if present to reach LinkInfo
            link_flags = struct.unpack_from("<I", data, 20)[0]
            has_id_list = bool(link_flags & 0x1)
            offset = 76
            if has_id_list:
                id_list_size = struct.unpack_from("<H", data, offset)[0]
                offset += 2 + id_list_size

            # Read VolumeID and LocalBasePath offsets from LinkInfo
            volume_id_offset = struct.unpack_from("<I", data, offset + 12)[0]
            local_base_path_offset = struct.unpack_from("<I", data, offset + 16)[0]
            vol = offset + volume_id_offset

            # Read drive type, serial number, and volume label from VolumeID
            drive_type = DRIVE_TYPES.get(struct.unpack_from("<I", data, vol + 4)[0], "Unknown")
            drive_serial = f"{struct.unpack_from('<I', data, vol + 8)[0]:08X}"
            vol_label_offset = struct.unpack_from("<I", data, vol + 12)[0]
            label_start = vol + vol_label_offset
            label_end = data.index(b"\x00", label_start)
            volume_name = data[label_start:label_end].decode("ascii", errors="replace")

            # Read target path from LocalBasePath
            path_start = offset + local_base_path_offset
            path_end = data.index(b"\x00", path_start)
            target_path = data[path_start:path_end].decode("ascii", errors="replace")

            results.append({
                "file": os.path.basename(lnk_file),
                "creation_time": str(creation_time),
                "last_access_time": str(last_access_time),
                "last_written_time": str(last_written_time),
                "logical_file_size": logical_file_size,
                "drive_type": drive_type,
                "volume_serial_number": drive_serial,
                "volume_name": volume_name,
                "target_path": target_path,
            })

        except Exception as e:
            results.append({"file": lnk_file, "error": str(e)})
    return results


def main():
    lnk_files = extract_files(WIN_RECENT, ".lnk")
    results = lnk_parser(lnk_files)
    with open("lnk_results.json", "w") as f:
        json.dump(results, f, indent=4)


if __name__ == "__main__":
    main()
