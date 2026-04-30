import os
import json
import ctypes
import struct
from forensic_helpers import filetime_to_dt, format_file_size, extract_files, require_admin

PF_FILE_DIR = os.path.join("C:\\", "Windows", "Prefetch")

WIN_VER = {
    17: "Windows XP",
    23: "Windows Vista/7",
    26: "Windows 8",
    30: "Windows 10",
    31: "Windows 11",
}


def decompress_prefetch(data: bytes) -> bytes:
    """
    Decompress a Windows 8+ prefetch file using Xpress Huffman decompression.
    MAM header: 4 bytes signature + 4 bytes decompressed size + compressed data
    """
    decompressed_size = struct.unpack_from("<I", data, 4)[0]
    compressed_data = data[8:]

    ntdll = ctypes.windll.ntdll
    decompressed = ctypes.create_string_buffer(decompressed_size)
    final_size = ctypes.c_ulong(0)

    workspace_size = ctypes.c_ulong(0)
    raw_size = ctypes.c_ulong(0)
    ntdll.RtlGetCompressionWorkSpaceSize(0x104, ctypes.byref(workspace_size), ctypes.byref(raw_size))
    workspace = ctypes.create_string_buffer(workspace_size.value)

    ntdll.RtlDecompressBufferEx(
        0x104,  # COMPRESSION_FORMAT_XPRESS_HUFF
        decompressed,
        decompressed_size,
        compressed_data,
        len(compressed_data),
        ctypes.byref(final_size),
        workspace
    )

    return decompressed.raw


def parse_prefetch(data: bytes, filename: str) -> dict:
    # Validate SCCA signature
    if data[4:8] != b"SCCA":
        raise ValueError("Not a valid prefetch file")

    version_raw = struct.unpack_from("<I", data, 0)[0]
    version = WIN_VER.get(version_raw, f"Unknown ({version_raw})")
    exe_name = data[16:76].decode("utf-16-le").rstrip("\x00")
    pf_hash = f"{struct.unpack_from('<I', data, 76)[0]:08X}"
    file_size = format_file_size(struct.unpack_from("<I", data, 12)[0])
    execution_count = struct.unpack_from("<I", data, 208)[0]

    # Up to 8 last run timestamps stored sequentially at offset 128
    last_run_times = []
    for i in range(8):
        filetime = struct.unpack_from("<Q", data, 128 + i * 8)[0]
        dt = filetime_to_dt(filetime)
        if dt:
            last_run_times.append(dt)

    return {
        "file": filename,
        "executable": exe_name,
        "prefetch_hash": pf_hash,
        "os_version": version,
        "file_size": file_size,
        "execution_count": execution_count,
        "last_run_times": last_run_times,
    }


def prefetch_parser(pf_files: list[str]) -> list[dict]:
    results = []
    for pf_file in pf_files:
        try:
            with open(pf_file, "rb") as f:
                data = f.read()

            if data[:3] == b"MAM":
                data = decompress_prefetch(data)

            results.append(parse_prefetch(data, os.path.basename(pf_file)))

        except Exception as e:
            results.append({"file": pf_file, "error": str(e)})
    return results


def main():
    require_admin()
    pf_files = extract_files(PF_FILE_DIR, ".pf")
    results = prefetch_parser(pf_files)
    os.makedirs("results", exist_ok=True)
    with open(os.path.join("results", "prefetch_results.json"), "w") as f:
        json.dump(results, f, indent=4)
    parsed = sum(1 for r in results if "error" not in r)
    errors = sum(1 for r in results if "error" in r)
    print(f"Parsed {parsed} entries, {errors} errors. Results saved to: results/prefetch_results.json")


if __name__ == "__main__":
    main()
