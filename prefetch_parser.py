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


WIN_VER = {
    17: "Windows XP",
    23 : "Windows Vista/7",
    26: "Windows 8",
    30: "Windows 10",
    31: "Windows 11"

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


def prefetch_parser(pf_files: list[str]) -> list[dict]:
    for pf_file in pf_files:
        try:
            with open(pf_file, "rb") as f:
                data = f.read()

            # Decompress if MAM compressed (Windows 8+)
            if data[:3] == b"MAM":
                data = decompress_prefetch(data)
            print(f"OS ver: {WIN_VER[struct.unpack_from("<I", data, 0)[0]]}")
            print(f"last run: {filetime_to_dt(struct.unpack_from("<Q", data, 128)[0])}")

        except Exception as e:
            print(f"Failed to parse {pf_file}: {e}")


if __name__ == "__main__":
    is_admin()
    pf_files = extract_files(PF_FILE_DIR, ".pf")
    prefetch_parser(pf_files)
