from datetime import datetime, timezone, timedelta
import struct
with open("C:\\Users\\alexa\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\Alexander Amog_Junior DevOps Engineer (Night Shift)_20260418.pdf.lnk", "rb") as f:
    data = f.read()

# Example: read file size at offset 52, 4 bytes, little endian unsigned int
file_size = struct.unpack_from("<I", data, 52)[0]



# Example: read creation time at offset 28, 8 bytes, little endian unsigned long long
creation_time_raw = struct.unpack_from("<Q", data, 28)[0]

FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
dt = FILETIME_EPOCH + timedelta(microseconds=creation_time_raw // 10)


print(file_size)
print(dt)