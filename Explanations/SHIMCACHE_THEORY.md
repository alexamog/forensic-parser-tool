# Shimcache (AppCompatCache) and Amcache

## What is Shimcache?

Shimcache, formally known as the Application Compatibility Cache, was created by Microsoft for **application compatibility purposes** - not forensics. When Windows encounters an executable, it checks whether that program requires any compatibility shims to run correctly on the current OS version. To avoid repeating this check every time the same executable is seen, Windows caches the results.

The side effect of this is a record of every executable the OS has encountered on the filesystem, which is forensically valuable.

Shimcache is stored in the registry at:

```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
```

Value name: `AppCompatCache`

---

## Key forensic value

Shimcache proves that an executable **existed on the system** and was seen by the OS. This is distinct from Prefetch, which proves an executable was actually run.

This distinction matters in practice:

- If a suspect claims they never had a particular tool on their machine, Shimcache can prove the executable existed even if it was never launched
- If the Prefetch file for a program is missing - deleted, or pushed out by the 128 file limit - Shimcache may still hold a record of the file
- If a program was placed on the system and removed before being executed, Shimcache may be the only artifact that recorded its presence

---

## Critical caveat: written on shutdown only

Shimcache entries are **not written to the registry in real time**. The cache is only flushed to the registry when Windows shuts down cleanly.

This has two forensic implications:

1. **Abrupt shutdown** - if the system loses power, crashes, or is forcibly turned off, any entries accumulated during that session are lost and never written to the registry
2. **Live forensics** - if you read Shimcache from a running system, entries from the current session will not yet be present. Only entries from previous sessions are visible

An absence of a Shimcache entry does not mean a file never existed - it may simply mean the system did not shut down cleanly after that file was encountered.

---

## Entry ordering

Shimcache stores entries with the most recently encountered executable first. This ordering is forensically significant because:

- A suspicious executable near the top of the cache was seen recently
- Entries further down were seen earlier in the system's history
- If a known executable appears immediately before or after a suspicious one, it helps establish context and a rough timeline of activity

---

## Timestamps by Windows version

Shimcache does not store timestamps in all Windows versions:

| Windows Version | Timestamp stored |
|----------------|-----------------|
| Windows XP | Last modified time and last update time |
| Windows Vista / 7 | Last modified time |
| Windows 8+ | No timestamp |

On Windows 10 and 11, you get the ordering of entries but no associated times. To pin activity to a specific date, timestamps from other artifacts such as LNK files, Prefetch, or the NTFS $MFT must be used for corroboration.

---

## Shimcache vs Prefetch vs Amcache

These three artifacts are often used together and are frequently confused:

| Artifact | Proves | Timestamp | Location |
|----------|--------|-----------|----------|
| Prefetch | Program was executed | Yes | `C:\Windows\Prefetch\` |
| Shimcache | Executable existed on the system | Only on XP/Vista/7 | Registry |
| Amcache | Program was installed or run | Yes | `C:\Windows\appcompat\Programs\Amcache.hve` |

In an investigation, the strongest case combines all three. Shimcache alone only proves presence - not execution. Prefetch proves execution but can be deleted or overwritten. Amcache provides file hashes and install metadata that can identify a program even if it has been renamed or moved.

---

## Reading Shimcache with winreg

Unlike the other parsers in this project which read files directly, Shimcache is read from the live registry using Python's built-in `winreg` module. No third-party libraries are needed.

```python
import winreg

key_path = r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
raw_data, _ = winreg.QueryValueEx(key, "AppCompatCache")
```

This returns the raw binary value which is then parsed with `struct` the same way as the other parsers.

---

## Binary structure (Windows 10/11)

The raw value begins with a header, followed by a sequence of entries. The first 4 bytes of the raw value contain the offset to the first entry, so the header size is not hardcoded - it is read directly from the data.

### Header

| Field | Offset | Size | Notes |
|-------|--------|------|-------|
| Offset to first entry | 0 | 4 bytes (`<I`) | Points to where the first `10ts` entry begins. Typically 0x34 (52) on Windows 10 1709+ and Windows 11 |

### Entry structure

Each entry starts with the signature `10ts` (bytes `0x31 0x30 0x74 0x73`):

| Field | Entry offset | Size | Notes |
|-------|-------------|------|-------|
| Signature | 0 | 4 bytes | `10ts` - confirms start of a valid entry |
| Unknown | 4 | 4 bytes | Purpose unknown, skipped |
| ceDataSize | 8 | 4 bytes (`<I`) | Total size of the entry body after the 12-byte header |
| Path length | 12 | 2 bytes (`<H`) | Length of the path string in bytes |
| Path | 14 | variable | UTF-16LE string, not null-terminated |
| Last modified time | 14 + path_length | 8 bytes (`<Q`) | Windows FILETIME - last modified time of the executable |
| Data size | 22 + path_length | 4 bytes (`<I`) | Length of the trailing data blob |
| Data blob | 26 + path_length | variable | Binary data - last 4 bytes indicate execution (1 = executed, 0 = not executed) |

### Navigating to the next entry

The correct formula to move to the next entry is:

```
next_entry_offset = current_offset + 26 + path_length + data_size
```

The 26 accounts for all fixed fields in the entry (4 + 4 + 4 + 2 + 8 + 4), then `path_length` and `data_size` account for the two variable-length sections.

### Parsing approach

```python
import struct

ENTRY_SIGNATURE = b"10ts"

# Read the offset to the first entry from the first 4 bytes
entry_offset = struct.unpack_from("<I", data, 0)[0]

while entry_offset < len(data) - 4:
    if data[entry_offset:entry_offset + 4] != ENTRY_SIGNATURE:
        break

    path_length = struct.unpack_from("<H", data, entry_offset + 12)[0]
    path = data[entry_offset + 14:entry_offset + 14 + path_length].decode("utf-16-le")
    last_modified = struct.unpack_from("<Q", data, entry_offset + 14 + path_length)[0]
    data_size = struct.unpack_from("<I", data, entry_offset + 22 + path_length)[0]

    entry_offset += 26 + path_length + data_size
```

---

---

---

# Amcache

## What is Amcache?

Amcache was introduced in Windows 8 as a replacement for an older artifact called `RecentFileCache.bcf`. Where Shimcache tracks executables the OS has seen, Amcache goes further - it records programs that were **actually installed or executed**, along with rich metadata including file hashes, publisher information, and PE compile times.

Amcache is stored as a registry hive file on disk at:

```
C:\Windows\appcompat\Programs\Amcache.hve
```

Because it is a standalone hive file rather than a live registry key, it is read differently from Shimcache. The hive must be loaded into the registry temporarily using `winreg.RegLoadKey` before its contents can be queried.

---

## Key forensic value

Amcache is one of the most powerful program execution artifacts because it provides information that no other single artifact does:

- **SHA-1 file hash** - uniquely identifies the executable regardless of filename. If a suspect renames a known malicious tool, the hash will still match
- **First execution time** - when the program was first run on the system
- **PE compile time** - when the executable was originally compiled, which can reveal whether a tool was purpose-built or commercially available
- **Publisher and version** - identifies the software vendor and version
- **Full file path** - where the executable was located at the time of execution

The file hash is particularly significant. It allows investigators to look up the hash against threat intelligence databases to identify known malware, even if the file itself has been deleted.

---

## Key differences from Shimcache

| | Shimcache | Amcache |
|---|-----------|---------|
| What it proves | Executable existed on the system | Program was installed or executed |
| File hash | No | Yes (SHA-1) |
| Timestamps | Only XP/Vista/7 | Yes |
| Publisher info | No | Yes |
| PE compile time | No | Yes |
| Storage | Live registry key | Hive file on disk |
| How to read | `winreg.OpenKey` | `winreg.RegLoadKey` to mount hive first |
| Written in real time | No - on shutdown only | Yes |
| Introduced | Windows XP | Windows 8 |

The most important practical difference is that Amcache is written in real time, whereas Shimcache is only flushed on shutdown. This means Amcache entries will be present even if the system was abruptly shut down after a program was run.

---

## Registry structure within the hive

On Windows 10 and 11, program entries are stored under:

```
Root\InventoryApplicationFile
```

Each subkey represents one executable. The subkey name is derived from the file path and hash. The values within each subkey are the forensically relevant fields:

| Value name | Contents |
|------------|----------|
| `FileId` | SHA-1 hash of the file (prefixed with `0000`) |
| `LowerCaseLongPath` | Full path to the executable |
| `Name` | Filename |
| `Publisher` | Company or publisher name |
| `Version` | File version string |
| `Size` | File size in bytes |
| `ProductName` | Product name from PE metadata |
| `LinkDate` | PE compile time |

### Reading the hive with winreg

Because the hive is a separate file rather than part of the live registry, it must be mounted first:

```python
import winreg

HIVE_PATH = r"C:\Windows\appcompat\Programs\Amcache.hve"
MOUNT_POINT = r"AMCACHE_TEMP"

winreg.RegLoadKey(winreg.HKEY_LOCAL_MACHINE, MOUNT_POINT, HIVE_PATH)

key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, rf"{MOUNT_POINT}\Root\InventoryApplicationFile")
```

After reading, the hive must be unloaded:

```python
winreg.RegUnLoadKey(winreg.HKEY_LOCAL_MACHINE, MOUNT_POINT)
```

> **Note:** Loading and unloading registry hives requires administrator privileges.

---

## Multi-artifact scenario

A common investigation scenario combining all three artifacts:

```
Shimcache entry for suspicious.exe        - file existed on the system
Amcache entry for suspicious.exe          - file was executed, SHA-1 hash recorded
Prefetch file for suspicious.exe          - confirms execution, shows run count and timestamps
```

If only Shimcache is present with no Amcache or Prefetch entry, the file may have been placed on the system but never run. If Amcache is present but Prefetch is missing, the Prefetch file may have been deleted - but Amcache still proves execution and provides the hash.

---
