# Recycle Bin Forensics

## Why is the Recycle Bin important?

When a user deletes a file in Windows, it is not immediately erased, it is moved to the Recycle Bin, a hidden system folder. Windows creates two files for each deleted item, one of which contains structured metadata about the deletion. This metadata survives even after the Recycle Bin is emptied and can be recovered from unallocated disk space, making the Recycle Bin a valuable source of evidence in any investigation involving file deletion.

The Recycle Bin is located at:

- `C:\$Recycle.Bin\<SID>\`

Each user on the system has their own subfolder named after their **Security Identifier (SID)**  the SID in the path directly identifies which user account performed the deletion.

---

## The $I and $R file pair

When a file is moved to the Recycle Bin, Windows creates two files with a shared random suffix:

| File | Contents |
|------|----------|
| `$R` + random suffix + original extension | The actual file data |
| `$I` + random suffix + original extension | Metadata: original path, file size, deletion timestamp |

For example, deleting `report.xlsx` might produce:
- `$RABCD123.xlsx`: the file's contents
- `$IABCD123.xlsx`: the metadata record

Both files are **live, active files** while the item sits in the Recycle Bin. Nothing has been erased at this point the files have simply been moved to a hidden system folder and renamed.

When the user **empties the Recycle Bin**, both files are deleted. Their NTFS MFT records are marked as unallocated and the clusters are freed. However, the $I metadata records are small and frequently **recoverable from unallocated space** even long after emptying. This is where their forensic value is greatest even if the $R file's data has been overwritten, a recovered $I file can still prove the original path, size, and deletion time.

---

## A note on NTFS vs FAT deletion

Modern Windows uses **NTFS**, where file deletion works by clearing an "in use" flag in the file's MFT record. The record and its data clusters remain intact until the space is reused by another file.

This is different from **FAT** filesystems, where deletion marks the first byte of a directory entry with `0xE5` to indicate the slot is free. The 0xE5 marker is a FAT concept and does not apply to NTFS.

---

## SID and RID: identifying who deleted the file

Each user on the system has their own Recycle Bin subfolder named after their **Security Identifier (SID)**. A full SID looks like this:

```
S-1-5-21-1234567890-987654321-1122334455-1000
```

| Part | Meaning |
|------|---------|
| `S` | Identifies the string as a SID |
| `1` | Revision level (always 1) |
| `5` | Identifier authority (5 = NT Authority) |
| `21` | Indicates a domain or local machine account |
| `1234567890-987654321-1122334455` | Sub-authority values — unique to the machine or domain |
| `1000` | **RID (Relative Identifier)** — identifies the specific account |

The **RID** is the last segment and the only part that differs between accounts on the same machine. Some RIDs are well-known:

| RID | Account |
|-----|---------|
| `500` | Built-in Administrator |
| `501` | Guest |
| `503` | DefaultAccount |
| `504` | WDAGUtilityAccount (Windows Defender Application Guard) |
| `1000`+ | Standard user accounts created on the machine |

**Forensic relevance:** A deletion path of `C:\$Recycle.Bin\S-1-5-21-...-500\` means the built-in Administrator account performed the deletion — significant if a suspect claimed not to have admin access. Standard user accounts will show a RID of 1000 or above. If multiple SID subfolders exist under `$Recycle.Bin`, multiple user accounts have deleted files, and each $I file can be attributed to a specific account by its parent folder.

---

## Key forensic fields

- **Original file path** — the full path before deletion, including drive letter. If the path references a USB drive letter (e.g. `E:\`) or a network path, that is forensically significant — it can indicate data being brought in or taken out on a removable device
- **Deletion timestamp** — when the file was moved to the Recycle Bin, not when the Recycle Bin was emptied
- **Original file size** — can be used to corroborate other evidence or identify the file even if the data is gone
- **SID and RID (from folder path)** — identifies which user account performed the deletion; the RID alone can reveal whether it was a standard user or the built-in Administrator

---

## Key forensic scenarios

**Proving deliberate deletion**
A file appearing in the Recycle Bin metadata confirms the user chose to delete it. Combined with an LNK file showing prior access and a Prefetch entry showing program execution, you can build a complete before-and-after timeline.

**Detecting data exfiltration**
If the original path in a $I file references a removable drive (e.g. `E:\confidential_data.xlsx`), it proves the file existed on an external device — even if that device is no longer available.

**Anti-forensics detection**
A user who empties the Recycle Bin expecting to destroy evidence may not realise that $I records can survive in unallocated space. The deletion timestamp in a recovered $I file may directly contradict a suspect's account of events.

---

## TRIM and data recovery on SSDs

When clusters are freed, the data they held is not immediately erased:

- **HDD**: Freed clusters are left as-is until another file overwrites them. Data can persist for a long time and is recoverable with standard carving tools
- **SSD**: The TRIM command instructs the storage controller to proactively zero out freed blocks to maintain write performance. This happens quickly after deletion and largely eliminates the possibility of recovering overwritten data

This is a critical distinction in modern investigations. An SSD with TRIM enabled is significantly harder to recover data from than an HDD. That said, the $I metadata file is small and may survive in a cluster that has not yet been TRIMmed or reused.

---

## Linking $I and $R files

The $I and $R files for the same deleted item share an identical random suffix. This suffix is the only way to associate them:

```
$I ABCD123 .xlsx   ←— metadata
$R ABCD123 .xlsx   ←— file contents
```

If a user deletes the same file multiple times, each deletion produces a new $I/$R pair with a different random suffix. Multiple $I files pointing to the same original path are forensically significant — they show a pattern of repeated deletion.

---

## Binary structure of the $I file

The first three fields are identical across all versions. The path field differs between version 1 and version 2 — this is the most important structural distinction to be aware of when writing a parser.

### Shared fields (all versions)

| Field | Offset | Size | Notes |
|-------|--------|------|-------|
| Version | 0 | 8 bytes (`<Q`) | `0x01` = Vista/7/8, `0x02` = Windows 10+ |
| Original file size | 8 | 8 bytes (`<Q`) | Size of the deleted file in bytes |
| Deletion timestamp | 16 | 8 bytes (`<Q`) | Windows FILETIME |

### Version 1 (Vista / 7 / 8) — path from offset 24

| Field | Offset | Size | Notes |
|-------|--------|------|-------|
| Original file path | 24 | variable | Null-terminated UTF-16LE string |

### Version 2 (Windows 10+) — path from offset 28

| Field | Offset | Size | Notes |
|-------|--------|------|-------|
| File name length | 24 | 4 bytes (`<I`) | Number of characters in the path string |
| Original file path | 28 | variable | UTF-16LE string, **not** null-terminated — use the length field instead |

> **This is a common parser bug.** On a Windows 10/11 machine, all $I files are version 2. If you read the path starting at offset 24 without checking the version first, you are reading the 4-byte length field as the beginning of the string and will get garbage output. Always read the version first and branch accordingly.

### Validation

The file should begin with a known version value. Any other value indicates a corrupt or unrecognised format:

```python
version = struct.unpack_from("<Q", data, 0)[0]
if version not in (1, 2):
    raise ValueError(f"Unrecognised $I file version: {version}")
```

### Reading the original path

```python
if version == 1:
    path_data = data[24:]
    i = 0
    while i < len(path_data) - 1:
        if path_data[i] == 0 and path_data[i + 1] == 0:
            break
        i += 2
    original_path = path_data[:i].decode("utf-16-le")
else:
    char_count = struct.unpack_from("<I", data, 24)[0]
    original_path = data[28:28 + char_count * 2].decode("utf-16-le")
```

---

## Reference

- [Recycle Bin $I file format — ForensicsWiki](https://forensicswiki.xyz/page/Windows#Recycle_Bin)
- [librecycle — open source $I/$R parser](https://github.com/libyal/libregf)
