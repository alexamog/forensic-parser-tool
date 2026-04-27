# Recycle Bin Forensics

## Why is the Recycle Bin important?

When a user deletes a file in Windows, it is not immediately erased — it is moved to the Recycle Bin, a hidden system folder. Windows creates two files for each deleted item, one of which contains structured metadata about the deletion. This metadata survives even after the Recycle Bin is emptied and can be recovered from unallocated disk space, making the Recycle Bin a valuable source of evidence in any investigation involving file deletion.

The Recycle Bin is located at:

- `C:\$Recycle.Bin\<SID>\`

Each user on the system has their own subfolder named after their **Security Identifier (SID)** — the SID in the path directly identifies which user account performed the deletion.

---

## The $I and $R file pair

When a file is moved to the Recycle Bin, Windows creates two files with a shared random suffix:

| File | Contents |
|------|----------|
| `$R` + random suffix + original extension | The actual file data |
| `$I` + random suffix + original extension | Metadata: original path, file size, deletion timestamp |

For example, deleting `report.xlsx` might produce:
- `$RABCD123.xlsx` — the file's contents
- `$IABCD123.xlsx` — the metadata record

Both files are **live, active files** while the item sits in the Recycle Bin. Nothing has been erased at this point — the files have simply been moved to a hidden system folder and renamed.

When the user **empties the Recycle Bin**, both files are deleted. Their NTFS MFT records are marked as unallocated and the clusters are freed. However, the $I metadata records are small and frequently **recoverable from unallocated space** even long after emptying. This is where their forensic value is greatest — even if the $R file's data has been overwritten, a recovered $I file can still prove the original path, size, and deletion time.

---

## A note on NTFS vs FAT deletion

Modern Windows uses **NTFS**, where file deletion works by clearing an "in use" flag in the file's MFT record. The record and its data clusters remain intact until the space is reused by another file.

This is different from **FAT** filesystems, where deletion marks the first byte of a directory entry with `0xE5` to indicate the slot is free. The 0xE5 marker is a FAT concept and does not apply to NTFS.

---

## Key forensic fields

- **Original file path** — the full path before deletion, including drive letter. If the path references a USB drive letter (e.g. `E:\`) or a network path, that is forensically significant — it can indicate data being brought in or taken out on a removable device
- **Deletion timestamp** — when the file was moved to the Recycle Bin, not when the Recycle Bin was emptied
- **Original file size** — can be used to corroborate other evidence or identify the file even if the data is gone
- **SID (from folder path)** — identifies which user account performed the deletion

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

## Binary structure of the $I file

The $I file is small and has a simple fixed-offset structure:

| Field | Offset | Size | Notes |
|-------|--------|------|-------|
| Version | 0 | 8 bytes (`<Q`) | `0x01` = Vista/7/8, `0x02` = Windows 10+ |
| Original file size | 8 | 8 bytes (`<Q`) | Size of the deleted file in bytes |
| Deletion timestamp | 16 | 8 bytes (`<Q`) | Windows FILETIME |
| Original file path | 24 | variable | Null-terminated UTF-16LE string |

### Validation

The file should begin with a known version value. Any other value indicates a corrupt or unrecognised format:

```python
version = struct.unpack_from("<Q", data, 0)[0]
if version not in (1, 2):
    raise ValueError(f"Unrecognised $I file version: {version}")
```

### Reading the original path

```python
path_data = data[24:]
null_pos = path_data.find(b"\x00\x00")
original_path = path_data[:null_pos].decode("utf-16-le")
```

---

## Reference

- [Recycle Bin $I file format — ForensicsWiki](https://forensicswiki.xyz/page/Windows#Recycle_Bin)
- [librecycle — open source $I/$R parser](https://github.com/libyal/libregf)
