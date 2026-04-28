# LNK File Forensics

## Why are LNK files important?

LNK files (Shell Link files / Windows Shortcut files) are automatically created by Windows when a user opens a file, folder, or application. They are critical in digital forensics because they can provide **evidence of user activity even if the original file has been deleted**.

They can be found in the following paths:

- `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent Items\`
- `C:\Users\<user>\AppData\Roaming\Microsoft\Office\Recent\`

---

## Ten forensically relevant fields of an LNK file

| # | Field | Location | Size |
|---|-------|----------|------|
| 1 | Created time (target file) | Offset 28 | 8 bytes |
| 2 | Last access time (target file) | Offset 36 | 8 bytes |
| 3 | Last written time (target file) | Offset 44 | 8 bytes |
| 4 | Logical size | Offset 52 | 4 bytes |
| 5 | Drive type | VolumeID structure within LinkInfo, offset +4 | 4 bytes |
| 6 | Volume Serial Number | VolumeID structure within LinkInfo, offset +8 | 4 bytes (little endian, displayed as 8 char hex) |
| 7 | Volume name (if present) | VolumeID structure within LinkInfo, at vol label offset | Null terminated ASCII string |
| 8 | Target path | LocalBasePath offset within LinkInfo | Null terminated ASCII string |
| 9 | LNK file's own timestamps | Filesystem metadata | - |
| 10 | NetBIOS hostname and MAC address | TrackerDataBlock in ExtraData | 16 bytes (hostname), 6 bytes (MAC) |

> **Note:** Fields 1-4 sit at fixed offsets in the Shell Link Header and can be read directly. Fields 5-8 sit at variable positions and must be reached by navigating the LinkInfo structure. Fields 9-10 require navigating the ExtraData section.

---

## Why navigate via LinkInfo rather than searching for landmarks

Fields 5-8 sit at variable positions in the file. A naive approach is to search for the byte sequence `10 00 00 00` as a landmark, but this is unreliable because that sequence is not unique - it can appear elsewhere in the file as part of other data, causing the parser to read from the wrong position entirely.

The correct approach is to navigate the binary structure directly:

1. Skip the 76-byte Shell Link Header
2. If a LinkTargetIDList is present (indicated by bit 0 of LinkFlags at offset 20), read its 2-byte size field and skip past it
3. You are now at the start of LinkInfo - read the VolumeID offset at +12 and the LocalBasePath offset at +16
4. Jump to VolumeID using `LinkInfo start + VolumeID offset` to read drive type, serial number, and volume label
5. Jump to LocalBasePath using `LinkInfo start + LocalBasePath offset` to read the target path

---

## Key takeaways

- **Deleted file recovery context:** Even if a file is wiped, its LNK artifact can confirm it existed, its size, and when it was last touched.

- **Device attribution:** The Volume Serial Number is unique per format event, allowing investigators to tie access to a specific physical device. For example, formatting a drive twice produces two different serial numbers - so if a suspect reformats a drive to destroy evidence, the serial number changes and that discrepancy is itself forensically significant.

- **Drive type:** Knowing whether a file was accessed from a removable drive vs a fixed drive can indicate data exfiltration - a removable drive suggests files were brought in or taken out on that device.

- **Timeline reconstruction:** The three target file timestamps alongside the LNK file's own filesystem timestamps allow you to build a precise activity timeline for a user.

- **Drive letter mapping:** The path field shows what drive letter was assigned, which can corroborate or contradict testimony about which device was plugged in.

- **Machine identification:** The NetBIOS hostname and MAC address can link the artifact to a specific computer, which is valuable in multi-device investigations.

---

## Reference

- [MS-SHLLINK: Shell Link Binary File Format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink)
