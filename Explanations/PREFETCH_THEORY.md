# Prefetch Files

Prefetch files are created by the Windows OS to make application startups more efficient. Each prefetch file contains metadata about a program that has been executed.

They are located at: `C:\Windows\Prefetch`

Files are named in the format: `APPNAME-XXXXXXXX.pf`

- The hash is derived from the **executable's path**, not the file itself
- This means if the same program runs from two different locations (e.g. once from `C:\` and once from a USB drive), it generates **two different prefetch files** — forensically useful for detecting programs run from unusual locations

---

## Key Forensic Fields

- **Proof of execution** — even if the program has been deleted, the prefetch file confirms it was run
- **Execution count** — how many times the program was launched
- **Last execution timestamps** — up to 8 timestamps of the last 8 run times (Windows 8+)
- **Files and volumes accessed** — what files and directories the program touched on launch
- **Original file path** — where the executable was located

---

## Important Caveats

- Windows has a default limit of **128 prefetch files** — once the limit is hit, the oldest gets overwritten. This is important when building a timeline as older evidence may be lost
- Prefetch is **disabled by default on Windows Server** and on some SSDs depending on configuration — absence of prefetch files does not always mean programs were not executed
- On **Windows 8+**, prefetch files are compressed using the Xpress Huffman algorithm and must be decompressed before parsing. Windows 7 and earlier are uncompressed
- Prefetch is often **disabled in virtual machines**

---

## Why Prefetch Files May Be Absent

If no prefetch files are found on a machine, there are four possible explanations:

1. They were manually deleted by the user
2. A cleanup tool such as CCleaner was used, and its own prefetch file was then manually deleted
3. Prefetch is disabled on the system via registry setting
4. The machine is a virtual machine or Windows Server where prefetch does not run by default

In a real investigation, always check the registry to confirm whether prefetch was enabled or disabled — a deliberately disabled prefetch on a regular workstation is itself suspicious.

---

## Key Forensic Scenario

When a person attempts to run a cleanup tool such as CCleaner to hide evidence, the act of running CCleaner itself creates a prefetch file — meaning investigators can prove the cleanup tool was executed even after it has done its job.

### Multi-artifact timeline example

```
LNK file for sensitive_document.xlsx  → last accessed 14:23
CCleaner prefetch                     → first executed 14:31
Prefetch files for other programs     → missing after 14:31
```

The 8 minute gap tells a clear story — the user accessed a sensitive file, then immediately ran CCleaner. The missing prefetch files after that timestamp corroborate that CCleaner did its job. But the CCleaner prefetch file itself survived, and the LNK file for the document survived, giving you both ends of the story.

---

## Superfetch (SysMain)

Superfetch is a related Windows service that remembers when and how often you run an application and preloads data into RAM before you even open it. While not the same as prefetch, it works alongside it to optimise performance.

> **Note:** Do not confuse Prefetch and Superfetch. Prefetch creates a file on the **first execution** of a program regardless of frequency. Superfetch tracks usage patterns over time to optimise RAM preloading. In an investigation, it is the prefetch file that provides proof of execution — not Superfetch.

---

## Reference

- [MS-PFE: Prefetch File Format](https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20(PF)%20format.asciidoc)
