# Windows Forensic Parser Tools

A growing collection of Python scripts for parsing Windows forensic artifacts. Each tool extracts forensically relevant metadata from a specific artifact type, outputs results to JSON, and is accompanied by a theory document explaining the artifact and its investigative value.

The goal of this project is to build parsers from the ground up - reading raw binary directly using Python's `struct` module rather than relying on third-party libraries - in order to develop a deep understanding of the underlying file formats.

---

## Tools

| Artifact | Script | Theory |
|----------|--------|--------|
| LNK Files (Shell Link) | `lnk_file_parser.py` | [LNK_THEORY.md](Explanations/LNK_THEORY.md) |
| Prefetch Files | `prefetch_parser.py` | [PREFETCH_THEORY.md](Explanations/PREFETCH_THEORY.md) |
| Recycle Bin (`$I` files) | `recycle_bin_parser.py` | [RECYCLE_BIN_THEORY.md](Explanations/RECYCLE_BIN_THEORY.md) |
| Shimcache (AppCompatCache) and Amcache | `N/A` | [SHIMCACHE_THEORY.md](Explanations/SHIMCACHE_THEORY.md) |

---

## Supporting Documentation

- [LNK_THEORY.md](Explanations/LNK_THEORY.md) - What LNK files are, their forensic value, and how they are structured
- [PREFETCH_THEORY.md](Explanations/PREFETCH_THEORY.md) - What prefetch files are, their forensic value, and how they are structured
- [RECYCLE_BIN_THEORY.md](Explanations/RECYCLE_BIN_THEORY.md) - What Recycle Bin $I files are, their forensic value, and how they are structured
- [SHIMCACHE_THEORY.md](Explanations/SHIMCACHE_THEORY.md) - What Shimcache and Amcache are, their forensic value, how they differ, and how they are structured
- [ENDIANNESS.md](Explanations/ENDIANNESS.md) - Explanation of endianness and why it matters when parsing Windows binary formats

---

## Requirements

- Python 3.10+
- Windows OS (parsers rely on Windows-specific paths and APIs)
- Administrator privileges required for `prefetch_parser.py` and `recycle_bin_parser.py`

---

## Usage

### Running via the menu (recommended)

The easiest way to run the tools is through the interactive menu:

```
python app.py
```

This presents a numbered menu to select which parser to run. Parsers that require administrator privileges will prompt accordingly when selected.

### Running individual parsers

All results are written to the `results/` folder.

```
python lnk_file_parser.py
```

Results are written to `results/lnk_results.json`.

```
python prefetch_parser.py
```

Results are written to `results/prefetch_results.json`.

> **Note:** `prefetch_parser.py` must be run as administrator - prefetch files are stored in `C:\Windows\Prefetch`, which requires elevated access.

```
python recycle_bin_parser.py
```

Results are written to `results/recycle_bin_results.json`.

> **Note:** `recycle_bin_parser.py` must be run as administrator - `C:\$Recycle.Bin` requires elevated access.
