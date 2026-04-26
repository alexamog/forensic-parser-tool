# Windows Forensic Parser Tools

A growing collection of Python scripts for parsing Windows forensic artifacts. Each tool extracts forensically relevant metadata from a specific artifact type, outputs results to JSON, and is accompanied by a theory document explaining the artifact and its investigative value.

The goal of this project is to build parsers from the ground up — reading raw binary directly using Python's `struct` module rather than relying on third-party libraries — in order to develop a deep understanding of the underlying file formats.

---

## Tools

| Artifact | Script | Theory |
|----------|--------|--------|
| LNK Files (Shell Link) | `lnk_file_parser.py` | [LNK_THEORY.md](Explanations/LNK_THEORY.md) |
<!-- | Prefetch Files | `prefetch_parser.py` *(coming soon)* | [PREFETCH_THEORY.md](Explanations/PREFETCH_THEORY.md) | -->

---

## Supporting Documentation

- [LNK_THEORY.md](Explanations/LNK_THEORY.md) — What LNK files are, their forensic value, and how they are structured
- [PREFETCH_THEORY.md](Explanations/PREFETCH_THEORY.md) — What prefetch files are, their forensic value, and how they are structured
- [ENDIANNESS.md](Explanations/ENDIANNESS.md) — Explanation of endianness and why it matters when parsing Windows binary formats

---

## Requirements

- Python 3.10+
- No third-party libraries required (uses `struct` from the standard library)

---

## Usage

```
python lnk_file_parser.py
```

Results are written to `lnk_results.json`.
