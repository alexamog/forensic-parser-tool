# Forensic LNK File Parser

A Python script that parses Windows LNK (Shell Link) files and extracts forensically relevant metadata, outputting results to JSON.

## What it does

Scans `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent` for LNK files and extracts the following fields from each:

- Target file timestamps (created, last access, last written)
- Logical file size
- Drive type (fixed, removable, network, etc.)
- Volume serial number
- Volume name
- Target path

Results are written to `lnk_results.json`.

## Requirements

```
pip install -r requirements.txt
```

## Usage

```
python lnk_file_parser.py
```

## Dependencies

- Python 3.10+
- No third-party libraries required for the parser (uses `struct` from the standard library)
