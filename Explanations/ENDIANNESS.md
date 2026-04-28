# Endianness

Endianness is essential when manually inspecting raw hex in a hex editor or writing parsers, because it tells you the correct order to read multi-byte values.

Endianness describes which end of a multi-byte number gets stored first in memory - either the big end or the little end.

**Big Endian:** Most significant byte comes first  
**Little Endian:** Least significant byte comes first (lowest memory address)

- Most Windows systems are little-endian
- This is important because if you read bytes in the wrong endianness, you get completely wrong values

---

## Example Analogy - Writing the number 1,234

- Normal (big-endian): `1 2 3 4` most significant digit first
- Reversed (little-endian): `4 3 2 1` least significant digit first

---

## Example: The number `305419896` in hex is `0x12345678`

| Format | Byte Order in Memory |
|--------|----------------------|
| Big-endian | `12 34 56 78` |
| Little-endian | `78 56 34 12` |

When reading little-endian, reverse the bytes before interpreting:  
`78 56 34 12` → reverse → `12 34 56 78` = `0x12345678`

---

## Python Code Example

```python
int.from_bytes(raw, "little")  # correct for Windows
int.from_bytes(raw, "big")     # would give wrong value
```

In the `struct` module, the `<` prefix handles this automatically:

```python
struct.unpack_from("<I", data, offset)  # < means little-endian
struct.unpack_from(">I", data, offset)  # > means big-endian
```

---

## Why It Matters in LNK Parsing

When extracting the volume serial number from a LNK file, the raw bytes in memory might look like:

```
32 42 09 D0
```

Read as little-endian (correct for Windows):  
`32 42 09 D0` → reverse → `D0 09 42 32` = `D0094232`

Read as big-endian (incorrect):  
`32 42 09 D0` = `32420900` - incorrect value

This would produce incorrect forensic evidence, which is why understanding endianness is fundamental to binary parsing.
