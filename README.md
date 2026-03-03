# ƈʀʏքȶӄɨȶ
**CTF cryptography and steganography toolkit that figures out what you're looking at.**

Most of the time in CTFs, half the work is just figuring out *what kind* of challenge you're dealing with before you can even start solving it. CryptKit handles that part — you give it a string, a file, or a hex dump, and it identifies the encoding or cipher type, then runs the right solvers automatically.

Built from tools and patterns I kept reaching for during actual CTF competitions.

---

## What it does

- Detects encoding type from raw input (Base64, XOR, Vigenère, hex, morse, hashes, and more)
- Checks images for common stego techniques — LSB extraction, metadata, appended data, palette tricks
- Chains solvers automatically based on what it finds
- If the decoded output looks like something encoded again, it re-runs on that too (up to 3 layers deep)
- Gives confidence scores so you know how sure it is

---

## Install

```bash
git clone https://github.com/yourusername/cryptkit
cd cryptkit
pip install -e .
```

Or with pipx:

```bash
pipx install .
```

Requires Python 3.10+

---

## Usage

```bash
# Analyze a string
cryptkit --text "SGVsbG8gV29ybGQ="

# Analyze a file (image, binary, text)
cryptkit --file challenge.png

# Analyze a hex string
cryptkit --hex "48656c6c6f"

# Save output to file
cryptkit --text "U2VjcmV0" --output result.txt

# Raw JSON output
cryptkit --text "U2VjcmV0" --json

# Verbose mode (shows each solver as it runs)
cryptkit --file stego.png --verbose
```

---

## What it can detect

| Category | Supported |
|---|---|
| Base encodings | Base64, Base32, Base58, Base85 |
| Classical ciphers | Caesar, ROT13, Vigenère, Atbash |
| XOR | Single-byte and multi-byte brute force |
| Hashes | MD5, SHA1, SHA256, SHA512 (identification only) |
| Other text | Hex strings, Morse code, substitution ciphers |
| Image stego | LSB (all channels + bit planes), EXIF/metadata, appended data, palette encoding |
| Binary | Magic byte detection, embedded file carving, entropy analysis |

---

## How it works

1. **Fingerprint** — looks at the raw input and builds a list of what it might be, each with a confidence score
2. **Pipeline** — runs the right solver for each finding, highest confidence first
3. **Report** — prints everything it found in a clean terminal output

If a solver returns something that itself looks encoded, it loops back through the fingerprinter automatically.

---
