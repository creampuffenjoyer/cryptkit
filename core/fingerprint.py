"""
Fingerprinting engine — inspects raw input and returns ranked findings.
"""
from __future__ import annotations

import math
import os
import re
import string
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Union

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    type: str
    confidence: float       # 0.0 – 1.0
    hint: str
    meta: dict = field(default_factory=dict)

    def __repr__(self) -> str:
        bar = int(self.confidence * 20)
        filled = "#" * bar + "-" * (20 - bar)
        return f"[{filled}] {self.confidence:.0%}  {self.type:<20s}  {self.hint}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ENGLISH_FREQ = {
    'e': 12.70, 't': 9.06, 'a': 8.17, 'o': 7.51, 'i': 6.97,
    'n': 6.75, 's': 6.33, 'h': 6.09, 'r': 5.99, 'd': 4.25,
    'l': 4.03, 'c': 2.78, 'u': 2.76, 'm': 2.41, 'w': 2.36,
    'f': 2.23, 'g': 2.02, 'y': 1.97, 'p': 1.93, 'b': 1.49,
    'v': 0.98, 'k': 0.77, 'j': 0.15, 'x': 0.15, 'q': 0.10, 'z': 0.07,
}

_MAGIC = {
    b'\x89PNG\r\n\x1a\n': 'png',
    b'\xff\xd8\xff': 'jpg',
    b'BM': 'bmp',
    b'GIF87a': 'gif',
    b'GIF89a': 'gif',
    b'PK\x03\x04': 'zip',
    b'Rar!': 'rar',
    b'7z\xbc\xaf\x27\x1c': '7z',
    b'%PDF': 'pdf',
    b'\x1f\x8b': 'gzip',
    b'BZh': 'bzip2',
}

_BASE58_ALPHABET = set('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz')
_BASE64_CHARS    = set(string.ascii_letters + string.digits + '+/=')
_BASE64URL_CHARS = set(string.ascii_letters + string.digits + '-_=')

# ---------------------------------------------------------------------------
# Bug fix #9: use Counter, not list.count() in a loop (was O(26n))
# ---------------------------------------------------------------------------

def _letter_freq_score(text: str) -> float:
    """0..1 — dot-product of observed vs expected English letter frequencies."""
    letters = [c.lower() for c in text if c.isalpha()]
    if not letters:
        return 0.0
    total = len(letters)
    freq = Counter(letters)
    score = sum(
        (freq[ch] / total) * (expected / 100.0)
        for ch, expected in _ENGLISH_FREQ.items()
        if ch in freq
    )
    return score


def _index_of_coincidence(text: str) -> float:
    letters = [c.lower() for c in text if c.isalpha()]
    n = len(letters)
    if n < 2:
        return 0.0
    freq = Counter(letters)
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _check_magic(data: bytes) -> str | None:
    for magic, fmt in _MAGIC.items():
        if data.startswith(magic):
            return fmt
    return None


def _repeated_byte_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    return counts.most_common(1)[0][1] / len(data)


# ---------------------------------------------------------------------------
# Text detectors
# ---------------------------------------------------------------------------

def _detect_text(text: str) -> list[Finding]:
    findings: list[Finding] = []
    stripped = text.strip()
    n = len(stripped)
    if not n:
        return findings

    found_types: set[str] = set()

    # --- Hash types (must come before hex / base64) ---
    if re.fullmatch(r'[0-9a-fA-F]+', stripped):
        h = n
        hash_map = {
            32: ('hash_md5',    0.95, '32 hex chars — likely MD5'),
            40: ('hash_sha1',   0.95, '40 hex chars — likely SHA-1'),
            56: ('hash_sha224', 0.90, '56 hex chars — likely SHA-224'),
            64: ('hash_sha256', 0.95, '64 hex chars — likely SHA-256'),
            96: ('hash_sha384', 0.90, '96 hex chars — likely SHA-384'),
            128:('hash_sha512', 0.95, '128 hex chars — likely SHA-512'),
        }
        if h in hash_map:
            htype, hconf, hhint = hash_map[h]
            findings.append(Finding(htype, hconf, hhint))
            found_types.add(htype)
            findings.append(Finding('hex_string', 0.50,
                                    f'Even-length hex — also matches {htype}'))
            found_types.add('hex_string')
        elif h % 2 == 0:
            findings.append(Finding('hex_string', 0.80,
                                    f'Even-length hex string ({h} chars)'))
            found_types.add('hex_string')

    # --- Base64 ---
    b64_clean = stripped.rstrip('=')
    has_b64_chars = (set(b64_clean) <= _BASE64_CHARS or
                     set(b64_clean) <= _BASE64URL_CHARS)
    if has_b64_chars and n > 4:
        padding_ok = len(stripped) % 4 == 0
        conf = 0.80 if padding_ok else 0.55
        letter_score = _letter_freq_score(stripped)
        if letter_score > 0.70:
            conf *= 0.4
        findings.append(Finding('base64', conf,
                                f'Base64 charset, length={n}, '
                                f'padding={"ok" if padding_ok else "missing"}'))
        found_types.add('base64')

    # --- Base32 ---
    if re.fullmatch(r'[A-Z2-7]+=*', stripped) and n >= 8:
        padding_ok = len(stripped) % 8 == 0
        findings.append(Finding('base32', 0.85 if padding_ok else 0.60,
                                f'Base32 charset (A-Z/2-7), length={n}'))
        found_types.add('base32')

    # --- Base58 ---
    if set(stripped) <= _BASE58_ALPHABET and n >= 10 and stripped.isalnum():
        no_ambiguous = not any(c in stripped for c in '0OIl')
        findings.append(Finding('base58', 0.75 if no_ambiguous else 0.45,
                                f'Base58 charset, length={n}'))
        found_types.add('base58')

    # --- Base85 (Bug fix #5: tighten — require min length 20, no hex overlap) ---
    if (n >= 20
            and 'hex_string' not in found_types
            and all(33 <= ord(c) <= 117 for c in stripped)
            and not stripped.isalnum()):
        findings.append(Finding('base85', 0.45,
                                f'Chars in Base85 printable range, length={n}'))
        found_types.add('base85')

    # --- Morse code ---
    if re.fullmatch(r'[.\- /]+', stripped) and n > 3:
        findings.append(Finding('morse', 0.90,
                                'Only . - / and space — Morse code pattern'))
        found_types.add('morse')

    # --- ROT13 / Caesar ---
    # Only skip Caesar detection when base64 decodes to *readable* output
    # (i.e. it really is base64).  CTF flags like "j1woly_y_mbu" match the
    # Base64URL charset but decode to binary garbage, so they must still be
    # checked as Caesar ciphers.
    alpha_ratio = sum(c.isalpha() for c in stripped) / n
    if alpha_ratio > 0.55:
        eng = _letter_freq_score(stripped)
        _skip_caesar = False
        if 'base64' in found_types and any(
            f.type == 'base64' and f.confidence >= 0.75 for f in findings
        ):
            try:
                import base64 as _b64mod
                _decoded = _b64mod.b64decode(stripped + '==')
                _printable = sum(0x20 <= b < 0x7f for b in _decoded)
                if _decoded and (_printable / len(_decoded)) >= 0.70:
                    _skip_caesar = True
            except Exception:
                pass

        if not _skip_caesar:
            if eng < 0.045:
                findings.append(Finding('caesar_rot', 0.70,
                                        f'High letter ratio ({alpha_ratio:.0%}), '
                                        f'low English score ({eng:.2f}) — shifted?'))
                found_types.add('caesar_rot')

    # --- Vigenere ---
    # Require >= 40 alpha chars for reliable IoC stats; tighten range to
    # 0.038–0.055; also require English score < 0.050 so plain English
    # text with an unusual letter distribution (e.g. pangrams) doesn't fire.
    alpha_chars = sum(c.isalpha() for c in stripped)
    if alpha_chars >= 40:
        ioc = _index_of_coincidence(stripped)
        vig_eng = _letter_freq_score(stripped)
        if 0.038 <= ioc <= 0.055 and vig_eng < 0.050:
            findings.append(Finding('vigenere', 0.70,
                                    f'Index of coincidence={ioc:.4f} '
                                    f'(polyalphabetic range 0.038–0.055)'))
            found_types.add('vigenere')

    # --- XOR (high entropy short text) ---
    data = stripped.encode('latin-1', errors='replace')
    ent = _entropy(data)
    if ent > 6.5 and n < 500 and 'base64' not in found_types:
        findings.append(Finding('xor_encrypted', 0.60,
                                f'Entropy={ent:.2f} bits — high entropy suggests XOR'))
        found_types.add('xor_encrypted')

    return findings


# ---------------------------------------------------------------------------
# File detectors
# ---------------------------------------------------------------------------

def _detect_file(path: Path) -> list[Finding]:
    findings: list[Finding] = []

    if not path.exists():
        findings.append(Finding('error', 0.0, f'File not found: {path}'))
        return findings

    size = path.stat().st_size
    with open(path, 'rb') as fh:
        header = fh.read(16)

    fmt = _check_magic(header)
    if fmt in ('png', 'jpg', 'bmp', 'gif'):
        findings.append(Finding('image_file', 0.99,
                                f'Magic bytes match {fmt.upper()} — stego analysis',
                                meta={'format': fmt, 'size': size}))
    elif fmt in ('zip', 'rar', '7z'):
        findings.append(Finding('archive_file', 0.99,
                                f'Magic bytes match {fmt.upper()} archive',
                                meta={'format': fmt, 'size': size}))
    elif fmt == 'pdf':
        findings.append(Finding('pdf_file', 0.99, 'PDF magic bytes'))
    elif fmt in ('gzip', 'bzip2'):
        findings.append(Finding('compressed_file', 0.99, f'{fmt} magic bytes'))
    else:
        try:
            with open(path, 'r', encoding='utf-8', errors='strict') as fh:
                text_content = fh.read(4096)
            findings.append(Finding('text_file', 0.80,
                                    f'Readable UTF-8 text, size={size}'))
            findings.extend(_detect_text(text_content))
        except UnicodeDecodeError:
            with open(path, 'rb') as fh:
                raw = fh.read(4096)
            ent = _entropy(raw)
            findings.append(Finding('binary_file', 0.70,
                                    f'Unknown binary, entropy={ent:.2f}',
                                    meta={'entropy': ent, 'size': size}))
            findings.extend(_detect_binary(raw))

    return findings


# ---------------------------------------------------------------------------
# Binary / hex detectors
# ---------------------------------------------------------------------------

def _detect_binary(data: bytes) -> list[Finding]:
    findings: list[Finding] = []
    if not data:
        return findings

    text = data.decode('latin-1')
    hex_stripped = text.strip()
    if re.fullmatch(r'[0-9a-fA-F\s]+', hex_stripped):
        try:
            raw = bytes.fromhex(hex_stripped.replace(' ', '').replace('\n', ''))
            fmt = _check_magic(raw)
            if fmt:
                findings.append(Finding('hex_encoded_binary', 0.90,
                                        f'Hex decodes to {fmt.upper()} magic bytes'))
        except ValueError:
            pass

    ent = _entropy(data)
    rep = _repeated_byte_ratio(data)

    if ent > 7.5:
        findings.append(Finding('encrypted_or_compressed', 0.80,
                                f'Entropy={ent:.2f} bits (>7.5) — likely encrypted/compressed'))
    elif ent < 4.0:
        findings.append(Finding('low_entropy_binary', 0.70,
                                f'Entropy={ent:.2f} bits (<4.0) — likely plaintext/structured'))

    if rep > 0.15:
        dominant = Counter(data).most_common(1)[0][0]
        findings.append(Finding('xor_encrypted', 0.70,
                                f'Byte 0x{dominant:02x} repeats {rep:.0%} — '
                                f'possible single-byte XOR (key candidate: 0x{dominant:02x})'))

    printable = sum(0x20 <= b < 0x7f for b in data)
    if printable / len(data) > 0.70:
        findings.append(Finding('printable_strings', 0.75,
                                f'{printable/len(data):.0%} printable ASCII bytes'))

    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def fingerprint(input_data: Union[str, bytes, Path]) -> list[Finding]:
    """
    Fingerprint the given input and return findings sorted by confidence (desc).

    Args:
        input_data: A string (text or hex), bytes (raw binary), or Path (file).

    Returns:
        Sorted list of Finding objects.
    """
    findings: list[Finding] = []

    if isinstance(input_data, Path) or (
        isinstance(input_data, str) and os.path.exists(input_data)
    ):
        findings = _detect_file(Path(input_data))
    elif isinstance(input_data, bytes):
        findings = _detect_binary(input_data)
    elif isinstance(input_data, str):
        findings = _detect_text(input_data)
    else:
        findings = [Finding('unknown', 0.0,
                            f'Unsupported input type: {type(input_data)}')]

    return sorted(findings, key=lambda f: f.confidence, reverse=True)
