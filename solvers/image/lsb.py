"""
LSB steganography extraction.

Extracts the least-significant bits from individual R/G/B/A channels
across bit planes 0-3, then reassembles bytes and checks for printable
ASCII or known magic bytes.
"""
from __future__ import annotations
from pathlib import Path
import string

_PRINTABLE = set(string.printable.encode())

_MAGIC = {
    b'\x89PNG': 'PNG',
    b'\xff\xd8\xff': 'JPEG',
    b'BM': 'BMP',
    b'GIF8': 'GIF',
    b'PK\x03\x04': 'ZIP',
    b'%PDF': 'PDF',
}


def _bits_to_bytes(bits: list[int]) -> bytes:
    """Pack a flat list of bits (MSB first per byte) into bytes."""
    out = []
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for b in bits[i:i + 8]:
            byte = (byte << 1) | b
        out.append(byte)
    return bytes(out)


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(b in _PRINTABLE for b in data) / len(data)


def _has_magic(data: bytes) -> str | None:
    for magic, fmt in _MAGIC.items():
        if data.startswith(magic):
            return fmt
    return None


def _try_extract(pixels, channel_idx: int, bit_plane: int,
                 width: int, height: int) -> dict | None:
    """Extract one bit-plane from one channel and return result if interesting."""
    bits = []
    for pixel in pixels:
        val = pixel[channel_idx] if isinstance(pixel, (tuple, list)) else pixel
        bits.append((val >> bit_plane) & 1)

    data = _bits_to_bytes(bits)
    if not data:
        return None

    fmt = _has_magic(data)
    if fmt:
        return {
            "decoded_text": f"Magic bytes: {fmt}",
            "raw": data,
            "confidence": 0.85,
        }

    # Check for printable prefix
    prefix = bytearray()
    for b in data:
        if b in _PRINTABLE:
            prefix.append(b)
        else:
            break

    if len(prefix) >= 6:
        try:
            text = prefix.decode('latin-1')
            ratio = len(prefix) / len(data)
            return {
                "decoded_text": f"Printable prefix of {len(prefix)} bytes: {text[:80]}",
                "raw": data,
                "confidence": 0.60 + 0.25 * ratio,
            }
        except Exception:
            pass

    full_ratio = _printable_ratio(data)
    if full_ratio > 0.95 and len(data) > 10:
        try:
            text = data.decode('latin-1')
            return {
                "decoded_text": f"{full_ratio:.0%} printable ASCII: {text[:80]}",
                "raw": data,
                "confidence": 0.70,
            }
        except Exception:
            pass

    return None


def extract_lsb(image_path: str | Path) -> list[dict] | None:
    """
    Extract LSB data from each channel (R/G/B/A) across bit planes 0-3.

    Returns a list of interesting findings (non-empty printable text or
    known magic bytes), or None if the file cannot be opened / nothing found.
    """
    try:
        from PIL import Image
        img = Image.open(str(image_path)).convert('RGBA')
    except Exception:
        return None

    width, height = img.size
    pixels = list(img.getdata())

    channel_names = ['R', 'G', 'B', 'A']
    results = []

    for ch_idx, ch_name in enumerate(channel_names):
        for bit_plane in range(4):
            result = _try_extract(pixels, ch_idx, bit_plane, width, height)
            if result:
                result['channel_name'] = f'{ch_name} bit-{bit_plane}'
                results.append(result)

    return results if results else None
