"""
Palette-mode image analysis — looks for hidden ASCII text in the colour table.
"""
from __future__ import annotations
from pathlib import Path


def _decode_palette_text(palette_bytes: bytes) -> str | None:
    """Extract a contiguous run of printable ASCII from the start of the palette."""
    out = bytearray()
    for b in palette_bytes:
        if 0x20 <= b < 0x7f:
            out.append(b)
        elif out:
            break
    if len(out) >= 4:
        try:
            return out.decode('ascii', errors='replace')
        except Exception:
            pass
    return None


def _palette_as_hex(palette_bytes: bytes) -> str:
    """Return the raw palette as a hex string (grouped in RGB triples)."""
    return ' '.join(
        palette_bytes[i:i+3].hex()
        for i in range(0, min(len(palette_bytes), 48), 3)
    )


def analyze_palette(image_path: str | Path) -> dict | None:
    """
    Analyse the colour palette of a palette-mode (mode='P') image.

    Returns a dict with findings, or None if not applicable / nothing found.
    """
    try:
        from PIL import Image
        img = Image.open(str(image_path))
    except Exception:
        return None

    if img.mode != 'P':
        return None

    palette = img.getpalette()
    if not palette:
        return None

    # PIL returns palette as flat [R,G,B, R,G,B, ...] list of ints
    palette_bytes = bytes(palette)
    findings: list[str] = []

    # Check for ASCII text in the palette
    text = _decode_palette_text(palette_bytes)
    if text:
        findings.append(f'Palette contains {len(text)} printable ASCII bytes: {text[:60]}')

    # Check for suspiciously few unique colours
    unique_colours = len(set(
        (palette[i], palette[i+1], palette[i+2])
        for i in range(0, len(palette), 3)
        if i + 2 < len(palette)
    ))
    if unique_colours < 8:
        findings.append(f'Only {unique_colours} colours used — suspicious palette')

    if not findings:
        return None

    decoded_text = text if text else _palette_as_hex(palette_bytes)
    return {
        "decoded_text": f'Palette-mode image — palette extracted: {"; ".join(findings)}',
        "confidence": 0.65,
        "raw_text": decoded_text,
    }
