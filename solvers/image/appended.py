"""
Detect data appended after image EOF markers (PNG IEND, JPEG EOI),
or embedded file magic bytes inside the image data.
"""
from __future__ import annotations
from pathlib import Path

_EOF_MARKERS: list[tuple[bytes, str]] = [
    (b'\x00\x00\x00\x00IEND\xaeB`\x82', 'PNG IEND'),
    (b'\xff\xd9', 'JPEG EOI'),
]

_MAGIC: list[tuple[bytes, str]] = [
    (b'\x89PNG\r\n\x1a\n', 'PNG'),
    (b'\xff\xd8\xff', 'JPEG'),
    (b'PK\x03\x04', 'ZIP'),
    (b'Rar!', 'RAR'),
    (b'%PDF', 'PDF'),
    (b'\x1f\x8b', 'GZIP'),
    (b'BZh', 'BZIP2'),
    (b'7z\xbc\xaf', '7Z'),
]


def _find_embedded_magic(data: bytes, start: int) -> list[dict]:
    """Scan for embedded file magic bytes anywhere in data[start:]."""
    found = []
    for magic, fmt in _MAGIC:
        pos = start
        while True:
            idx = data.find(magic, pos)
            if idx == -1:
                break
            found.append({"type": fmt, "offset": idx})
            pos = idx + 1
    return found


def check_appended(file_path: str | Path) -> dict | None:
    """
    Check for data appended after PNG IEND or JPEG EOI,
    and scan for embedded magic byte signatures.

    Returns a dict with findings, or None if nothing suspicious found.
    """
    try:
        data = Path(file_path).read_bytes()
    except Exception:
        return None

    if not data:
        return None

    findings: list[str] = []
    result: dict = {}

    # Check EOF markers
    for marker, name in _EOF_MARKERS:
        idx = data.find(marker)
        if idx == -1:
            # Try shorter version for JPEG
            if b'\xff\xd9' in marker:
                idx = data.rfind(b'\xff\xd9')
                if idx == -1:
                    continue
                end_pos = idx + 2
                name = 'JPEG EOI'
            else:
                continue
        else:
            end_pos = idx + len(marker)

        if end_pos < len(data):
            appended = data[end_pos:]
            result['appended_data'] = appended[:200]
            result['appended_offset'] = end_pos
            result['eof_marker'] = name
            findings.append(
                f'{len(appended)} bytes after {name} at offset {end_pos}'
            )
            # Look for embedded magic in appended data
            embedded = _find_embedded_magic(appended, 0)
            if embedded:
                result['embedded_files'] = embedded
                types = list({e['type'] for e in embedded})
                findings.append(
                    f'Embedded {"/".join(types)} signature(s) found inside file'
                )
            break

    # Also scan entire file for embedded non-image magic (skip first 4 bytes)
    if not findings:
        embedded = _find_embedded_magic(data, 4)
        # Filter out the file's own magic
        embedded = [e for e in embedded if e['offset'] > 16]
        if embedded:
            types = list({e['type'] for e in embedded})
            findings.append(
                f'Embedded {"/".join(types)} signature(s) found inside file'
            )
            result['embedded_files'] = embedded

    if not findings:
        return None

    result['hint'] = '; '.join(findings)
    result['confidence'] = 0.85
    return result
