"""
Image metadata extraction: EXIF, ICC profile, XMP comments.

Flags any field containing a non-standard or unusually long string value.
"""
from __future__ import annotations
from pathlib import Path
import string

_PRINTABLE = set(string.printable)


def _is_suspicious(value: str) -> bool:
    """True if the string looks like it might hide data."""
    if len(value) > 100:
        return True
    non_print = sum(1 for c in value if c not in _PRINTABLE)
    return non_print > 2


def extract_metadata(image_path: str | Path) -> dict | None:
    """
    Extract and flag suspicious metadata from an image file.

    Returns {"flagged": list[str], "confidence": float} or None.
    """
    try:
        from PIL import Image
        img = Image.open(str(image_path))
    except Exception:
        return None

    flagged: list[str] = []

    # EXIF
    try:
        import piexif
        raw_exif = img.info.get('exif', b'')
        if raw_exif:
            exif_dict = piexif.load(raw_exif)
            for ifd_name, ifd in exif_dict.items():
                if not isinstance(ifd, dict):
                    continue
                for tag, val in ifd.items():
                    if isinstance(val, bytes):
                        try:
                            s = val.decode('utf-8', errors='replace')
                            if _is_suspicious(s):
                                flagged.append(
                                    f'[EXIF:{ifd_name}:{tag}] long or non-printable EXIF field: {s[:60]}'
                                )
                        except Exception:
                            pass
                    elif isinstance(val, str) and _is_suspicious(val):
                        flagged.append(
                            f'[EXIF:{ifd_name}:{tag}] long or non-printable EXIF tag: {val[:60]}'
                        )
    except Exception:
        pass

    # XMP
    try:
        xmp = img.info.get('xmp') or img.info.get('XML:com.adobe.xmp', b'')
        if isinstance(xmp, bytes):
            xmp = xmp.decode('utf-8', errors='replace')
        if xmp and len(xmp) > 500:
            flagged.append(f'[XMP] unusually large XMP block: {len(xmp)} bytes')
    except Exception:
        pass

    # ICC profile
    try:
        icc = img.info.get('icc_profile') or img.info.get('ICC_profile')
        if icc:
            printable = sum(1 for b in icc if chr(b) in _PRINTABLE)
            if printable > 20:
                flagged.append(
                    f'[ICC] ICC profile contains {printable} printable bytes'
                )
    except Exception:
        pass

    # PNG text chunks and JPEG comments
    try:
        for key in ('comments', 'comment', 'Description', 'Author', 'Title',
                    'Software', 'Warning', 'Disclaimer', 'Source', 'Copyright'):
            val = img.info.get(key)
            if val:
                if isinstance(val, bytes):
                    val = val.decode('utf-8', errors='replace')
                if _is_suspicious(str(val)):
                    flagged.append(f'[{key}] suspicious comment/text chunk: {str(val)[:80]}')
                else:
                    flagged.append(f'[{key}] info: {str(val)[:80]}')
    except Exception:
        pass

    # PNG metadata from info dict
    try:
        for key, val in img.info.items():
            if key in ('exif', 'xmp', 'icc_profile', 'ICC_profile',
                       'comments', 'comment'):
                continue
            if isinstance(val, str) and _is_suspicious(val):
                flagged.append(f'[{key}] suspicious image info field: {val[:60]}')
    except Exception:
        pass

    if not flagged:
        return None

    confidence = min(0.50 + 0.10 * len(flagged), 0.90)
    return {"flagged": flagged, "confidence": confidence}
