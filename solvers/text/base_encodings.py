"""
Base encoding decoders: Base64, Base32, Base58, Base85.
Each function returns {"decoded": str, "confidence": float} or None on failure.
"""
from __future__ import annotations

import base64
import re
import string


# ---------------------------------------------------------------------------
# Base64
# ---------------------------------------------------------------------------

def decode_base64(text: str) -> dict | None:
    """Decode standard or URL-safe Base64."""
    text = text.strip()
    # Try standard first, then URL-safe (convert - → + and _ → /)
    for variant, candidate in [
        ("standard", text),
        ("url-safe", text.replace('-', '+').replace('_', '/')),
    ]:
        try:
            # Add padding if missing
            padded = candidate
            remainder = len(padded) % 4
            if remainder:
                padded += '=' * (4 - remainder)
            raw = base64.b64decode(padded, validate=True)
            decoded = raw.decode('utf-8', errors='replace')
            # Confidence: higher if result is clean printable ASCII
            printable_ratio = sum(c in string.printable for c in decoded) / max(len(decoded), 1)
            confidence = 0.85 + 0.10 * printable_ratio if printable_ratio > 0.90 else 0.60
            return {"decoded": decoded, "confidence": confidence, "variant": variant, "raw": raw}
        except Exception:
            continue
    return None


# ---------------------------------------------------------------------------
# Base32
# ---------------------------------------------------------------------------

def decode_base32(text: str) -> dict | None:
    """Decode standard Base32."""
    text = text.strip().upper()
    # Pad to multiple of 8
    remainder = len(text) % 8
    if remainder:
        text += '=' * (8 - remainder)
    try:
        raw = base64.b32decode(text, casefold=True)
        decoded = raw.decode('utf-8', errors='replace')
        printable_ratio = sum(c in string.printable for c in decoded) / max(len(decoded), 1)
        confidence = 0.90 if printable_ratio > 0.90 else 0.65
        return {"decoded": decoded, "confidence": confidence, "raw": raw}
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Base58
# ---------------------------------------------------------------------------

_B58_ALPHABET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def decode_base58(text: str) -> dict | None:
    """Decode Bitcoin-style Base58."""
    text = text.strip()
    if not all(c.encode() in _B58_ALPHABET for c in text):
        return None
    try:
        n = 0
        for char in text:
            n = n * 58 + _B58_ALPHABET.index(char.encode())
        # Convert integer to bytes
        result = []
        while n > 0:
            result.append(n % 256)
            n //= 256
        # Count leading 1s → leading zero bytes
        leading_zeros = len(text) - len(text.lstrip('1'))
        raw = bytes([0] * leading_zeros + result[::-1])
        decoded = raw.decode('utf-8', errors='replace')
        printable_ratio = sum(c in string.printable for c in decoded) / max(len(decoded), 1)
        confidence = 0.80 if printable_ratio > 0.85 else 0.50
        return {"decoded": decoded, "confidence": confidence, "raw": raw}
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Base85
# ---------------------------------------------------------------------------

def decode_base85(text: str) -> dict | None:
    """Decode ASCII85 / Base85."""
    text = text.strip()
    for decode_fn, label in [
        (base64.a85decode, "ascii85"),
        (base64.b85decode, "base85"),
    ]:
        try:
            raw = decode_fn(text.encode())
            decoded = raw.decode('utf-8', errors='replace')
            printable_ratio = sum(c in string.printable for c in decoded) / max(len(decoded), 1)
            confidence = 0.85 if printable_ratio > 0.90 else 0.55
            return {"decoded": decoded, "confidence": confidence, "variant": label, "raw": raw}
        except Exception:
            continue
    return None
