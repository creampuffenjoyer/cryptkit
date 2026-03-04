"""
XOR solvers: single-byte brute-force and multi-byte key recovery.
"""
from __future__ import annotations

import string


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PRINTABLE = set(string.printable.encode())


def _score_bytes(data: bytes) -> float:
    """Score decoded bytes by printable ASCII ratio + English letter bonus."""
    if not data:
        return 0.0
    printable = sum(b in _PRINTABLE for b in data)
    base_score = printable / len(data)

    # Bonus for common English letters / spaces
    english_bonus = sum(
        1 for b in data
        if chr(b).lower() in 'etaoinshrdlu '
    ) / len(data)
    return base_score * 0.7 + english_bonus * 0.3


def _hamming_distance(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count('1') for x, y in zip(a, b))


def _normalised_hamming(data: bytes, key_len: int) -> float:
    """Average normalised Hamming distance between consecutive blocks."""
    n_blocks = min(8, len(data) // key_len)
    if n_blocks < 2:
        return float('inf')
    distances = []
    for i in range(n_blocks - 1):
        a = data[i * key_len:(i + 1) * key_len]
        b = data[(i + 1) * key_len:(i + 2) * key_len]
        distances.append(_hamming_distance(a, b) / key_len)
    return sum(distances) / len(distances)


def _xor_with_key(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


# ---------------------------------------------------------------------------
# Single-byte XOR
# ---------------------------------------------------------------------------

def xor_single_byte(data: bytes) -> list[dict]:
    """
    Brute-force all 256 single-byte XOR keys.

    Returns:
        Top 3 results: [{"decoded": str, "key": int, "key_hex": str, "confidence": float}]
    """
    results = []
    for key in range(256):
        decrypted = bytes(b ^ key for b in data)
        score = _score_bytes(decrypted)
        results.append({
            "decoded": decrypted.decode('latin-1'),
            "key": key,
            "key_hex": f"0x{key:02x}",
            "score": score,
        })

    results.sort(key=lambda r: r["score"], reverse=True)
    top3 = results[:3]

    max_score = top3[0]["score"] if top3 else 1.0
    for r in top3:
        r["confidence"] = min(r["score"] / max(max_score, 0.01) * 0.90, 0.95)
        del r["score"]

    return top3


# ---------------------------------------------------------------------------
# Multi-byte XOR
# ---------------------------------------------------------------------------

def xor_multi_byte(data: bytes, max_keylen: int = 16) -> list[dict]:
    """
    Recover multi-byte XOR key using Hamming distance key-length detection,
    then frequency analysis per byte stream.

    Returns:
        Top 3 results: [{"decoded": str, "key": bytes, "key_hex": str, "confidence": float}]
    """
    if len(data) < max_keylen * 2:
        return xor_single_byte(data)

    # Find best key lengths by normalised Hamming distance
    key_scores = []
    for kl in range(1, max_keylen + 1):
        dist = _normalised_hamming(data, kl)
        key_scores.append((kl, dist))

    key_scores.sort(key=lambda x: x[1])
    top_key_lengths = [kl for kl, _ in key_scores[:3]]

    results = []
    for kl in top_key_lengths:
        # Split into kl streams, solve each with single-byte brute-force
        streams = [data[i::kl] for i in range(kl)]
        key_bytes = []
        for stream in streams:
            best = xor_single_byte(stream)[0]
            key_bytes.append(best["key"])

        key = bytes(key_bytes)
        decrypted = _xor_with_key(data, key)
        score = _score_bytes(decrypted)
        results.append({
            "decoded": decrypted.decode('latin-1'),
            "key": key,
            "key_hex": key.hex(),
            "score": score,
        })

    results.sort(key=lambda r: r["score"], reverse=True)
    top3 = results[:3]

    max_score = top3[0]["score"] if top3 else 1.0
    for r in top3:
        r["confidence"] = min(r["score"] / max(max_score, 0.01) * 0.90, 0.95)
        del r["score"]

    return top3
