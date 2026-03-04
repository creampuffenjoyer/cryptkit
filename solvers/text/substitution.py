"""
Simple frequency-analysis substitution cipher solver.
"""
from __future__ import annotations

_ENGLISH_FREQ_ORDER = 'etaoinshrdlcumwfgypbvkjxqz'


def frequency_analysis(text: str) -> dict | None:
    """
    Attempt to crack a simple substitution cipher by mapping the most
    common letters in the ciphertext to the most common English letters.

    Returns {"decoded": str, "key": dict, "confidence": float} or None.
    """
    from collections import Counter

    letters = [c.lower() for c in text if c.isalpha()]
    if len(letters) < 20:
        return None

    freq = Counter(letters)
    cipher_order = [ch for ch, _ in freq.most_common()]

    # Build mapping: most frequent cipher letter -> most frequent English letter
    mapping: dict[str, str] = {}
    for i, cipher_ch in enumerate(cipher_order):
        if i < len(_ENGLISH_FREQ_ORDER):
            mapping[cipher_ch] = _ENGLISH_FREQ_ORDER[i]
        else:
            mapping[cipher_ch] = cipher_ch

    decoded = ''.join(
        mapping.get(c.lower(), c.lower()) if c.isalpha() else c
        for c in text
    )

    # Rough confidence: ratio of mapped letters
    confidence = min(len(mapping) / 26, 1.0) * 0.55
    return {"decoded": decoded, "key": mapping, "confidence": confidence}
