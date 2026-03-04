"""
Classical cipher solvers: Caesar brute-force, ROT13, Vigenère crack, Atbash.
"""
from __future__ import annotations

import re
import string
from itertools import product

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_COMMON_WORDS = frozenset(
    'the and that have with this from they will been have said not but what'
    ' all were when your can said there use each which she how their if will'
    ' one would about out up into go its him over think also back after come'
    ' could our then than only very much even new want more now'.split()
)

_ENGLISH_FREQ_ORDER = 'etaoinshrdlcumwfgypbvkjxqz'

# Expected frequency per letter (percent), used for chi-squared / dot-product
_ENGLISH_FREQ = {
    'a': 8.17, 'b': 1.49, 'c': 2.78, 'd': 4.25, 'e': 12.70, 'f': 2.23,
    'g': 2.02, 'h': 6.09, 'i': 6.97, 'j': 0.15, 'k': 0.77, 'l': 4.03,
    'm': 2.41, 'n': 6.75, 'o': 7.51, 'p': 1.93, 'q': 0.10, 'r': 5.99,
    's': 6.33, 't': 9.06, 'u': 2.76, 'v': 0.98, 'w': 2.36, 'x': 0.15,
    'y': 1.97, 'z': 0.07,
}


def _score_english(text: str) -> float:
    """Score text by English word presence + letter frequency."""
    words = re.findall(r'[a-z]+', text.lower())
    if not words:
        return 0.0
    word_score = sum(1 for w in words if w in _COMMON_WORDS) / len(words)

    letters = [c for c in text.lower() if c.isalpha()]
    if not letters:
        return word_score
    from collections import Counter
    freq = Counter(letters)
    total = len(letters)
    freq_score = 0.0
    for i, ch in enumerate(_ENGLISH_FREQ_ORDER):
        rank = sorted(freq, key=freq.get, reverse=True)
        if ch in rank[:6]:
            freq_score += 1 / (rank.index(ch) + 1)
    freq_score /= 6

    return 0.6 * word_score + 0.4 * freq_score


def _freq_dot_score(text: str) -> float:
    """
    Dot-product of observed vs expected English letter frequencies.
    Reliable even for short strings with digits/underscores (CTF flags).
    """
    from collections import Counter
    letters = [c for c in text.lower() if c.isalpha()]
    if not letters:
        return 0.0
    freq = Counter(letters)
    total = len(letters)
    return sum(
        (freq[ch] / total) * expected
        for ch, expected in _ENGLISH_FREQ.items()
        if ch in freq
    )


def _shift_char(c: str, n: int) -> str:
    if c.isalpha():
        base = ord('A') if c.isupper() else ord('a')
        return chr((ord(c) - base + n) % 26 + base)
    return c


# ---------------------------------------------------------------------------
# Caesar brute-force
# ---------------------------------------------------------------------------

def caesar_brute(text: str) -> list[dict]:
    """
    Try all 25 Caesar shifts. Return top 5 by English score.

    Returns:
        List of up to 5 dicts: {"decoded": str, "key": int, "confidence": float}
    """
    results = []
    for shift in range(1, 26):
        candidate = ''.join(_shift_char(c, shift) for c in text)
        score = _freq_dot_score(candidate)
        results.append({"decoded": candidate, "key": shift, "score": score})

    results.sort(key=lambda r: r["score"], reverse=True)
    top5 = results[:5]

    # Normalise to confidence
    max_score = top5[0]["score"] if top5 else 1.0
    for r in top5:
        r["confidence"] = min(r["score"] / max(max_score, 0.01), 1.0) * 0.85
        del r["score"]

    return top5


# ---------------------------------------------------------------------------
# ROT13
# ---------------------------------------------------------------------------

def rot13(text: str) -> dict:
    """Direct ROT13 decode."""
    decoded = ''.join(_shift_char(c, 13) for c in text)
    confidence = _score_english(decoded)
    return {"decoded": decoded, "key": 13, "confidence": min(confidence * 1.5, 0.95)}


# ---------------------------------------------------------------------------
# Vigenère crack (Kasiski + Index of Coincidence + frequency analysis)
# ---------------------------------------------------------------------------

def _index_of_coincidence(text: str) -> float:
    letters = [c.lower() for c in text if c.isalpha()]
    n = len(letters)
    if n < 2:
        return 0.0
    from collections import Counter
    freq = Counter(letters)
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))


def _top_key_lengths(text: str, n: int = 3, max_len: int = 20) -> list[int]:
    """
    Return top-n candidate key lengths ranked by average IoC across streams.
    Divisors of the true key length can also score well, so callers should
    try all candidates and score the decoded text to pick the best.
    """
    letters = [c.lower() for c in text if c.isalpha()]
    scores = []
    for kl in range(2, min(max_len + 1, len(letters) // 3)):
        streams = [''.join(letters[i::kl]) for i in range(kl)]
        avg_ioc = sum(_index_of_coincidence(s) for s in streams) / kl
        scores.append((kl, avg_ioc))

    if not scores:
        return [1]

    scores.sort(key=lambda x: x[1], reverse=True)
    return [kl for kl, _ in scores[:n]]


def _freq_solve_stream(stream: str) -> str:
    """
    Solve a single Caesar stream by dot-product correlation against
    the expected English frequency distribution.  More reliable than
    the 'map most common letter to e' heuristic on short texts.
    """
    from collections import Counter
    letters = [c.lower() for c in stream if c.isalpha()]
    if not letters:
        return 'a'

    total = len(letters)
    freq = Counter(letters)

    best_key, best_score = 0, -1.0
    for key_byte in range(26):
        score = 0.0
        for cipher_ch, count in freq.items():
            plain_ch = chr((ord(cipher_ch) - ord('a') - key_byte) % 26 + ord('a'))
            score += (count / total) * _ENGLISH_FREQ.get(plain_ch, 0.0)
        if score > best_score:
            best_score = score
            best_key = key_byte

    return chr(ord('a') + best_key)


def _vigenere_decrypt(text: str, key: str) -> str:
    key_idx = 0
    out = []
    for ch in text:
        if ch.isalpha():
            shift = ord(key[key_idx % len(key)].lower()) - ord('a')
            out.append(_shift_char(ch, -shift))
            key_idx += 1
        else:
            out.append(ch)
    return ''.join(out)


def vigenere_crack(text: str) -> dict | None:
    """
    Attempt to crack a Vigenère cipher.
    Tries the top 3 IoC-ranked key lengths and scores each decoded result.
    Returns {"decoded": str, "key": str, "confidence": float} or None.
    """
    letters = [c.lower() for c in text if c.isalpha()]
    if len(letters) < 20:
        return None

    candidates = _top_key_lengths(text, n=3)
    results = []
    for key_len in candidates:
        streams = [''.join(letters[i::key_len]) for i in range(key_len)]
        key = ''.join(_freq_solve_stream(s) for s in streams)
        decoded = _vigenere_decrypt(text, key)
        score = _score_english(decoded)
        results.append({"decoded": decoded, "key": key, "score": score})

    results.sort(key=lambda r: r["score"], reverse=True)
    best = results[0]
    confidence = min(best["score"] * 1.2, 0.90)
    return {"decoded": best["decoded"], "key": best["key"], "confidence": confidence}


# ---------------------------------------------------------------------------
# Atbash
# ---------------------------------------------------------------------------

def atbash(text: str) -> dict:
    """Direct Atbash decode (A↔Z, B↔Y, …)."""
    def _atbash_char(c: str) -> str:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            return chr(base + 25 - (ord(c) - base))
        return c

    decoded = ''.join(_atbash_char(c) for c in text)
    confidence = _score_english(decoded)
    return {"decoded": decoded, "key": None, "confidence": min(confidence * 1.5, 0.90)}
