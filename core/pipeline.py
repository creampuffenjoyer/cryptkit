"""
Solver pipeline — maps fingerprint findings to solver functions and runs them.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

MAX_DEPTH = 3

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class SolverResult:
    finding_type: str
    solver_name: str
    success: bool
    confidence: float
    output: Any
    decoded: str | None
    key: Any = None
    depth: int = 0
    children: list['SolverResult'] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ENGLISH_FREQ_APPROX: dict[str, float] = {
    'e': 12.70, 't': 9.06, 'a': 8.17, 'o': 7.51, 'i': 6.97,
    'n': 6.75, 's': 6.33, 'h': 6.09, 'r': 5.99, 'd': 4.25,
    'l': 4.03, 'c': 2.78, 'u': 2.76, 'm': 2.41, 'w': 2.36,
    'f': 2.23, 'g': 2.02, 'y': 1.97, 'p': 1.93, 'b': 1.49,
    'v': 0.98, 'k': 0.77, 'j': 0.15, 'x': 0.15, 'q': 0.10, 'z': 0.07,
}

_MORSE_MAP: dict[str, str] = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
    '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
    '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
    '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
    '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
    '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
    '...--': '3', '....-': '4', '.....': '5', '-....': '6',
    '--...': '7', '---..': '8', '----.': '9',
    # Extended: common in CTF flags
    '..--.-': '_', '-...-': '=', '.-.-.-': '.', '--..--': ',',
    '..--..': '?', '.----.': "'", '-.-.--': '!', '-..-.': '/',
    '---...': ':', '-.-.-.': ';', '-.--.': '(', '-.--.-': ')',
}


def _looks_like_english(text: str) -> bool:
    """Return True if the text is probably already decoded plain English."""
    from collections import Counter
    letters = [c.lower() for c in text if c.isalpha()]
    if not letters:
        return False
    total = len(letters)
    freq = Counter(letters)
    score = sum(
        (freq[ch] / total) * (expected / 100.0)
        for ch, expected in _ENGLISH_FREQ_APPROX.items()
        if ch in freq
    )
    return score > 0.060


def _decode_morse(text: str) -> dict | None:
    words = text.strip().split('/')
    decoded_words = []
    for word in words:
        chars = []
        for code in word.strip().split():
            ch = _MORSE_MAP.get(code)
            if ch is None:
                return None
            chars.append(ch)
        decoded_words.append(''.join(chars))
    return {"decoded": ' '.join(decoded_words), "confidence": 0.95, "key": None}


def _to_bytes(data) -> bytes:
    if isinstance(data, bytes):
        return data
    if isinstance(data, str):
        return data.encode('latin-1', errors='replace')
    return bytes(data)


def _hash_wrapper(identify_fn):
    """Wrap identify_hash so its output is treated as identification, not decode."""
    def _inner(text):
        result = identify_fn(text)
        if result is None:
            return None
        label = f'[HASH: {result["hash_type"]}]  Crack: {result["crack_hint"]}'
        return {
            "decoded": label,
            "confidence": result["confidence"],
            "hash_type": result["hash_type"],
        }
    return _inner


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def _build_registry() -> dict:
    from solvers.text.base_encodings import (
        decode_base64, decode_base32, decode_base58, decode_base85,
    )
    from solvers.text.classical import caesar_brute, rot13, vigenere_crack, atbash
    from solvers.text.xor_solver import xor_single_byte, xor_multi_byte
    from solvers.text.hash_id import identify_hash
    from solvers.text.substitution import frequency_analysis
    from solvers.image.lsb import extract_lsb
    from solvers.image.metadata import extract_metadata
    from solvers.image.palette import analyze_palette
    from solvers.image.appended import check_appended

    def _hex_decode(t: str) -> dict | None:
        h = t.strip().replace(' ', '')
        if len(h) % 2 != 0:
            return None
        try:
            raw = bytes.fromhex(h)
            return {'decoded': raw.decode('utf-8', errors='replace'), 'confidence': 0.90}
        except Exception:
            return None

    return {
        'base64':    [('Base64 decoder',  decode_base64)],
        'base32':    [('Base32 decoder',  decode_base32)],
        'base58':    [('Base58 decoder',  decode_base58)],
        'base85':    [('Base85 decoder',  decode_base85)],
        'hex_string': [('Hex decoder',   _hex_decode)],
        'hash_md5':    [('Hash identifier', _hash_wrapper(identify_hash))],
        'hash_sha1':   [('Hash identifier', _hash_wrapper(identify_hash))],
        'hash_sha224': [('Hash identifier', _hash_wrapper(identify_hash))],
        'hash_sha256': [('Hash identifier', _hash_wrapper(identify_hash))],
        'hash_sha384': [('Hash identifier', _hash_wrapper(identify_hash))],
        'hash_sha512': [('Hash identifier', _hash_wrapper(identify_hash))],
        'caesar_rot': [
            ('Caesar brute', caesar_brute),
            ('ROT13',        rot13),
            ('Atbash',       atbash),
        ],
        'vigenere':   [('Vigenere crack', vigenere_crack)],
        'morse':      [('Morse decoder',  _decode_morse)],
        'xor_encrypted': [
            ('XOR single-byte', lambda d: xor_single_byte(_to_bytes(d))),
            ('XOR multi-byte',  lambda d: xor_multi_byte(_to_bytes(d))),
        ],
        'image_file': [
            ('LSB extractor',    extract_lsb),
            ('Metadata reader',  extract_metadata),
            ('Appended checker', check_appended),
            ('Palette analyzer', analyze_palette),
        ],
    }


# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------

def _extract_decoded(output: Any) -> tuple[str | None, Any]:
    """Pull (decoded_text, key) from various solver output shapes."""
    if output is None:
        return None, None
    if isinstance(output, list):
        output = output[0] if output else None
        if output is None:
            return None, None
    if isinstance(output, dict):
        decoded = (output.get('decoded') or output.get('decoded_text'))
        key = output.get('key')
        return (str(decoded) if decoded is not None else None), key
    return str(output), None


def _solver_confidence(output: Any) -> float:
    if isinstance(output, list):
        output = output[0] if output else None
    if isinstance(output, dict):
        return float(output.get('confidence', 0.5))
    return 0.5


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def _run_solvers(
    finding,
    raw_input,
    registry: dict,
    depth: int,
    stats: dict,
    seen: set[str],
    verbose_cb: Callable[[str], None] | None = None,
) -> list[SolverResult]:
    """Run all solvers registered for a finding type."""
    from core.fingerprint import fingerprint

    results: list[SolverResult] = []
    solver_list = registry.get(finding.type, [])

    for label, solver_fn in solver_list:
        stats["solvers_run"] += 1
        if verbose_cb:
            verbose_cb(f"  running {label} for \\[{finding.type}]...")

        try:
            output = solver_fn(raw_input)
        except Exception:
            output = None

        if output is None:
            continue

        # If solver returns a list (e.g. caesar_brute top-N), emit one
        # SolverResult per candidate so the display shows all of them.
        single_outputs = output if isinstance(output, list) else [output]

        for single_output in single_outputs:
            decoded, key = _extract_decoded(single_output)
            conf = _solver_confidence(single_output)
            success = decoded is not None and len(str(decoded).strip()) > 0

            result = SolverResult(
                finding_type=finding.type,
                solver_name=label,
                success=success,
                confidence=conf,
                output=single_output,
                decoded=decoded,
                key=key,
                depth=depth,
            )

            if (
                success
                and depth < MAX_DEPTH
                and isinstance(decoded, str)
                and decoded not in seen
                and not _looks_like_english(decoded)
            ):
                seen.add(decoded)
                child_findings = fingerprint(decoded)
                child_findings = [
                    f for f in child_findings
                    if f.confidence >= 0.75 and f.type not in ("base85",)
                ]
                for cf in child_findings[:2]:
                    child_results = _run_solvers(
                        cf, decoded, registry, depth + 1, stats, seen, verbose_cb
                    )
                    result.children.extend(child_results)

            results.append(result)

    return results


def run_pipeline(
    raw_input,
    findings: list,
    verbose_cb: Callable[[str], None] | None = None,
) -> tuple[list[SolverResult], dict]:
    """
    Run the full solver pipeline for a list of findings.

    Returns (solver_results, stats).
    """
    registry = _build_registry()
    stats = {"solvers_run": 0, "elapsed_s": 0.0}
    results: list[SolverResult] = []
    seen: set[str] = set()

    t0 = time.monotonic()

    for finding in findings:
        solver_results = _run_solvers(
            finding, raw_input, registry, depth=0,
            stats=stats, seen=seen, verbose_cb=verbose_cb,
        )
        results.extend(solver_results)

    stats["elapsed_s"] = time.monotonic() - t0
    return results, stats
