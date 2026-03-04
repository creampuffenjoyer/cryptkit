"""
Hash type identification — pattern matching only, no cracking.
"""
from __future__ import annotations

import re

_HASH_PATTERNS = [
    (r'^[0-9a-fA-F]{32}$',  'MD5',     'md5',     'hashcat -m 0 / john --format=raw-md5'),
    (r'^[0-9a-fA-F]{40}$',  'SHA-1',   'sha1',    'hashcat -m 100 / john --format=raw-sha1'),
    (r'^[0-9a-fA-F]{56}$',  'SHA-224', 'sha224',  'hashcat -m 1300'),
    (r'^[0-9a-fA-F]{64}$',  'SHA-256', 'sha256',  'hashcat -m 1400 / john --format=raw-sha256'),
    (r'^[0-9a-fA-F]{96}$',  'SHA-384', 'sha384',  'hashcat -m 10800'),
    (r'^[0-9a-fA-F]{128}$', 'SHA-512', 'sha512',  'hashcat -m 1700 / john --format=raw-sha512'),
    (r'^\$2[aby]\$.{56}$',  'bcrypt',  'bcrypt',  'hashcat -m 3200 / john --format=bcrypt'),
    (r'^\$6\$.{86}$',       'SHA-512-crypt', 'sha512crypt', 'hashcat -m 1800'),
    (r'^\$5\$.{43}$',       'SHA-256-crypt', 'sha256crypt', 'hashcat -m 7400'),
    (r'^\$1\$.{22}$',       'MD5-crypt',     'md5crypt',    'hashcat -m 500'),
    (r'^[0-9a-fA-F]{8}$',   'CRC32',   'crc32',   'hashcat -m 11500'),
    (r'^[0-9a-fA-F]{16}$',  'MySQL323 / MSSQL 2000', 'mysql323', 'hashcat -m 200'),
]


def identify_hash(text: str) -> dict | None:
    """
    Identify hash type by length and character pattern.

    Returns:
        {
          "hash_type": str,
          "id": str,
          "crack_hint": str,
          "confidence": float,
          "value": str,
        }
        or None if not recognised.
    """
    text = text.strip()
    for pattern, name, id_, hint in _HASH_PATTERNS:
        if re.match(pattern, text):
            return {
                "hash_type": name,
                "id": id_,
                "crack_hint": hint,
                "confidence": 0.95,
                "value": text,
            }
    return None
