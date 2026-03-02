from __future__ import annotations

from collections import Counter


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0

    counts = Counter(s)
    length = float(len(s))

    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0.0:
            # Use natural log and convert to bits.
            from math import log2

            entropy -= p * log2(p)
    return entropy

