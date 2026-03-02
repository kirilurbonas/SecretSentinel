from __future__ import annotations

from app.detectors.entropy import shannon_entropy


def test_shannon_entropy_empty() -> None:
    assert shannon_entropy("") == 0.0


def test_shannon_entropy_low() -> None:
    assert shannon_entropy("aaaaaa") < 0.1


def test_shannon_entropy_binary() -> None:
    h = shannon_entropy("abababab")
    assert 0.9 < h < 1.1

