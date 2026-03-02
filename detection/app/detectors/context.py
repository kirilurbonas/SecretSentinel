from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ContextInfo:
    is_test_file: bool
    is_example_file: bool
    is_comment_line: bool


def classify_filename(filename: str) -> tuple[bool, bool]:
    lower = filename.lower()
    is_test = any(x in lower for x in ("test_", "_test", ".spec.", ".tests.", "fixtures"))
    is_example = any(x in lower for x in ("example", "examples", "sample", "demo"))
    return is_test, is_example


def is_comment_line(line: str) -> bool:
    stripped = line.lstrip()
    return stripped.startswith(("#", "//", "/*", "* ", "--"))


def build_context(filename: str, line: str) -> ContextInfo:
    is_test, is_example = classify_filename(filename)
    return ContextInfo(
        is_test_file=is_test,
        is_example_file=is_example,
        is_comment_line=is_comment_line(line),
    )

