"""Tests for context classification utilities."""
from __future__ import annotations

import pytest
from app.detectors.context import build_context


@pytest.mark.parametrize("filename,expected_test,expected_example", [
    ("test_auth.py", True, False),
    ("auth_test.go", True, False),
    ("auth.spec.ts", True, False),
    ("fixtures/creds.json", True, False),
    ("examples/demo.py", False, True),
    ("sample_config.yaml", False, True),
    ("demo.sh", False, True),
    ("config.py", False, False),
    ("main.go", False, False),
])
def test_classify_filename(filename: str, expected_test: bool, expected_example: bool) -> None:
    ctx = build_context(filename, "irrelevant line")
    assert ctx.is_test_file == expected_test, f"{filename}: expected is_test_file={expected_test}"
    assert ctx.is_example_file == expected_example, f"{filename}: expected is_example_file={expected_example}"


@pytest.mark.parametrize("line,expected", [
    ("# this is a comment", True),
    ("// C-style comment", True),
    ("/* block comment start", True),
    ("* continuation of block comment", True),
    ("-- SQL comment", True),
    ("  # indented comment", True),
    ("PASSWORD=secret", False),
    ("import os  # inline comment after code", False),
    ("", False),
])
def test_is_comment_line(line: str, expected: bool) -> None:
    ctx = build_context("any.py", line)
    assert ctx.is_comment_line == expected, f"{line!r}: expected is_comment_line={expected}"
