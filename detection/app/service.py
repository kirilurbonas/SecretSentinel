from __future__ import annotations

import os
from typing import Iterable, List

from prometheus_client import Counter

from .detectors import context as ctx
from .detectors import regex_rules
from .models import ScanRequest, ScanResultItem

MIN_CONFIDENCE: float = float(os.getenv("SENTINEL_MIN_CONFIDENCE", "0.5"))

_secrets_detected = Counter(
    "secrets_detected_total",
    "Total number of secrets detected",
    ["rule_id"],
)


def scan_content(request: ScanRequest) -> List[ScanResultItem]:
    lines = request.content.splitlines()
    findings: List[ScanResultItem] = []

    for line_no, line in enumerate(lines, start=1):
        findings.extend(_scan_line(request.filename, line_no, line))

    return findings


def _scan_line(filename: str, line_no: int, line: str) -> List[ScanResultItem]:
    if not line:
        return []

    ctx_info = ctx.build_context(filename, line)
    results: List[ScanResultItem] = []

    for rule in regex_rules.ALL_RULES:
        matches: Iterable[str]
        matches = regex_rules.iter_rule_matches(rule, line, filename)

        # For generic high-entropy, post-filter by entropy and length.
        if rule.id == "high_entropy":
            matches = regex_rules.filter_high_entropy(matches, min_entropy=4.8, min_length=20)

        for value in matches:
            base_conf = rule.base_confidence
            conf = adjust_confidence(base_conf, ctx_info, rule.id)
            if conf < MIN_CONFIDENCE:
                continue
            _secrets_detected.labels(rule_id=rule.id).inc()
            results.append(
                ScanResultItem(
                    line=line_no,
                    type=rule.type,
                    value=value,
                    confidence=conf,
                )
            )

    return results


def adjust_confidence(base: float, ctx_info: ctx.ContextInfo, rule_id: str) -> float:
    score = base

    if ctx_info.is_test_file or ctx_info.is_example_file:
        score -= 0.2

    if ctx_info.is_comment_line:
        score -= 0.2

    # Certain rules are inherently more reliable.
    if rule_id in {"private_key", "aws_access_key"}:
        score += 0.05

    # Clamp between 0.0 and 1.0
    if score < 0.0:
        score = 0.0
    if score > 1.0:
        score = 1.0
    return score
