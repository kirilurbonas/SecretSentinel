from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, List

from .entropy import shannon_entropy


@dataclass
class RegexRule:
    id: str
    type: str
    pattern: re.Pattern[str]
    base_confidence: float


AWS_ACCESS_KEY = RegexRule(
    id="aws_access_key",
    type="AWS Access Key (AKIA...)",
    pattern=re.compile(r"AKIA[0-9A-Z]{16}"),
    base_confidence=0.98,
)

AWS_SECRET_KEY = RegexRule(
    id="aws_secret_key",
    type="AWS Secret Key",
    pattern=re.compile(r"[A-Za-z0-9/+=]{40}"),
    base_confidence=0.95,
)

GITHUB_PAT = RegexRule(
    id="github_pat",
    type="GitHub Personal Access Token",
    pattern=re.compile(r"ghp_[A-Za-z0-9]{36}"),
    base_confidence=0.95,
)

STRIPE_SECRET = RegexRule(
    id="stripe_secret",
    type="Stripe Secret Key (sk_live_...)",
    pattern=re.compile(r"sk_live_[A-Za-z0-9]{24,}"),
    base_confidence=0.95,
)

PRIVATE_KEY = RegexRule(
    id="private_key",
    type="Private Key Block",
    pattern=re.compile(r"-----BEGIN .* PRIVATE KEY-----"),
    base_confidence=0.99,
)

DATABASE_URL = RegexRule(
    id="database_url",
    type="Database URL",
    pattern=re.compile(r"(?i)\b(postgres://|mysql://|mongodb\+srv://)"),
    base_confidence=0.9,
)

ENV_ASSIGNMENT = RegexRule(
    id="env_assignment",
    type=".env-style Secret Assignment",
    pattern=re.compile(r"(?i)\b(PASSWORD|SECRET|TOKEN|API_KEY)\b\s*=\s*[^#\s]+"),
    base_confidence=0.85,
)

GENERIC_HIGH_ENTROPY = RegexRule(
    id="high_entropy",
    type="Generic High-Entropy Secret",
    pattern=re.compile(r"[A-Za-z0-9/\+=]{20,}"),
    base_confidence=0.7,
)


ALL_RULES: List[RegexRule] = [
    AWS_ACCESS_KEY,
    AWS_SECRET_KEY,
    GITHUB_PAT,
    STRIPE_SECRET,
    PRIVATE_KEY,
    DATABASE_URL,
    ENV_ASSIGNMENT,
    GENERIC_HIGH_ENTROPY,
    # Additional rules for other providers (Google, Azure, Slack, Twilio, etc.)
    # would be added here to reach 50+ total patterns.
]


def iter_rule_matches(rule: RegexRule, line: str) -> Iterable[str]:
    for match in rule.pattern.findall(line):
        # For patterns with groups, findall returns a tuple or first group;
        # normalize by casting to str.
        yield str(match)


def filter_high_entropy(tokens: Iterable[str], min_entropy: float, min_length: int) -> Iterable[str]:
    for token in tokens:
        if len(token) < min_length:
            continue
        if shannon_entropy(token) >= min_entropy:
            yield token

