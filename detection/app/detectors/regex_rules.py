from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, List, Optional

from .entropy import shannon_entropy


@dataclass
class RegexRule:
    id: str
    type: str
    pattern: re.Pattern[str]
    base_confidence: float
    filename_filter: Optional[re.Pattern[str]] = None


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

# Google
GOOGLE_API_KEY = RegexRule(
    id="google_api_key",
    type="Google API Key",
    pattern=re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    base_confidence=0.95,
)
GOOGLE_OAUTH = RegexRule(
    id="google_oauth_secret",
    type="Google OAuth Client Secret",
    pattern=re.compile(r"(?i)client_secret[\"']?\s*[:=]\s*[\"']?[a-zA-Z0-9_-]{24,}"),
    base_confidence=0.88,
)

# Azure
AZURE_STORAGE_KEY = RegexRule(
    id="azure_storage_key",
    type="Azure Storage Account Key",
    pattern=re.compile(r"AccountKey=[a-zA-Z0-9+/=]{88}"),
    base_confidence=0.95,
)
AZURE_CONNECTION_STRING = RegexRule(
    id="azure_connection_string",
    type="Azure Connection String",
    pattern=re.compile(r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey="),
    base_confidence=0.9,
)
AZURE_SUBSCRIPTION = RegexRule(
    id="azure_subscription_id",
    type="Azure Subscription ID",
    pattern=re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
    base_confidence=0.5,
)

# Slack
SLACK_BOT_TOKEN = RegexRule(
    id="slack_bot_token",
    type="Slack Bot Token",
    pattern=re.compile(r"xoxb-[0-9]{10,13}-[a-zA-Z0-9-]{24,}"),
    base_confidence=0.95,
)
SLACK_USER_TOKEN = RegexRule(
    id="slack_user_token",
    type="Slack User Token",
    pattern=re.compile(r"xoxp-[0-9]{10,13}-[a-zA-Z0-9-]{24,}"),
    base_confidence=0.95,
)
SLACK_WEBHOOK = RegexRule(
    id="slack_webhook",
    type="Slack Webhook URL",
    pattern=re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+"),
    base_confidence=0.95,
)

# Twilio
TWILIO_API_KEY = RegexRule(
    id="twilio_api_key",
    type="Twilio API Key (SK...)",
    pattern=re.compile(r"SK[0-9a-fA-F]{32}"),
    base_confidence=0.95,
)
TWILIO_ACCOUNT_SID = RegexRule(
    id="twilio_account_sid",
    type="Twilio Account SID",
    pattern=re.compile(r"AC[0-9a-fA-F]{32}"),
    base_confidence=0.9,
)

# SendGrid / Mailgun
SENDGRID_API_KEY = RegexRule(
    id="sendgrid_api_key",
    type="SendGrid API Key",
    pattern=re.compile(r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}"),
    base_confidence=0.95,
)
MAILGUN_API_KEY = RegexRule(
    id="mailgun_api_key",
    type="Mailgun API Key",
    pattern=re.compile(r"key-[0-9a-fA-F]{32}"),
    base_confidence=0.9,
)

# JWT
JWT_TOKEN = RegexRule(
    id="jwt",
    type="JWT Token",
    pattern=re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    base_confidence=0.92,
)

# Generic auth
BEARER_TOKEN = RegexRule(
    id="bearer_token",
    type="Bearer Token",
    pattern=re.compile(r"(?i)Bearer\s+[a-zA-Z0-9_.-]{20,}"),
    base_confidence=0.75,
)
BASIC_AUTH = RegexRule(
    id="basic_auth",
    type="Basic Auth Credentials",
    pattern=re.compile(r"(?i)Basic\s+[A-Za-z0-9+/=]{20,}"),
    base_confidence=0.8,
)

# Generic env / connection string
CONNECTION_STRING_PASSWORD = RegexRule(
    id="connection_string_password",
    type="Connection String with Password",
    pattern=re.compile(r"(?i)(password|pwd|passwd)=[^\s;]+"),
    base_confidence=0.85,
)
GENERIC_SECRET_ENV = RegexRule(
    id="generic_secret_env",
    type="Generic *_SECRET / *_KEY env",
    pattern=re.compile(r"(?i)\b[A-Z_]+(?:SECRET|KEY|TOKEN|PASSWORD)\s*=\s*[^#\s]+"),
    base_confidence=0.75,
)

# More providers
DROPBOX_ACCESS_TOKEN = RegexRule(
    id="dropbox_token",
    type="Dropbox Access Token",
    pattern=re.compile(r"sl\.[a-zA-Z0-9_-]{135}"),
    base_confidence=0.95,
)
HEROKU_API_KEY = RegexRule(
    id="heroku_api_key",
    type="Heroku API Key",
    pattern=re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
    base_confidence=0.4,
)
NPM_TOKEN = RegexRule(
    id="npm_token",
    type="NPM Token",
    pattern=re.compile(r"npm_[a-zA-Z0-9]{36}"),
    base_confidence=0.95,
)
DIGITALOCEAN_TOKEN = RegexRule(
    id="digitalocean_token",
    type="DigitalOcean Token",
    pattern=re.compile(r"dop_v1_[a-f0-9]{64}"),
    base_confidence=0.95,
)
TWITTER_BEARER = RegexRule(
    id="twitter_bearer",
    type="Twitter Bearer Token",
    pattern=re.compile(r"AAAAAAAAAAAAAAAAAAAAA[a-zA-Z0-9%]+"),
    base_confidence=0.85,
)
STRIPE_TEST_KEY = RegexRule(
    id="stripe_test_key",
    type="Stripe Test Key (sk_test_...)",
    pattern=re.compile(r"sk_test_[A-Za-z0-9]{24,}"),
    base_confidence=0.95,
)
GITHUB_APP_SECRET = RegexRule(
    id="github_app_secret",
    type="GitHub App Secret",
    pattern=re.compile(r"(?i)ghs_[a-zA-Z0-9]{36}"),
    base_confidence=0.95,
)
GITHUB_OAUTH = RegexRule(
    id="github_oauth",
    type="GitHub OAuth Secret",
    pattern=re.compile(r"(?i)gho_[a-zA-Z0-9]{36}"),
    base_confidence=0.95,
)
GENERIC_API_KEY_PATTERN = RegexRule(
    id="generic_api_key",
    type="Generic API Key Pattern",
    pattern=re.compile(r"(?i)api[_-]?key[\"']?\s*[:=]\s*[\"']?[a-zA-Z0-9_-]{20,}"),
    base_confidence=0.7,
)
PRIVATE_KEY_EC = RegexRule(
    id="private_key_ec",
    type="EC Private Key",
    pattern=re.compile(r"-----BEGIN EC PRIVATE KEY-----"),
    base_confidence=0.99,
)
OPENSSH_PRIVATE_KEY = RegexRule(
    id="openssh_private_key",
    type="OpenSSH Private Key",
    pattern=re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
    base_confidence=0.99,
)
REDIS_URL = RegexRule(
    id="redis_url",
    type="Redis URL",
    pattern=re.compile(r"redis(?:s)?://[^\s]+"),
    base_confidence=0.88,
)
AMQP_URL = RegexRule(
    id="amqp_url",
    type="AMQP URL",
    pattern=re.compile(r"amqps?://[^\s]+"),
    base_confidence=0.85,
)
FIREBASE_KEY = RegexRule(
    id="firebase_key",
    type="Firebase/Google Cloud Key",
    pattern=re.compile(r"(?i)(?:firebase|gcp)[\"']?\s*[:=].*[\"']?AIza[0-9A-Za-z_-]{35}"),
    base_confidence=0.9,
)
DATADOG_API_KEY = RegexRule(
    id="datadog_api_key",
    type="Datadog API Key",
    pattern=re.compile(r"[a-f0-9]{32}"),
    base_confidence=0.35,
)
NEW_RELIC_LICENSE = RegexRule(
    id="new_relic_license",
    type="New Relic License Key",
    pattern=re.compile(r"[0-9a-f]{40}"),
    base_confidence=0.4,
)
SQUARE_ACCESS_TOKEN = RegexRule(
    id="square_token",
    type="Square Access Token",
    pattern=re.compile(r"sq0atp-[a-zA-Z0-9_-]{22,}"),
    base_confidence=0.95,
)
PAYPAL_CLIENT = RegexRule(
    id="paypal_client",
    type="PayPal Client Secret",
    pattern=re.compile(r"([A-Z]{2}[0-9]{2})?[A-Za-z0-9]{80,}"),
    base_confidence=0.35,
)
DISCORD_TOKEN = RegexRule(
    id="discord_token",
    type="Discord Token",
    pattern=re.compile(r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,38}"),
    base_confidence=0.92,
)
TELEGRAM_BOT = RegexRule(
    id="telegram_bot",
    type="Telegram Bot Token",
    pattern=re.compile(r"\d{8,10}:[a-zA-Z0-9_-]{35}"),
    base_confidence=0.95,
)
SPARKPOST_API = RegexRule(
    id="sparkpost_api",
    type="SparkPost API Key",
    pattern=re.compile(r"[a-f0-9]{40}"),
    base_confidence=0.35,
)
CODECOV_TOKEN = RegexRule(
    id="codecov_token",
    type="Codecov Token",
    pattern=re.compile(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"),
    base_confidence=0.4,
)
VERCEL_TOKEN = RegexRule(
    id="vercel_token",
    type="Vercel Token",
    pattern=re.compile(r"[A-Za-z0-9]{24}"),
    base_confidence=0.35,
)
SUPABASE_ANON = RegexRule(
    id="supabase_anon",
    type="Supabase Anon Key",
    pattern=re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.([A-Za-z0-9_-]+)"),
    base_confidence=0.5,
)
PAGERDUTY_KEY = RegexRule(
    id="pagerduty_key",
    type="PagerDuty API Key",
    pattern=re.compile(r"[a-f0-9]{32}"),
    base_confidence=0.35,
)
LINEAR_API = RegexRule(
    id="linear_api",
    type="Linear API Key",
    pattern=re.compile(r"lin_api_[a-zA-Z0-9]{40}"),
    base_confidence=0.95,
)

# GCP service account JSON — structural marker unique to GCP SA files
GCP_SERVICE_ACCOUNT = RegexRule(
    id="gcp_service_account",
    type="GCP Service Account Key",
    pattern=re.compile(r'"type"\s*:\s*"service_account"'),
    base_confidence=0.97,
)

# AWS STS session tokens — much longer than regular access keys (100+ chars)
AWS_STS_TOKEN = RegexRule(
    id="aws_sts_token",
    type="AWS STS Session Token",
    pattern=re.compile(r"(?i)(session_token|aws_session_token)\s*[=:]\s*[A-Za-z0-9/+=]{100,}"),
    base_confidence=0.93,
)

# Kubernetes Secret YAML — only fires on .yaml/.yml files
K8S_SECRET_YAML = RegexRule(
    id="k8s_secret_yaml",
    type="Kubernetes Secret (YAML)",
    pattern=re.compile(r"(?i)^kind:\s*Secret\s*$"),
    base_confidence=0.75,
    filename_filter=re.compile(r"\.ya?ml$"),
)


ALL_RULES: List[RegexRule] = [
    AWS_ACCESS_KEY,
    AWS_SECRET_KEY,
    AWS_STS_TOKEN,
    GITHUB_PAT,
    GITHUB_APP_SECRET,
    GITHUB_OAUTH,
    STRIPE_SECRET,
    STRIPE_TEST_KEY,
    PRIVATE_KEY,
    PRIVATE_KEY_EC,
    OPENSSH_PRIVATE_KEY,
    DATABASE_URL,
    ENV_ASSIGNMENT,
    GENERIC_HIGH_ENTROPY,
    GOOGLE_API_KEY,
    GOOGLE_OAUTH,
    AZURE_STORAGE_KEY,
    AZURE_CONNECTION_STRING,
    SLACK_BOT_TOKEN,
    SLACK_USER_TOKEN,
    SLACK_WEBHOOK,
    TWILIO_API_KEY,
    TWILIO_ACCOUNT_SID,
    SENDGRID_API_KEY,
    MAILGUN_API_KEY,
    JWT_TOKEN,
    BEARER_TOKEN,
    BASIC_AUTH,
    CONNECTION_STRING_PASSWORD,
    GENERIC_SECRET_ENV,
    DROPBOX_ACCESS_TOKEN,
    NPM_TOKEN,
    DIGITALOCEAN_TOKEN,
    TWITTER_BEARER,
    GENERIC_API_KEY_PATTERN,
    REDIS_URL,
    AMQP_URL,
    FIREBASE_KEY,
    SQUARE_ACCESS_TOKEN,
    DISCORD_TOKEN,
    TELEGRAM_BOT,
    SUPABASE_ANON,
    LINEAR_API,
    GCP_SERVICE_ACCOUNT,
    K8S_SECRET_YAML,
]


def iter_rule_matches(rule: RegexRule, line: str, filename: str = "") -> Iterable[str]:
    if rule.filename_filter is not None and not rule.filename_filter.search(filename):
        return
    for match in rule.pattern.findall(line):
        # For patterns with groups, findall returns a tuple or first group;
        # normalize by casting to str.
        yield str(match)


def filter_high_entropy(
    tokens: Iterable[str], min_entropy: float, min_length: int
) -> Iterable[str]:
    for token in tokens:
        if len(token) < min_length:
            continue
        if shannon_entropy(token) >= min_entropy:
            yield token

