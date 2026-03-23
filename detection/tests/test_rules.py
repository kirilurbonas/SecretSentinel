"""
Parametrized tests: one positive and one negative sample per rule in ALL_RULES.
"""
from __future__ import annotations

import pytest
from app.detectors.regex_rules import ALL_RULES, iter_rule_matches

# (rule_id, positive_sample, negative_sample, filename)
CASES: list[tuple[str, str, str, str]] = [
    ("aws_access_key", "AKIAIOSFODNN7EXAMPLE123456", "not-an-aws-key", "config.py"),
    ("aws_secret_key", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "tooshort", "config.py"),
    ("aws_sts_token", "session_token=FwoGZXIvYXdzEMf" + "A" * 100, "session_token=short", "creds.py"),
    ("github_pat", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", "ghp_short", "env.py"),
    ("github_app_secret", "ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789AB", "ghs_x", "env.py"),
    ("github_oauth", "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789AB", "gho_x", "env.py"),
    ("stripe_secret", "sk_live_" + "x" * 24, "sk_live_short", "pay.py"),
    ("stripe_test_key", "sk_test_" + "x" * 24, "sk_test_short", "pay.py"),
    ("private_key", "-----BEGIN RSA PRIVATE KEY-----", "BEGIN PUBLIC KEY", "key.pem"),
    ("private_key_ec", "-----BEGIN EC PRIVATE KEY-----", "BEGIN PUBLIC KEY", "key.pem"),
    ("openssh_private_key", "-----BEGIN OPENSSH PRIVATE KEY-----", "BEGIN PUBLIC KEY", "id_rsa"),
    ("database_url", "postgres://user:pass@localhost/db", "not-a-url", "config.py"),
    ("env_assignment", "PASSWORD=super_secret_value", "# just a comment", "env.py"),
    ("google_api_key", "AIza" + "A" * 35, "not-a-google-key", "api.py"),
    ("azure_storage_key", "AccountKey=" + "A" * 88, "AccountKey=short", "storage.py"),
    ("azure_connection_string", "DefaultEndpointsProtocol=https;AccountName=myacct;AccountKey=x", "not-azure", "conn.py"),
    ("slack_bot_token", "xoxb-" + "0" * 12 + "-" + "x" * 24, "xoxb-short", "slack.py"),
    ("slack_user_token", "xoxp-" + "0" * 12 + "-" + "x" * 24, "xoxp-short", "slack.py"),
    ("slack_webhook", "https://hooks.slack.com/services/T12345678/B12345678/abc123xyz", "https://example.com", "hook.py"),
    ("twilio_api_key", "SK" + "0123456789abcdef" * 2, "SK_short", "twilio.py"),
    ("twilio_account_sid", "AC" + "0123456789abcdef" * 2, "AC_short", "twilio.py"),
    ("sendgrid_api_key", "SG." + "A" * 22 + "." + "B" * 43, "SG.short", "sg.py"),
    ("mailgun_api_key", "key-" + "0123456789abcdef" * 2, "key-short", "mg.py"),
    ("jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "not.a.jwt", "auth.py"),
    ("bearer_token", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9extra", "Bearer x", "req.py"),
    ("basic_auth", "Basic dXNlcjpwYXNzd29yZA==", "Basic short", "req.py"),
    ("connection_string_password", "password=sup3r_s3cr3t", "password=", "db.py"),
    ("generic_secret_env", "MY_API_KEY=abcdefghijklmnopqrstuvwxyz", "# comment", "env.py"),
    ("dropbox_token", "sl." + "A" * 135, "sl.short", "dropbox.py"),
    ("npm_token", "npm_" + "A" * 36, "npm_short", "pkg.py"),
    ("digitalocean_token", "dop_v1_" + "a" * 64, "dop_v1_short", "do.py"),
    ("twitter_bearer", "AAAAAAAAAAAAAAAAAAAAA%2FextraCharsHere", "AAAA", "tw.py"),
    ("generic_api_key", 'api_key: "abcdefghijklmnopqrstuvwxyz"', "api_key: x", "conf.py"),
    ("redis_url", "redis://user:pass@localhost:6379/0", "not-redis", "cache.py"),
    ("amqp_url", "amqp://guest:guest@localhost:5672/", "not-amqp", "mq.py"),
    ("firebase_key", 'firebase: "AIza' + 'A' * 35 + '"', "firebase: none", "fb.py"),
    ("square_token", "sq0atp-ABCDEFGHIJKLMNOPQRSTUVWXYZ", "sq0atp-short", "sq.py"),
    ("discord_token", "M" + "A" * 23 + "." + "B" * 6 + "." + "C" * 27, "discord", "ds.py"),
    ("telegram_bot", "123456789:" + "A" * 35, "notbot", "tg.py"),
    ("supabase_anon", "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "not.supabase", "sb.py"),
    ("linear_api", "lin_api_" + "A" * 40, "lin_api_short", "linear.py"),
    ("gcp_service_account", '"type": "service_account"', '"type": "user"', "sa.json"),
    ("k8s_secret_yaml", "kind: Secret", "kind: Deployment", "manifest.yaml"),
]

RULE_MAP = {rule.id: rule for rule in ALL_RULES}


@pytest.mark.parametrize("rule_id,positive,negative,filename", CASES)
def test_rule_positive(rule_id: str, positive: str, negative: str, filename: str) -> None:
    rule = RULE_MAP.get(rule_id)
    if rule is None:
        pytest.skip(f"Rule {rule_id!r} not in ALL_RULES (may have been retired)")
    matches = list(iter_rule_matches(rule, positive, filename))
    assert len(matches) > 0, f"Rule {rule_id!r} did not match positive sample: {positive!r}"


@pytest.mark.parametrize("rule_id,positive,negative,filename", CASES)
def test_rule_negative(rule_id: str, positive: str, negative: str, filename: str) -> None:
    rule = RULE_MAP.get(rule_id)
    if rule is None:
        pytest.skip(f"Rule {rule_id!r} not in ALL_RULES (may have been retired)")
    matches = list(iter_rule_matches(rule, negative, filename))
    assert len(matches) == 0, f"Rule {rule_id!r} matched negative sample: {negative!r} → {matches}"
