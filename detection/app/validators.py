"""
Secret liveness validators.

Each function attempts to verify whether a secret value is still active
with its upstream provider. Returns (live: bool | None, error: str | None).
- True  → secret is confirmed live
- False → secret is confirmed revoked / invalid
- None  → could not determine (unknown provider, network error, etc.)
"""
from __future__ import annotations

import urllib.error
import urllib.request
from typing import Tuple

LiveResult = Tuple["bool | None", "str | None"]


def _check_aws(value: str) -> LiveResult:
    """
    Validate an AWS credential by calling STS GetCallerIdentity.
    Expects value to be an access key ID (AKIA...) OR a JSON blob containing it.
    """
    try:
        import boto3  # type: ignore[import-untyped]
        import botocore.exceptions  # type: ignore[import-untyped]

        # If value looks like an access key ID, we can't derive the secret key here.
        # The validator is most useful when called with the full credential JSON.
        import json

        try:
            creds = json.loads(value)
            access_key = creds.get("accessKeyId") or creds.get("AccessKeyId")
            secret_key = creds.get("secretAccessKey") or creds.get("SecretAccessKey")
        except (json.JSONDecodeError, AttributeError):
            # Plain access key ID — we can't call STS without the secret key.
            return None, "provide full JSON credential to validate AWS keys"

        if not access_key or not secret_key:
            return None, "accessKeyId and secretAccessKey required"

        sts = boto3.client(
            "sts",
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
        )
        sts.get_caller_identity()
        return True, None
    except ImportError:
        return None, "boto3 not installed"
    except Exception as e:  # noqa: BLE001
        msg = str(e)
        if "InvalidClientTokenId" in msg or "SignatureDoesNotMatch" in msg:
            return False, None
        return None, msg


def _check_github(value: str) -> LiveResult:
    """Validate a GitHub PAT by calling GET /user."""
    try:
        req = urllib.request.Request(
            "https://api.github.com/user",
            headers={"Authorization": f"token {value}", "User-Agent": "SecretSentinel/1.0"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status == 200:
                return True, None
        return False, None
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return False, None
        return None, f"HTTP {e.code}"
    except Exception as e:  # noqa: BLE001
        return None, str(e)


_VALIDATORS = {
    "aws_access_key": _check_aws,
    "aws_secret_key": _check_aws,
    "aws_sts_token": _check_aws,
    "github_pat": _check_github,
    "github_app_secret": _check_github,
    "github_oauth": _check_github,
}


def validate(secret_type: str, value: str) -> LiveResult:
    """Dispatch to the appropriate validator, or return (None, 'unknown provider')."""
    fn = _VALIDATORS.get(secret_type)
    if fn is None:
        return None, "unknown provider"
    return fn(value)
