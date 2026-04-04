"""Tests for secret liveness validators."""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from app.validators import _check_aws, _check_github, validate


class TestCheckGithub:
    def test_returns_true_for_valid_token(self) -> None:
        mock_response = MagicMock()
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_response.status = 200

        with patch("app.validators.urllib.request.urlopen", return_value=mock_response):
            live, error = _check_github("ghp_validtoken123")

        assert live is True
        assert error is None

    def test_returns_false_for_401(self) -> None:
        import urllib.error

        with patch(
            "app.validators.urllib.request.urlopen",
            side_effect=urllib.error.HTTPError(
                url="https://api.github.com/user",
                code=401,
                msg="Unauthorized",
                hdrs=None,  # type: ignore[arg-type]
                fp=None,
            ),
        ):
            live, error = _check_github("ghp_revoked")

        assert live is False
        assert error is None

    def test_returns_none_for_other_http_error(self) -> None:
        import urllib.error

        with patch(
            "app.validators.urllib.request.urlopen",
            side_effect=urllib.error.HTTPError(
                url="https://api.github.com/user",
                code=500,
                msg="Server Error",
                hdrs=None,  # type: ignore[arg-type]
                fp=None,
            ),
        ):
            live, error = _check_github("ghp_token")

        assert live is None
        assert error is not None
        assert "500" in error

    def test_returns_none_on_network_error(self) -> None:
        with patch(
            "app.validators.urllib.request.urlopen",
            side_effect=ConnectionError("network unreachable"),
        ):
            live, error = _check_github("ghp_token")

        assert live is None
        assert error is not None


class TestCheckAws:
    def test_returns_none_when_boto3_not_installed(self) -> None:
        with patch.dict("sys.modules", {"boto3": None}):
            live, error = _check_aws("AKIAIOSFODNN7EXAMPLE")

        assert live is None
        assert error is not None

    def test_returns_none_for_plain_access_key(self) -> None:
        mock_boto3 = MagicMock()
        with patch.dict("sys.modules", {"boto3": mock_boto3, "botocore.exceptions": MagicMock()}):
            live, error = _check_aws("AKIAIOSFODNN7EXAMPLE")

        assert live is None
        assert "provide full JSON" in (error or "")

    def test_returns_true_for_valid_json_credentials(self) -> None:
        mock_boto3 = MagicMock()
        mock_sts = MagicMock()
        mock_boto3.client.return_value = mock_sts
        mock_sts.get_caller_identity.return_value = {"Account": "123456789"}
        mock_botocore = MagicMock()

        creds = json.dumps(
            {
                "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "secretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            }
        )
        with patch.dict("sys.modules", {"boto3": mock_boto3, "botocore.exceptions": mock_botocore}):
            live, error = _check_aws(creds)

        assert live is True
        assert error is None

    def test_returns_false_for_invalid_credentials(self) -> None:
        mock_boto3 = MagicMock()
        mock_sts = MagicMock()
        mock_boto3.client.return_value = mock_sts
        mock_sts.get_caller_identity.side_effect = Exception("InvalidClientTokenId: ...")
        mock_botocore = MagicMock()

        creds = json.dumps(
            {
                "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "secretAccessKey": "invalidsecretkey",
            }
        )
        with patch.dict("sys.modules", {"boto3": mock_boto3, "botocore.exceptions": mock_botocore}):
            live, error = _check_aws(creds)

        assert live is False
        assert error is None

    def test_returns_none_for_missing_fields_in_json(self) -> None:
        mock_boto3 = MagicMock()
        mock_botocore = MagicMock()
        creds = json.dumps({"accessKeyId": "AKIA..."})  # missing secretAccessKey
        with patch.dict("sys.modules", {"boto3": mock_boto3, "botocore.exceptions": mock_botocore}):
            live, error = _check_aws(creds)

        assert live is None
        assert error is not None


class TestValidateDispatch:
    def test_dispatches_to_github_for_github_pat(self) -> None:
        mock_fn = MagicMock(return_value=(True, None))
        with patch("app.validators._VALIDATORS", {"github_pat": mock_fn}):
            live, error = validate("github_pat", "ghp_xxx")
        mock_fn.assert_called_once_with("ghp_xxx")
        assert live is True

    def test_dispatches_to_aws_for_aws_access_key(self) -> None:
        mock_fn = MagicMock(return_value=(False, None))
        with patch("app.validators._VALIDATORS", {"aws_access_key": mock_fn}):
            live, error = validate("aws_access_key", "AKIA...")
        mock_fn.assert_called_once_with("AKIA...")
        assert live is False

    def test_dispatches_to_aws_for_aws_secret_key(self) -> None:
        mock_fn = MagicMock(return_value=(None, "error"))
        with patch("app.validators._VALIDATORS", {"aws_secret_key": mock_fn}):
            live, error = validate("aws_secret_key", "secret")
        mock_fn.assert_called_once_with("secret")

    def test_dispatches_to_github_for_github_app_secret(self) -> None:
        mock_fn = MagicMock(return_value=(True, None))
        with patch("app.validators._VALIDATORS", {"github_app_secret": mock_fn}):
            validate("github_app_secret", "token")
        mock_fn.assert_called_once_with("token")

    def test_returns_none_unknown_provider_for_unrecognised_type(self) -> None:
        live, error = validate("unknown_type", "somevalue")
        assert live is None
        assert error == "unknown provider"

    def test_returns_none_for_stripe_secret_no_validator(self) -> None:
        live, error = validate("stripe_secret", "sk_live_xxx")
        assert live is None
        assert error == "unknown provider"
