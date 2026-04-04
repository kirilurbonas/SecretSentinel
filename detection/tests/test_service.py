from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_scan_detects_aws_access_key() -> None:
    aws_key = "AKIA" + "1234567890ABCDEF"
    payload = {
        "content": aws_key,
        "filename": "config.go",
    }
    resp = client.post("/scan", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    findings = body["findings"]
    assert any("AWS Access Key" in f["type"] for f in findings)


def test_scan_batch_multiple_files() -> None:
    gh_token = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789AB"
    payload = {
        "files": [
            {"content": "no secrets here", "filename": "a.txt"},
            {"content": "token=" + gh_token, "filename": "b.txt"},
        ]
    }
    resp = client.post("/scan/batch", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    files = body["files"]
    assert len(files) == 2
    assert files[0]["filename"] == "a.txt"
    assert files[1]["filename"] == "b.txt"
    assert files[0]["findings"] == []
    assert any("GitHub Personal Access Token" in f["type"] for f in files[1]["findings"])

