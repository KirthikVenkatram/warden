import base64
import json

import httpx
import pytest

from core import github_pr


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def _make_client(requirements_text: str, calls: list, existing_pr: dict | None = None) -> httpx.Client:
    repo = "acme/orders-api"
    branch = "warden/fix-cve-2023-38545"

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        path = request.url.path
        method = request.method

        if path == f"/repos/{repo}" and method == "GET":
            return httpx.Response(200, json={"default_branch": "main"})

        if path == f"/repos/{repo}/git/ref/heads/main" and method == "GET":
            return httpx.Response(200, json={"object": {"sha": "headsha123"}})

        if path == f"/repos/{repo}/git/ref/heads/{branch}" and method == "GET":
            return httpx.Response(404, json={"message": "Not Found"})

        if path == f"/repos/{repo}/git/refs" and method == "POST":
            return httpx.Response(201, json={"ref": f"refs/heads/{branch}"})

        if path == f"/repos/{repo}/contents/requirements.txt" and method == "GET":
            return httpx.Response(200, json={"content": _b64(requirements_text), "sha": "filesha456"})

        if path == f"/repos/{repo}/contents/requirements.txt" and method == "PUT":
            return httpx.Response(200, json={"commit": {"sha": "newcommitsha"}})

        if path == f"/repos/{repo}/pulls" and method == "GET":
            return httpx.Response(200, json=[] if existing_pr is None else [existing_pr])

        if path == f"/repos/{repo}/pulls" and method == "POST":
            return httpx.Response(201, json={"html_url": "https://github.com/acme/orders-api/pull/42", "number": 42})

        raise AssertionError(f"unexpected request: {method} {path}")

    return httpx.Client(base_url=github_pr.GITHUB_API_URL, transport=httpx.MockTransport(handler))


@pytest.fixture(autouse=True)
def github_token(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "fake-token")


@pytest.fixture(autouse=True)
def isolate_db(tmp_path, monkeypatch):
    monkeypatch.setenv("WARDEN_DB", str(tmp_path / "warden.db"))


def test_open_fix_pr_rewrites_version_line_in_committed_payload():
    calls: list[httpx.Request] = []
    client = _make_client("requests==2.31.0\ncurl==8.3.0\nflask==2.0.1\n", calls)

    result = github_pr.open_fix_pr(
        "acme/orders-api", "CVE-2023-38545", "curl", "8.3.0", "8.4.0", client=client
    )

    assert result.status == "opened"
    assert result.url == "https://github.com/acme/orders-api/pull/42"
    assert result.number == 42

    put_call = next(c for c in calls if c.method == "PUT")
    payload = json.loads(put_call.content)
    committed = base64.b64decode(payload["content"]).decode()

    assert "curl==8.4.0" in committed
    assert "requests==2.31.0" in committed
    assert "flask==2.0.1" in committed
    assert "curl==8.3.0" not in committed


def test_open_fix_pr_missing_pin_is_skipped():
    calls: list[httpx.Request] = []
    client = _make_client("requests==2.31.0\n", calls)

    result = github_pr.open_fix_pr(
        "acme/orders-api", "CVE-2023-38545", "curl", "8.3.0", "8.4.0", client=client
    )

    assert result.status == "skipped"
    assert "curl" in result.reason
    assert not any(c.method == "PUT" for c in calls)
    assert not any(c.method == "POST" and c.url.path.endswith("/pulls") for c in calls)


def test_open_fix_pr_reuses_existing_open_pr():
    calls: list[httpx.Request] = []
    existing = {"html_url": "https://github.com/acme/orders-api/pull/7", "number": 7}
    client = _make_client("curl==8.3.0\n", calls, existing_pr=existing)

    result = github_pr.open_fix_pr(
        "acme/orders-api", "CVE-2023-38545", "curl", "8.3.0", "8.4.0", client=client
    )

    assert result.status == "reused"
    assert result.url == "https://github.com/acme/orders-api/pull/7"
    assert result.number == 7
    assert not any(c.method == "POST" and c.url.path.endswith("/pulls") for c in calls)


def test_open_fix_pr_missing_token_is_skipped(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    result = github_pr.open_fix_pr("acme/orders-api", "CVE-2023-38545", "curl", "8.3.0", "8.4.0")

    assert result.status == "skipped"
    assert "GITHUB_TOKEN" in result.reason
