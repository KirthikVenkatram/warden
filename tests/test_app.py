from unittest.mock import MagicMock

from core import store
from core.models import Action, Decision, Finding, Severity
from slack_app import agent
from slack_app.app import handle_thread_question, is_warden_digest, parse_repo_from_digest, parse_scan_command


def test_parses_bare_repo():
    assert parse_scan_command("scan owner/repo") == {
        "repo": "owner/repo",
        "source": "fixture:kev_blocking",
        "tests_green": False,
    }


def test_parses_source_flag():
    assert parse_scan_command("scan owner/repo --source fixture:high_epss") == {
        "repo": "owner/repo",
        "source": "fixture:high_epss",
        "tests_green": False,
    }


def test_parses_tests_green_flag():
    assert parse_scan_command("scan owner/repo --tests-green") == {
        "repo": "owner/repo",
        "source": "fixture:kev_blocking",
        "tests_green": True,
    }


def test_parses_source_and_tests_green_together():
    assert parse_scan_command("scan owner/repo --source fixture:high_epss --tests-green") == {
        "repo": "owner/repo",
        "source": "fixture:high_epss",
        "tests_green": True,
    }


def test_malformed_input_returns_none():
    assert parse_scan_command("") is None
    assert parse_scan_command("owner/repo") is None
    assert parse_scan_command("scan") is None
    assert parse_scan_command("scan owner/repo --bogus") is None
    assert parse_scan_command("scan owner/repo --source") is None


def test_get_render_rows_against_seeded_store(tmp_path, monkeypatch):
    monkeypatch.setenv("WARDEN_DB", str(tmp_path / "warden.db"))

    finding = Finding(
        cve="CVE-2024-3094",
        package="xz-utils",
        installed_version="5.6.0",
        fixed_version="5.6.2",
        severity=Severity.CRITICAL,
        cvss=10.0,
        epss=0.94,
        kev=True,
        scanner="trivy",
        repo="acme/orders-api",
    )
    decision = Decision(
        cve="CVE-2024-3094",
        package="xz-utils",
        action=Action.BLOCK,
        reasons=["on CISA KEV — known exploited in the wild"],
        auto_fixable=True,
    )
    store.upsert_decisions("acme/orders-api", [decision], [finding])

    rows = store.get_render_rows("acme/orders-api")

    assert len(rows) == 1
    row = rows[0]
    assert row["cve"] == "CVE-2024-3094"
    assert row["action"] == "block"
    assert row["severity"] == "critical"
    assert row["kev"] is True

    assert store.get_render_rows("acme/orders-api", action="auto") == []


def _digest_parent(repo: str) -> dict:
    """Matches blockkit.build_digest's real header: f":shield: Warden — {summary.repo}"."""
    return {
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": f":shield: Warden — {repo}"}},
        ]
    }


def test_parse_repo_from_digest_extracts_repo():
    assert parse_repo_from_digest(_digest_parent("acme/orders-api")) == "acme/orders-api"


def test_parse_repo_from_digest_extracts_repo_with_slashes_and_dashes():
    assert parse_repo_from_digest(_digest_parent("KirthikVenkatram/warden-demo-target")) == (
        "KirthikVenkatram/warden-demo-target"
    )


def test_parse_repo_from_digest_never_returns_the_fixed_warden_prefix():
    # Regression: the old implementation split on " — " and took index [0], which is
    # always the literal "Warden" prefix, never the actual repo — every thread question
    # silently queried the wrong (constant) "repo" string.
    repo = parse_repo_from_digest(_digest_parent("some-org/some-repo"))
    assert repo == "some-org/some-repo"
    assert repo != ":shield: Warden"
    assert "Warden" not in repo


def test_parse_repo_from_digest_rejects_non_digest_message():
    assert parse_repo_from_digest(None) is None
    assert parse_repo_from_digest({"blocks": []}) is None
    assert parse_repo_from_digest({"text": "just a regular reply"}) is None
    assert parse_repo_from_digest(
        {"blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": "hi"}}]}
    ) is None


def test_handle_thread_question_scopes_tool_dispatch_to_parsed_repo(monkeypatch):
    """Regression for the repo-resolution bug: the thread question must be answered
    against the exact repo parsed from the parent digest header, never a hardcoded
    default and never the fixed "Warden" prefix."""
    monkeypatch.setattr(store, "get_render_rows", lambda repo: [])
    build_tool_dispatch_mock = MagicMock(return_value={})
    monkeypatch.setattr(agent, "build_tool_dispatch", build_tool_dispatch_mock)
    monkeypatch.setattr(agent, "answer_question", lambda *a, **k: "answer")

    client = MagicMock()
    client.conversations_replies.return_value = {"messages": [_digest_parent("X/Y")]}

    event = {
        "channel": "C123",
        "thread_ts": "1000.0001",
        "ts": "1001.0002",
        "text": "why is this blocking",
    }

    handle_thread_question(event, client)

    build_tool_dispatch_mock.assert_called_once_with("X/Y")
    client.chat_postMessage.assert_called_once_with(channel="C123", thread_ts="1000.0001", text="answer")


def test_handle_thread_question_refuses_to_guess_when_repo_unparseable(monkeypatch):
    build_tool_dispatch_mock = MagicMock()
    monkeypatch.setattr(agent, "build_tool_dispatch", build_tool_dispatch_mock)

    client = MagicMock()
    malformed_parent = {"blocks": [{"type": "header", "text": {"type": "plain_text", "text": "no separator here"}}]}
    client.conversations_replies.return_value = {"messages": [malformed_parent]}

    event = {
        "channel": "C123",
        "thread_ts": "1000.0001",
        "ts": "1001.0002",
        "text": "why is this blocking",
    }

    handle_thread_question(event, client)

    build_tool_dispatch_mock.assert_not_called()
    client.chat_postMessage.assert_called_once_with(
        channel="C123", thread_ts="1000.0001", text="I can't tell which repo this thread is about."
    )


def test_is_warden_digest():
    assert is_warden_digest(_digest_parent("acme/orders-api")) is True
    assert is_warden_digest(None) is False
    assert is_warden_digest({"blocks": []}) is False
    assert is_warden_digest(
        {"blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": "hi"}}]}
    ) is False
