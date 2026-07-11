import json
from types import SimpleNamespace

import httpx
import pytest

from core import store
from core.models import Action, Decision, Finding, Severity
from slack_app import agent


def _tool_call(id_, name, args):
    return SimpleNamespace(id=id_, function=SimpleNamespace(name=name, arguments=json.dumps(args)))


def _message(tool_calls=None, content=None):
    return SimpleNamespace(tool_calls=tool_calls, content=content)


def _response(message):
    return SimpleNamespace(choices=[SimpleNamespace(message=message)])


class FakeCompletions:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        response = self._responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class FakeChat:
    def __init__(self, responses):
        self.completions = FakeCompletions(responses)


class FakeClient:
    def __init__(self, responses):
        self.chat = FakeChat(responses)


@pytest.fixture(autouse=True)
def api_key(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test-key")


def _status_error(status_code):
    resp = httpx.Response(status_code, request=httpx.Request("POST", "http://x"))
    return agent.groq.APIStatusError("boom", response=resp, body=None)


def test_answer_question_dispatches_tool_and_returns_final_text(monkeypatch):
    tool_call_response = _response(
        _message(tool_calls=[_tool_call("call_1", "explain_finding", {"cve": "CVE-2026-42208"})])
    )
    final_response = _response(_message(content="It's blocking because it's on CISA KEV."))
    fake_client = FakeClient([tool_call_response, final_response])
    monkeypatch.setattr(agent, "Groq", lambda **kwargs: fake_client)

    calls = []

    def fake_explain(cve):
        calls.append(cve)
        return "on CISA KEV — known exploited in the wild"

    tool_dispatch = {"explain_finding": fake_explain}

    answer = agent.answer_question(
        "why is this blocking?", "Repo: org/repo", agent.build_tools(), tool_dispatch
    )

    assert calls == ["CVE-2026-42208"]
    assert answer == "It's blocking because it's on CISA KEV."
    assert len(fake_client.chat.completions.calls) == 2


def test_draft_fix_pr_not_exposed_to_chat_loop():
    tool_names = [t["function"]["name"] for t in agent.build_tools()]
    assert "draft_fix_pr" not in tool_names
    assert "draft_fix_pr" not in agent.build_tool_dispatch("org/repo")


def test_tools_never_expose_a_repo_parameter():
    """The model must be unable to pass a repo — it's bound server-side per thread."""
    for tool in agent.build_tools():
        assert "repo" not in tool["function"]["parameters"]["properties"]


def test_tool_dispatch_binds_repo_and_ignores_any_llm_supplied_repo(monkeypatch):
    seen = []
    monkeypatch.setattr(
        agent.pipeline, "get_decisions", lambda repo, action=None: seen.append((repo, action)) or []
    )

    dispatch = agent.build_tool_dispatch("acme/orders-api")
    dispatch["get_findings"]()

    assert seen == [("acme/orders-api", None)]


def test_iteration_cap_terminates_runaway_tool_use(monkeypatch):
    tool_call_response = _response(
        _message(tool_calls=[_tool_call("call_1", "get_findings", {})])
    )
    fake_client = FakeClient([tool_call_response] * agent._MAX_ITERATIONS)
    monkeypatch.setattr(agent, "Groq", lambda **kwargs: fake_client)

    tool_dispatch = {"get_findings": lambda action=None: []}

    answer = agent.answer_question("why?", "Repo: org/repo", agent.build_tools(), tool_dispatch)

    assert len(fake_client.chat.completions.calls) == agent._MAX_ITERATIONS
    assert "tool-call budget" in answer


def test_retries_on_server_error_then_succeeds(monkeypatch):
    final_response = _response(_message(content="all clear."))
    fake_client = FakeClient([_status_error(503), _status_error(503), final_response])
    monkeypatch.setattr(agent, "Groq", lambda **kwargs: fake_client)
    monkeypatch.setattr(agent.time, "sleep", lambda seconds: None)

    answer = agent.answer_question("why?", "Repo: org/repo", agent.build_tools(), {})

    assert answer == "all clear."
    assert len(fake_client.chat.completions.calls) == 3


def test_missing_api_key_returns_short_message(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)

    answer = agent.answer_question("why?", "Repo: org/repo", agent.build_tools(), {})

    assert "not configured" in answer


def test_build_context_lists_findings_already_in_thread():
    rows = [
        {"cve": "CVE-2024-3094", "package": "xz-utils", "action": "block", "reasons": ["on CISA KEV"]},
    ]
    context = agent.build_context("acme/orders-api", rows)

    assert "Repo: acme/orders-api" in context
    assert "CVE-2024-3094" in context
    assert "block" in context


def test_build_context_empty_rows_names_repo_without_asserting_activity():
    context = agent.build_context("acme/orders-api", [])

    assert "Repo: acme/orders-api" in context
    assert "No findings are currently stored" in context


def test_grounded_answer_pulls_real_block_finding_from_resolved_repo(monkeypatch, tmp_path):
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

    tool_call_response = _response(_message(tool_calls=[_tool_call("call_1", "get_findings", {})]))
    final_response = _response(
        _message(content="CVE-2024-3094 is blocked — it's on CISA KEV, known exploited in the wild.")
    )
    fake_client = FakeClient([tool_call_response, final_response])
    monkeypatch.setattr(agent, "Groq", lambda **kwargs: fake_client)

    tool_dispatch = agent.build_tool_dispatch("acme/orders-api")
    context = agent.build_context("acme/orders-api", store.get_render_rows("acme/orders-api"))

    answer = agent.answer_question("why is this blocked?", context, agent.build_tools(), tool_dispatch)

    # the tool actually reached the real store for the resolved repo, not a guessed one
    sent_messages = fake_client.chat.completions.calls[1]["messages"]
    tool_msg = next(m for m in sent_messages if isinstance(m, dict) and m.get("role") == "tool")
    payload = json.loads(tool_msg["content"])
    assert payload[0]["cve"] == "CVE-2024-3094"
    assert payload[0]["action"] == "block"
    assert "CISA KEV" in answer


def test_empty_findings_reply_names_repo_and_does_not_claim_nothing_blocked(monkeypatch, tmp_path):
    monkeypatch.setenv("WARDEN_DB", str(tmp_path / "warden.db"))
    # no findings ever stored for this repo

    tool_call_response = _response(_message(tool_calls=[_tool_call("call_1", "get_findings", {})]))
    final_response = _response(
        _message(content="I couldn't retrieve any findings for acme/orders-api right now.")
    )
    fake_client = FakeClient([tool_call_response, final_response])
    monkeypatch.setattr(agent, "Groq", lambda **kwargs: fake_client)

    tool_dispatch = agent.build_tool_dispatch("acme/orders-api")
    context = agent.build_context("acme/orders-api", store.get_render_rows("acme/orders-api"))

    answer = agent.answer_question("what's blocked?", context, agent.build_tools(), tool_dispatch)

    sent_messages = fake_client.chat.completions.calls[1]["messages"]
    tool_msg = next(m for m in sent_messages if isinstance(m, dict) and m.get("role") == "tool")
    assert json.loads(tool_msg["content"]) == []

    assert "nothing is blocked" not in answer.lower()
    assert "nothing happened" not in answer.lower()
    assert "acme/orders-api" in answer
