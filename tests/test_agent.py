import json
from types import SimpleNamespace

import httpx
import pytest

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
        _message(tool_calls=[_tool_call("call_1", "explain_finding", {"cve": "CVE-2026-42208", "repo": "org/repo"})])
    )
    final_response = _response(_message(content="It's blocking because it's on CISA KEV."))
    fake_client = FakeClient([tool_call_response, final_response])
    monkeypatch.setattr(agent, "Groq", lambda **kwargs: fake_client)

    calls = []

    def fake_explain(cve, repo):
        calls.append((cve, repo))
        return "on CISA KEV — known exploited in the wild"

    tool_dispatch = {"explain_finding": fake_explain}

    answer = agent.answer_question(
        "why is this blocking?", "Repo: org/repo", agent.build_tools(), tool_dispatch
    )

    assert calls == [("CVE-2026-42208", "org/repo")]
    assert answer == "It's blocking because it's on CISA KEV."
    assert len(fake_client.chat.completions.calls) == 2


def test_draft_fix_pr_not_exposed_to_chat_loop():
    tool_names = [t["function"]["name"] for t in agent.build_tools()]
    assert "draft_fix_pr" not in tool_names
    assert "draft_fix_pr" not in agent.build_tool_dispatch()


def test_iteration_cap_terminates_runaway_tool_use(monkeypatch):
    tool_call_response = _response(
        _message(tool_calls=[_tool_call("call_1", "get_findings", {"repo": "org/repo"})])
    )
    fake_client = FakeClient([tool_call_response] * agent._MAX_ITERATIONS)
    monkeypatch.setattr(agent, "Groq", lambda **kwargs: fake_client)

    tool_dispatch = {"get_findings": lambda repo, action=None: []}

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
