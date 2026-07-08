from types import SimpleNamespace

import pytest

from slack_app import agent


def _function_call(name, args):
    return SimpleNamespace(name=name, args=args)


def _function_call_part(name, args):
    return SimpleNamespace(function_call=_function_call(name, args), text=None)


def _text_part(text):
    return SimpleNamespace(function_call=None, text=text)


def _response(parts, text=None):
    content = SimpleNamespace(parts=parts)
    candidate = SimpleNamespace(content=content)
    return SimpleNamespace(candidates=[candidate], text=text)


class FakeModels:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def generate_content(self, **kwargs):
        self.calls.append(kwargs)
        return self._responses.pop(0)


class FakeClient:
    def __init__(self, responses):
        self.models = FakeModels(responses)


@pytest.fixture(autouse=True)
def api_key(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")


def test_answer_question_dispatches_tool_and_returns_final_text(monkeypatch):
    tool_call_response = _response(
        [_function_call_part("explain_finding", {"cve": "CVE-2026-42208", "repo": "org/repo"})]
    )
    final_response = _response(
        [_text_part("It's blocking because it's on CISA KEV.")],
        text="It's blocking because it's on CISA KEV.",
    )
    fake_client = FakeClient([tool_call_response, final_response])
    monkeypatch.setattr(agent.genai, "Client", lambda **kwargs: fake_client)

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
    assert len(fake_client.models.calls) == 2


def test_draft_fix_pr_not_exposed_to_chat_loop():
    tool_names = [t["name"] for t in agent.build_tools()]
    assert "draft_fix_pr" not in tool_names
    assert "draft_fix_pr" not in agent.build_tool_dispatch()


def test_iteration_cap_terminates_runaway_tool_use(monkeypatch):
    tool_call_response = _response(
        [_function_call_part("get_findings", {"repo": "org/repo"})]
    )
    fake_client = FakeClient([tool_call_response] * agent._MAX_ITERATIONS)
    monkeypatch.setattr(agent.genai, "Client", lambda **kwargs: fake_client)

    tool_dispatch = {"get_findings": lambda repo, action=None: []}

    answer = agent.answer_question("why?", "Repo: org/repo", agent.build_tools(), tool_dispatch)

    assert len(fake_client.models.calls) == agent._MAX_ITERATIONS
    assert "tool-call budget" in answer


def test_missing_api_key_returns_short_message(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    answer = agent.answer_question("why?", "Repo: org/repo", agent.build_tools(), {})

    assert "not configured" in answer
