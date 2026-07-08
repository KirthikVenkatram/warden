from types import SimpleNamespace

import pytest

from slack_app import agent


def _text_block(text):
    return SimpleNamespace(type="text", text=text)


def _tool_use_block(name, tool_input, tool_id="toolu_1"):
    return SimpleNamespace(type="tool_use", name=name, id=tool_id, input=tool_input)


class FakeMessages:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return self._responses.pop(0)


class FakeClient:
    def __init__(self, responses):
        self.messages = FakeMessages(responses)


@pytest.fixture(autouse=True)
def api_key(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")


def test_answer_question_dispatches_tool_and_returns_final_text(monkeypatch):
    tool_use_response = SimpleNamespace(
        stop_reason="tool_use",
        content=[_tool_use_block("explain_finding", {"cve": "CVE-2026-42208", "repo": "org/repo"})],
    )
    final_response = SimpleNamespace(
        stop_reason="end_turn",
        content=[_text_block("It's blocking because it's on CISA KEV.")],
    )
    fake_client = FakeClient([tool_use_response, final_response])
    monkeypatch.setattr(agent.anthropic, "Anthropic", lambda: fake_client)

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
    assert len(fake_client.messages.calls) == 2


def test_draft_fix_pr_not_exposed_to_chat_loop():
    tool_names = [t["name"] for t in agent.build_tools()]
    assert "draft_fix_pr" not in tool_names
    assert "draft_fix_pr" not in agent.build_tool_dispatch()


def test_iteration_cap_terminates_runaway_tool_use(monkeypatch):
    tool_use_response = SimpleNamespace(
        stop_reason="tool_use",
        content=[_tool_use_block("get_findings", {"repo": "org/repo"})],
    )
    fake_client = FakeClient([tool_use_response] * agent._MAX_ITERATIONS)
    monkeypatch.setattr(agent.anthropic, "Anthropic", lambda: fake_client)

    tool_dispatch = {"get_findings": lambda repo, action=None: []}

    answer = agent.answer_question("why?", "Repo: org/repo", agent.build_tools(), tool_dispatch)

    assert len(fake_client.messages.calls) == agent._MAX_ITERATIONS
    assert "tool-call budget" in answer


def test_missing_api_key_returns_short_message(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    answer = agent.answer_question("why?", "Repo: org/repo", agent.build_tools(), {})

    assert "not configured" in answer
