"""Groq tool-use loop for in-thread Q&A about a scan's findings.

Read-only by design: the bound tools mirror scan_repo's already-stored decisions
(get_findings, explain_finding, get_finding_detail) but never draft_fix_pr. The agent
explains what the policy gate already decided; it cannot act on the user's behalf.
"""

import json
import logging
import os
import time

import groq
from groq import Groq

from core import pipeline, store

logger = logging.getLogger(__name__)

_MODEL = "openai/gpt-oss-20b"
_MAX_ITERATIONS = 5
_MAX_RETRIES = 3
_RETRY_BACKOFF_SECONDS = 1

_SYSTEM_PROMPT = (
    "You're Warden, a friendly security teammate answering follow-up questions in a Slack "
    "thread about a vulnerability scan. Be concise, warm, and conversational — plain "
    "language, no jargon dump.\n\n"
    "Grounding rules are absolute, no exceptions:\n"
    "- Only state facts that come from the provided context or a tool result. Never invent "
    "CVEs, packages, versions, repos, or policy outcomes.\n"
    "- The policy gate's decision (auto/ask/block/ignore) is authoritative — explain it, "
    "never second-guess or override it.\n"
    "- You are always scoped to the one repo named in your context. Every tool call you "
    "make is automatically scoped to that repo — you have no way to query any other repo, "
    "so never claim to.\n"
    "- If a tool call comes back empty (an empty list or {}), respond with exactly: "
    "\"I don't have findings for <repo>\" — substituting the real repo named in your context "
    "above, never a guessed or different one. Never conclude or imply that 'nothing is "
    "blocked' or 'nothing happened' just because a lookup came back empty, especially if "
    "findings are already visible earlier in the thread.\n"
    "- If you're unsure, say so instead of guessing."
)


def build_context(repo: str, rows: list[dict]) -> str:
    """Ground the agent in the resolved repo and the findings already visible in-thread.

    Built once per question from the parent digest's stored rows, so the agent already
    "sees" what's posted before calling any tool, and always has the resolved repo —
    it never has to guess one.
    """
    if not rows:
        return f"Repo: {repo}\nNo findings are currently stored for this repo."

    lines = [f"Repo: {repo}", "Findings already posted in this thread:"]
    for row in rows:
        lines.append(f"- {row['cve']} ({row['package']}): {row['action']} — {'; '.join(row['reasons'])}")
    return "\n".join(lines)


def build_tools() -> list[dict]:
    """OpenAI-style function-tool definitions for the read-only subset of core Warden can answer with.

    None of these take a `repo` parameter — the repo is bound server-side in
    build_tool_dispatch, so the model has no way to query a repo other than the one
    resolved for this thread.
    """
    return [
        {
            "type": "function",
            "function": {
                "name": "get_findings",
                "description": (
                    "List stored policy decisions for the current repo. Snoozed findings are "
                    "excluded. action: optional. Omit this argument entirely to return all "
                    "findings. If provided, must be exactly one of auto, ask, block, ignore."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": ["string", "null"],
                            "enum": ["auto", "ask", "block", "ignore"],
                        },
                    },
                    "required": [],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "explain_finding",
                "description": "Explain, in plain language, why a specific finding got the policy action it did.",
                "parameters": {
                    "type": "object",
                    "properties": {"cve": {"type": "string"}},
                    "required": ["cve"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "get_finding_detail",
                "description": (
                    "Return the stored decision plus enrichment (severity, cvss, epss, kev, "
                    "installed/fixed versions) for a specific cve in the current repo."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {"cve": {"type": "string"}},
                    "required": ["cve"],
                },
            },
        },
    ]


_VALID_ACTIONS = {"auto", "ask", "block", "ignore"}


def _sanitize_action(action: str | None) -> str | None:
    """Coerce Groq's occasional {"action": ""} (meaning "no filter") to None.

    Only a value from _VALID_ACTIONS is ever passed through to core — anything else
    (None, "", or garbage) becomes None so an invalid value never reaches core.
    """
    return action if action in _VALID_ACTIONS else None


def build_tool_dispatch(repo: str) -> dict:
    """Maps tool name -> callable(**kwargs) -> JSON-serializable result, bound to repo.

    Thin wrappers over core/ — no business logic here, and no draft_fix_pr: the
    chat loop is answer-only. repo is closed over rather than taken from the model, so
    a tool call can never be issued against a guessed or invented repo.
    """
    return {
        "get_findings": lambda action=None: [
            d.model_dump(mode="json") for d in pipeline.get_decisions(repo, _sanitize_action(action))
        ],
        "explain_finding": lambda cve: pipeline.explain_finding(cve, repo),
        "get_finding_detail": lambda cve: store.get_finding_detail(cve, repo),
    }


def _create_with_retry(client, **kwargs):
    """Retry transient Groq server errors (5xx, 429) with backoff."""
    for attempt in range(_MAX_RETRIES):
        try:
            return client.chat.completions.create(**kwargs)
        except groq.APIStatusError as exc:
            if exc.status_code < 500 and exc.status_code != 429:
                raise
            if attempt == _MAX_RETRIES - 1:
                raise
            time.sleep(_RETRY_BACKOFF_SECONDS * (2**attempt))


def answer_question(question: str, context: str, tools: list[dict], tool_dispatch: dict) -> str:
    """Run a Groq function-calling loop and return the final text answer.

    Calls the model, dispatches any requested tool to tool_dispatch, feeds the result
    back, and repeats until the model answers with text or _MAX_ITERATIONS is hit
    (in which case it returns a short fallback rather than looping forever).
    """
    if not os.environ.get("GROQ_API_KEY"):
        return "Q&A not configured — GROQ_API_KEY is not set."

    client = Groq(api_key=os.environ["GROQ_API_KEY"])
    messages: list = [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": f"{context}\n\nQuestion: {question}"},
    ]

    for _ in range(_MAX_ITERATIONS):
        try:
            response = _create_with_retry(
                client, model=_MODEL, messages=messages, tools=tools, tool_choice="auto"
            )
        except groq.APIStatusError:
            logger.exception("Groq chat.completions.create failed after retries")
            return "Q&A temporarily unavailable, try again."

        message = response.choices[0].message
        tool_calls = message.tool_calls or []
        if not tool_calls:
            return (message.content or "").strip() or "I don't have an answer for that."

        messages.append(message)

        for call in tool_calls:
            func = tool_dispatch.get(call.function.name)
            try:
                args = json.loads(call.function.arguments)
            except (TypeError, json.JSONDecodeError):
                args = {}
            if func is None:
                result = {"error": f"unknown tool {call.function.name}"}
            else:
                try:
                    result = func(**args)
                except Exception as exc:
                    logger.exception("tool %s failed", call.function.name)
                    result = {"error": str(exc)}
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": call.id,
                    "content": json.dumps(result, default=str),
                }
            )

    return "I couldn't reach an answer within the tool-call budget — try rephrasing the question."
