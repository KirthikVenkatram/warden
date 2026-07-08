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
    "You are Warden, a security triage agent. Answer concisely using ONLY the "
    "provided tools and context. Never invent CVE data, versions, or policy "
    "decisions — if a tool doesn't have it, say so. The policy gate is "
    "authoritative; you explain decisions, you do not override them."
)


def build_tools() -> list[dict]:
    """OpenAI-style function-tool definitions for the read-only subset of core Warden can answer with."""
    return [
        {
            "type": "function",
            "function": {
                "name": "get_findings",
                "description": (
                    "List stored policy decisions for a repo, optionally filtered by "
                    "action (auto/ask/block/ignore). Snoozed findings are excluded."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "repo": {"type": "string"},
                        "action": {"type": "string", "enum": ["auto", "ask", "block", "ignore"]},
                    },
                    "required": ["repo"],
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
                    "properties": {"cve": {"type": "string"}, "repo": {"type": "string"}},
                    "required": ["cve", "repo"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "get_finding_detail",
                "description": (
                    "Return the stored decision plus enrichment (severity, cvss, epss, kev, "
                    "installed/fixed versions) for a specific cve+repo."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {"cve": {"type": "string"}, "repo": {"type": "string"}},
                    "required": ["cve", "repo"],
                },
            },
        },
    ]


def build_tool_dispatch() -> dict:
    """Maps tool name -> callable(**kwargs) -> JSON-serializable result.

    Thin wrappers over core/ — no business logic here, and no draft_fix_pr: the
    chat loop is answer-only.
    """
    return {
        "get_findings": lambda repo, action=None: [
            d.model_dump(mode="json") for d in pipeline.get_decisions(repo, action)
        ],
        "explain_finding": lambda cve, repo: pipeline.explain_finding(cve, repo),
        "get_finding_detail": lambda cve, repo: store.get_finding_detail(cve, repo),
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
