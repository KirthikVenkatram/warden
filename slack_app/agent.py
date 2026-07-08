"""Anthropic tool-use loop for in-thread Q&A about a scan's findings.

Read-only by design: the bound tools mirror scan_repo's already-stored decisions
(get_findings, explain_finding, get_finding_detail) but never draft_fix_pr. The agent
explains what the policy gate already decided; it cannot act on the user's behalf.
"""

import json
import logging
import os

import anthropic

from core import pipeline, store

logger = logging.getLogger(__name__)

_MODEL = "claude-sonnet-4-6"
_MAX_ITERATIONS = 5
_MAX_TOKENS = 1024

_SYSTEM_PROMPT = (
    "You are Warden, a security triage agent. Answer concisely using ONLY the "
    "provided tools and context. Never invent CVE data, versions, or policy "
    "decisions — if a tool doesn't have it, say so. The policy gate is "
    "authoritative; you explain decisions, you do not override them."
)


def build_tools() -> list[dict]:
    """Anthropic tool schemas for the read-only subset of core Warden can answer with."""
    return [
        {
            "name": "get_findings",
            "description": (
                "List stored policy decisions for a repo, optionally filtered by "
                "action (auto/ask/block/ignore). Snoozed findings are excluded."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "action": {"type": "string", "enum": ["auto", "ask", "block", "ignore"]},
                },
                "required": ["repo"],
            },
        },
        {
            "name": "explain_finding",
            "description": "Explain, in plain language, why a specific finding got the policy action it did.",
            "input_schema": {
                "type": "object",
                "properties": {"cve": {"type": "string"}, "repo": {"type": "string"}},
                "required": ["cve", "repo"],
            },
        },
        {
            "name": "get_finding_detail",
            "description": (
                "Return the stored decision plus enrichment (severity, cvss, epss, kev, "
                "installed/fixed versions) for a specific cve+repo."
            ),
            "input_schema": {
                "type": "object",
                "properties": {"cve": {"type": "string"}, "repo": {"type": "string"}},
                "required": ["cve", "repo"],
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


def _extract_text(content: list) -> str:
    parts = [block.text for block in content if getattr(block, "type", None) == "text"]
    return "\n".join(parts).strip() or "I don't have an answer for that."


def answer_question(question: str, context: str, tools: list[dict], tool_dispatch: dict) -> str:
    """Run an Anthropic Messages tool-use loop and return the final text answer.

    Calls the model, dispatches any requested tool to tool_dispatch, feeds the result
    back, and repeats until the model answers with text or _MAX_ITERATIONS is hit
    (in which case it returns a short fallback rather than looping forever).
    """
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return "Q&A not configured — ANTHROPIC_API_KEY is not set."

    client = anthropic.Anthropic()
    messages: list[dict] = [{"role": "user", "content": f"{context}\n\nQuestion: {question}"}]

    for _ in range(_MAX_ITERATIONS):
        response = client.messages.create(
            model=_MODEL,
            max_tokens=_MAX_TOKENS,
            system=_SYSTEM_PROMPT,
            tools=tools,
            messages=messages,
        )

        if response.stop_reason != "tool_use":
            return _extract_text(response.content)

        messages.append({"role": "assistant", "content": response.content})

        tool_results = []
        for block in response.content:
            if getattr(block, "type", None) != "tool_use":
                continue
            func = tool_dispatch.get(block.name)
            if func is None:
                result = {"error": f"unknown tool {block.name}"}
            else:
                try:
                    result = func(**block.input)
                except Exception as exc:
                    logger.exception("tool %s failed", block.name)
                    result = {"error": str(exc)}
            tool_results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": json.dumps(result, default=str),
                }
            )
        messages.append({"role": "user", "content": tool_results})

    return "I couldn't reach an answer within the tool-call budget — try rephrasing the question."
