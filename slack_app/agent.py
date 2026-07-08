"""Gemini tool-use loop for in-thread Q&A about a scan's findings.

Read-only by design: the bound tools mirror scan_repo's already-stored decisions
(get_findings, explain_finding, get_finding_detail) but never draft_fix_pr. The agent
explains what the policy gate already decided; it cannot act on the user's behalf.
"""

import json
import logging
import os
import time

from google import genai
from google.genai import errors, types

from core import pipeline, store

logger = logging.getLogger(__name__)

_MODEL = "gemini-flash-latest"
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
    """Gemini function declarations for the read-only subset of core Warden can answer with."""
    return [
        {
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
        {
            "name": "explain_finding",
            "description": "Explain, in plain language, why a specific finding got the policy action it did.",
            "parameters": {
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
            "parameters": {
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


def _to_function_declarations(tools: list[dict]) -> list[types.FunctionDeclaration]:
    return [
        types.FunctionDeclaration(
            name=tool["name"],
            description=tool["description"],
            parameters=tool["parameters"],
        )
        for tool in tools
    ]


def _extract_function_calls(response) -> list:
    parts = getattr(response.candidates[0].content, "parts", []) if response.candidates else []
    return [part.function_call for part in parts if getattr(part, "function_call", None)]


def _generate_content_with_retry(client, **kwargs):
    """Retry transient Gemini server errors (e.g. 503 UNAVAILABLE) with backoff."""
    for attempt in range(_MAX_RETRIES):
        try:
            return client.models.generate_content(**kwargs)
        except errors.ServerError:
            if attempt == _MAX_RETRIES - 1:
                raise
            time.sleep(_RETRY_BACKOFF_SECONDS * (2**attempt))


def answer_question(question: str, context: str, tools: list[dict], tool_dispatch: dict) -> str:
    """Run a Gemini function-calling loop and return the final text answer.

    Calls the model, dispatches any requested tool to tool_dispatch, feeds the result
    back, and repeats until the model answers with text or _MAX_ITERATIONS is hit
    (in which case it returns a short fallback rather than looping forever).
    """
    if not os.environ.get("GEMINI_API_KEY"):
        return "Q&A not configured — GEMINI_API_KEY is not set."

    client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
    config = types.GenerateContentConfig(
        tools=[types.Tool(function_declarations=_to_function_declarations(tools))],
        system_instruction=_SYSTEM_PROMPT,
    )
    contents: list = [
        types.Content(role="user", parts=[types.Part.from_text(text=f"{context}\n\nQuestion: {question}")])
    ]

    for _ in range(_MAX_ITERATIONS):
        try:
            response = _generate_content_with_retry(client, model=_MODEL, contents=contents, config=config)
        except errors.ServerError:
            logger.exception("Gemini generate_content failed after retries")
            return "Q&A temporarily unavailable, try again."

        function_calls = _extract_function_calls(response)
        if not function_calls:
            return (response.text or "").strip() or "I don't have an answer for that."

        contents.append(response.candidates[0].content)

        response_parts = []
        for call in function_calls:
            func = tool_dispatch.get(call.name)
            if func is None:
                result = {"error": f"unknown tool {call.name}"}
            else:
                try:
                    result = func(**call.args)
                except Exception as exc:
                    logger.exception("tool %s failed", call.name)
                    result = {"error": str(exc)}
            response_parts.append(
                types.Part.from_function_response(
                    name=call.name,
                    response={"result": json.loads(json.dumps(result, default=str))},
                )
            )
        contents.append(types.Content(role="user", parts=response_parts))

    return "I couldn't reach an answer within the tool-call budget — try rephrasing the question."
