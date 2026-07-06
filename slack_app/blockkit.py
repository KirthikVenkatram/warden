"""Block Kit builders — pure functions from core data to Slack message JSON.

No slack client, no MCP, no business logic. Each finding dict passed in follows the
shape of core.store.get_finding_detail: cve, repo, package, action, reasons,
auto_fixable, severity, cvss, epss, kev, installed_version, fixed_version, plus an
optional "pr_url" for auto-remediated findings.
"""

import json

from core.models import ScanSummary

_ACTION_EMOJI = {
    "block": ":red_circle:",
    "ask": ":large_yellow_circle:",
    "auto": ":large_green_circle:",
    "ignore": ":white_circle:",
}
_ACTION_ORDER = {"block": 0, "ask": 1, "auto": 2, "ignore": 3}
_ACTION_LABEL = {"block": "blocked", "ask": "needs approval", "auto": "auto-fixed", "ignore": "ignored"}

_MAX_BLOCKS = 50
_MAX_SECTION_CHARS = 3000
_SNOOZE_OPTIONS = [("1 day", 1), ("7 days", 7), ("30 days", 30)]


def _value(cve: str, repo: str, **extra) -> str:
    return json.dumps({"cve": cve, "repo": repo, **extra})


def _truncate(text: str, limit: int = _MAX_SECTION_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def _count_line(summary: ScanSummary) -> str:
    parts = []
    for action in ("block", "ask", "auto", "ignore"):
        count = getattr(summary, action)
        if count:
            parts.append(f"{count} {_ACTION_LABEL[action]}")
    return " · ".join(parts) if parts else "no findings"


def _finding_text(finding: dict) -> str:
    action = finding["action"]
    emoji = _ACTION_EMOJI.get(action, "")
    cve = finding["cve"]
    package = finding["package"]
    installed = finding.get("installed_version")
    fixed = finding.get("fixed_version")
    severity = finding.get("severity")
    epss = finding.get("epss")

    versions = f"{installed} → {fixed}" if fixed else (installed or "version unknown")

    details = [versions]
    if severity:
        details.append(str(severity).upper())
    if epss is not None:
        details.append(f"EPSS {epss * 100:.0f}%")
    if finding.get("kev"):
        details.append(":rotating_light: KEV")

    text = f"{emoji} *{package}* — *{cve}*\n" + " · ".join(details)
    return _truncate(text)


def _finding_blocks(finding: dict, repo: str) -> list[dict]:
    action = finding["action"]
    cve = finding["cve"]

    blocks: list[dict] = [
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": _finding_text(finding)},
        }
    ]

    explain_button = {
        "type": "button",
        "text": {"type": "plain_text", "text": "Explain"},
        "action_id": "explain_finding",
        "value": _value(cve, repo),
    }

    if action == "block":
        blocks.append(
            {
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": ":lock: Merge blocked by policy"}],
            }
        )
        blocks.append({"type": "actions", "elements": [explain_button]})
    elif action == "ask":
        approve_button = {
            "type": "button",
            "text": {"type": "plain_text", "text": "Approve fix"},
            "style": "primary",
            "action_id": "approve_fix",
            "value": _value(cve, repo),
        }
        snooze_overflow = {
            "type": "overflow",
            "action_id": "snooze_finding",
            "options": [
                {
                    "text": {"type": "plain_text", "text": f"Snooze {label}"},
                    "value": _value(cve, repo, days=days),
                }
                for label, days in _SNOOZE_OPTIONS
            ],
        }
        blocks.append(
            {
                "type": "actions",
                "elements": [approve_button, snooze_overflow, explain_button],
            }
        )
    elif action == "auto":
        text = ":white_check_mark: auto-remediated"
        pr_url = finding.get("pr_url")
        if pr_url:
            text += f" — <{pr_url}|view PR>"
        blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": text}]})
    else:  # ignore
        blocks.append(
            {
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": "no fix available — informational only"}],
            }
        )

    return blocks


def build_digest(summary: ScanSummary, decisions: list[dict]) -> dict:
    """Build a Block Kit digest message for a scan's findings.

    `decisions` items follow the core.store.get_finding_detail shape (see module
    docstring). Findings are ordered block, ask, auto, ignore. Respects Slack's
    50-block and ~3000-char-per-section limits, truncating and noting overflow.
    """
    blocks: list[dict] = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"{summary.repo} — {_count_line(summary)}"},
        },
        {"type": "divider"},
    ]

    ordered = sorted(decisions, key=lambda d: _ACTION_ORDER.get(d["action"], 99))

    rendered = 0
    for finding in ordered:
        finding_blocks = _finding_blocks(finding, summary.repo)
        if len(blocks) + len(finding_blocks) > _MAX_BLOCKS - 1:
            break
        blocks.extend(finding_blocks)
        rendered += 1

    remaining = len(ordered) - rendered
    if remaining > 0:
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"…and {remaining} more finding(s) not shown."}
                ],
            }
        )

    return {"blocks": blocks}


def build_detail(detail: dict) -> dict:
    """Build a Block Kit message explaining one finding in full (Explain button target)."""
    cve = detail["cve"]
    package = detail["package"]
    nvd_link = f"https://nvd.nist.gov/vuln/detail/{cve}"

    installed = detail.get("installed_version")
    fixed = detail.get("fixed_version")
    versions = f"{installed} → {fixed}" if fixed else (installed or "version unknown")

    facts = [
        f"<{nvd_link}|{cve}>",
        f"*Severity:* {detail.get('severity') or 'unknown'}",
        f"*CVSS:* {detail.get('cvss')}",
        f"*EPSS:* {detail.get('epss')}",
        f"*KEV:* {'yes' if detail.get('kev') else 'no'}",
        f"*Versions:* {versions}",
        f"*Auto-fixable:* {'yes' if detail.get('auto_fixable') else 'no'}",
    ]

    reasons = detail.get("reasons") or []
    reasons_text = "*Policy reasons:*\n" + "\n".join(f"• {r}" for r in reasons)

    return {
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{package} — {cve}"},
            },
            {"type": "section", "text": {"type": "mrkdwn", "text": _truncate("\n".join(facts))}},
            {"type": "divider"},
            {"type": "section", "text": {"type": "mrkdwn", "text": _truncate(reasons_text)}},
        ]
    }
