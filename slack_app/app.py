"""Bolt Socket Mode client. /warden slash command -> pipeline -> Block Kit digest.

No business logic here — run_scan and get_render_rows do the work in core/; this
module only parses the command text, calls them, and renders the result.
"""

import json
import logging
import os
import time
from collections import Counter

from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

from core import pipeline, store
from core.models import PRResult, ScanSummary
from slack_app.blockkit import build_approved_card, build_detail, build_digest, build_snoozed_card

logger = logging.getLogger(__name__)

_DEFAULT_SOURCE = "fixture:kev_blocking"
_USAGE_HINT = "Usage: `/warden scan <owner/repo> [--source fixture:<name>] [--tests-green]`"


def parse_scan_command(text: str) -> dict | None:
    """Parse "scan <repo> [--source <name>] [--tests-green]" into run_scan args.

    Returns None for anything that doesn't match (missing repo, unknown flag, a
    dangling --source with no value) so the caller can fall back to a usage hint.
    """
    tokens = (text or "").split()
    if len(tokens) < 2 or tokens[0].lower() != "scan":
        return None

    repo = tokens[1]
    source = _DEFAULT_SOURCE
    tests_green = False

    i = 2
    while i < len(tokens):
        token = tokens[i]
        if token == "--source":
            if i + 1 >= len(tokens):
                return None
            source = tokens[i + 1]
            i += 2
        elif token == "--tests-green":
            tests_green = True
            i += 1
        else:
            return None

    return {"repo": repo, "source": source, "tests_green": tests_green}


_SNOOZE_SECONDS_PER_DAY = 86400


def parse_action_value(action: dict) -> dict:
    """Extract the {"cve", "repo", ...} payload from a button or overflow action.

    Overflow menus (snooze) carry their value inside selected_option; plain
    buttons (approve/explain) carry it directly on the action.
    """
    raw = action["selected_option"]["value"] if "selected_option" in action else action["value"]
    return json.loads(raw)


def _summary_from_rows(repo: str, rows: list[dict]) -> ScanSummary:
    counts = Counter(row["action"] for row in rows)
    return ScanSummary(
        repo=repo,
        scanner="trivy",
        total=len(rows),
        auto=counts["auto"],
        ask=counts["ask"],
        block=counts["block"],
        ignore=counts["ignore"],
    )


def build_approve_update(repo: str, rows: list[dict], cve: str, pr_result: PRResult) -> dict:
    """Rebuild the digest with only `cve`'s card transformed to show the PR result."""
    finding = next(row for row in rows if row["cve"] == cve)
    overrides = {cve: build_approved_card(finding, pr_result)}
    summary = _summary_from_rows(repo, rows)
    return build_digest(summary, rows, overrides=overrides)


def build_snooze_update(repo: str, rows: list[dict], finding: dict, until_ts: float) -> dict:
    """Rebuild the digest with `finding`'s card transformed to show the snooze note.

    `rows` no longer contains `finding` (get_render_rows excludes snoozed findings),
    so it's added back in just for this render.
    """
    combined = [row for row in rows if row["cve"] != finding["cve"]] + [finding]
    overrides = {finding["cve"]: build_snoozed_card(finding, until_ts)}
    summary = _summary_from_rows(repo, combined)
    return build_digest(summary, combined, overrides=overrides)


def _fallback_text(repo: str, summary) -> str:
    return (
        f"Warden scan of {repo}: {summary.total} finding(s) — "
        f"{summary.block} blocked, {summary.ask} need approval, "
        f"{summary.auto} auto-fixed, {summary.ignore} ignored."
    )


def create_app() -> App:
    app = App(token=os.environ["SLACK_BOT_TOKEN"])

    @app.command("/warden")
    def handle_warden_command(ack, respond, say, command):
        ack()

        parsed = parse_scan_command(command.get("text", ""))
        if parsed is None:
            respond(_USAGE_HINT)
            return

        repo = parsed["repo"]
        try:
            summary = pipeline.run_scan(repo, parsed["source"], parsed["tests_green"])
            rows = store.get_render_rows(repo)
            digest = build_digest(summary, rows)
        except Exception:
            logger.exception("warden scan failed for %s", repo)
            say(f"Scan of {repo} failed — check the logs.")
            return

        say(text=_fallback_text(repo, summary), blocks=digest["blocks"])

    @app.action("approve_fix")
    def handle_approve_fix(ack, body, respond):
        ack()

        value = parse_action_value(body["actions"][0])
        cve, repo = value["cve"], value["repo"]

        try:
            pr_result = pipeline.draft_fix_pr(cve, repo)
            rows = store.get_render_rows(repo)
            update = build_approve_update(repo, rows, cve, pr_result)
        except Exception:
            logger.exception("approve_fix failed for %s in %s", cve, repo)
            return

        respond(replace_original=True, text=_fallback_text(repo, _summary_from_rows(repo, rows)), blocks=update["blocks"])

    @app.action("explain_finding")
    def handle_explain_finding(ack, body, client):
        ack()

        value = parse_action_value(body["actions"][0])
        cve, repo = value["cve"], value["repo"]

        detail = store.get_finding_detail(cve, repo)
        channel = body["channel"]["id"]
        thread_ts = body["message"]["ts"]

        if detail is None:
            client.chat_postMessage(
                channel=channel,
                thread_ts=thread_ts,
                text=f"No stored finding for {cve} in {repo}. Run scan_repo first.",
            )
            return

        blocks = build_detail(detail)["blocks"]
        client.chat_postMessage(
            channel=channel,
            thread_ts=thread_ts,
            text=f"{detail['cve']} details",
            blocks=blocks,
        )

    @app.action("snooze_finding")
    def handle_snooze_finding(ack, body, respond):
        ack()

        value = parse_action_value(body["actions"][0])
        cve, repo, days = value["cve"], value["repo"], value["days"]

        try:
            finding = store.get_finding_detail(cve, repo)
            until_ts = time.time() + days * _SNOOZE_SECONDS_PER_DAY
            store.snooze(cve, repo, until_ts)
            rows = store.get_render_rows(repo)
            update = build_snooze_update(repo, rows, finding, until_ts)
        except Exception:
            logger.exception("snooze_finding failed for %s in %s", cve, repo)
            return

        respond(replace_original=True, text=_fallback_text(repo, _summary_from_rows(repo, rows)), blocks=update["blocks"])

    return app


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    app = create_app()
    handler = SocketModeHandler(app, os.environ["SLACK_APP_TOKEN"])
    logger.info("connected")
    handler.start()


if __name__ == "__main__":
    main()
