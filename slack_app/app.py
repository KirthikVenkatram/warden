"""Bolt Socket Mode client. /warden slash command -> pipeline -> Block Kit digest.

No business logic here — run_scan and get_render_rows do the work in core/; this
module only parses the command text, calls them, and renders the result.
"""

import logging
import os

from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

from core import pipeline, store
from slack_app.blockkit import build_digest

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

    return app


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    app = create_app()
    handler = SocketModeHandler(app, os.environ["SLACK_APP_TOKEN"])
    logger.info("connected")
    handler.start()


if __name__ == "__main__":
    main()
