from mcp.server.fastmcp import FastMCP

from core import pipeline

mcp = FastMCP("warden")


@mcp.tool()
def scan_repo(repo: str, source: str = "fixture:kev_blocking", tests_green: bool = False) -> dict:
    """Scan a repo's dependencies and gate every finding through the autonomy policy.

    Parses scanner output (a Trivy JSON report path, or "fixture:<name>" for one of the
    bundled demo fixtures — kev_blocking, high_epss, quiet_low), enriches each finding
    with EPSS + CISA KEV data, evaluates the Rego policy to decide auto/ask/block/ignore
    per finding, and stores the decisions (deduped by cve+package+repo). Set tests_green
    to True when the repo's test suite is currently passing — the policy only allows
    `auto` autonomy when tests are green. Returns a ScanSummary: repo, scanner, and
    counts of findings by action (total/auto/ask/block/ignore).
    """
    return pipeline.run_scan(repo, source, tests_green).model_dump(mode="json")


@mcp.tool()
def get_findings(repo: str, action: str | None = None) -> list[dict]:
    """List stored policy decisions for a repo, optionally filtered by action.

    action, if given, must be one of "auto", "ask", "block", or "ignore". Snoozed
    findings are excluded automatically. Each result is a Decision: cve, package,
    action, reasons (the exact policy justification), and auto_fixable. Call scan_repo
    first if a repo has no stored findings yet.
    """
    return [d.model_dump(mode="json") for d in pipeline.get_decisions(repo, action)]


@mcp.tool()
def explain_finding(cve: str, repo: str) -> str:
    """Explain, in plain language, why a specific finding got the policy action it did.

    Looks up the stored decision for this cve+repo (from the most recent scan_repo)
    and formats its severity, CVSS, EPSS score, CISA KEV status, the exact policy
    reasons, and whether it's auto-fixable. Pure formatting over already-stored data —
    it does not re-scan or call an LLM. Returns a message saying no finding is stored
    if scan_repo hasn't been run for this repo, or the cve isn't present.
    """
    return pipeline.explain_finding(cve, repo)


@mcp.tool()
def draft_fix_pr(cve: str, repo: str) -> dict:
    """Open a pull request that bumps the vulnerable package to its fixed version.

    Only call this for findings whose policy decision is "auto" or "ask" (never for
    "block" — the autonomy ladder does not permit fixing a blocked finding this way)
    and where auto_fixable is true. Not yet implemented: returns a stub result so the
    tool is callable; real PR creation lands in a later chunk.
    """
    return {"status": "not_implemented", "cve": cve}


if __name__ == "__main__":
    mcp.run()
