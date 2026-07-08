import json
from collections import Counter
from pathlib import Path

from core import enrich, github_pr, policy, scanner, store
from core.models import Decision, PRResult, ScanSummary

_FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


def run_scan(repo: str, source: str, tests_green: bool = False, threshold: float = 0.5) -> ScanSummary:
    """Ingest -> enrich -> gate -> store, headless end-to-end.

    source="fixture:<name>" loads a pre-enriched fixture and skips live enrichment
    (deterministic demo path, no network calls). Any other source is treated as a
    path to a Trivy JSON report, parsed and enriched live.
    """
    if source.startswith("fixture:"):
        name = source.removeprefix("fixture:")
        findings = scanner.load_fixture(_FIXTURES_DIR / f"{name}.json")
    else:
        report = json.loads(Path(source).read_text())
        findings = scanner.parse_trivy(report, repo)
        findings = enrich.enrich(findings)

    decisions = policy.evaluate(findings, tests_green, threshold)
    store.replace_findings(repo, decisions, findings)

    counts = Counter(d.action.value for d in decisions)
    return ScanSummary(
        repo=repo,
        scanner="trivy",
        total=len(decisions),
        auto=counts["auto"],
        ask=counts["ask"],
        block=counts["block"],
        ignore=counts["ignore"],
    )


def get_decisions(repo: str, action: str | None = None) -> list[Decision]:
    """Thin pass-through to store.get_decisions."""
    return store.get_decisions(repo, action)


def explain_finding(cve: str, repo: str) -> str:
    """Format a human-readable explanation of the stored decision for cve+repo.

    Pure formatting over what run_scan already stored (severity, CVSS, EPSS, KEV,
    installed/fixed versions, the exact policy reasons, auto-fixability) — no
    re-scanning, no LLM.
    """
    detail = store.get_finding_detail(cve, repo)
    if detail is None:
        return f"No stored finding for {cve} in {repo}. Run scan_repo first."

    lines = [f"{detail['cve']} ({detail['package']}) in {repo}", f"Action: {detail['action']}"]

    if detail["severity"] is not None:
        lines.append(f"Severity: {detail['severity']} (CVSS {detail['cvss']})")
    if detail["epss"] is not None:
        lines.append(f"EPSS: {detail['epss']:.2f}")
    if detail["kev"] is not None:
        lines.append(f"CISA KEV: {'yes' if detail['kev'] else 'no'}")
    if detail["installed_version"] is not None:
        lines.append(f"Installed version: {detail['installed_version']}")

    lines.append("Reasons: " + "; ".join(detail["reasons"]))

    fixable = "yes" if detail["auto_fixable"] else "no"
    if detail["fixed_version"]:
        fixable += f" (fixed version {detail['fixed_version']})"
    lines.append(f"Auto-fixable: {fixable}")

    return "\n".join(lines)


def draft_fix_pr(cve: str, repo: str) -> PRResult:
    """Look up the stored finding for cve+repo and open a fix PR for it.

    Thin orchestration: no stored finding, or no fixed version on file, skips without
    touching GitHub. Otherwise hands off to github_pr.open_fix_pr, which itself skips
    safely (rather than raising) if GITHUB_TOKEN is unset or the pin can't be found.
    """
    detail = store.get_finding_detail(cve, repo)
    if detail is None:
        return PRResult(
            cve=cve,
            package="",
            repo=repo,
            status="skipped",
            reason=f"No stored finding for {cve} in {repo}. Run scan_repo first.",
        )
    if not detail.get("fixed_version"):
        return PRResult(
            cve=cve,
            package=detail["package"],
            repo=repo,
            status="skipped",
            reason="No fixed version available for this finding.",
        )

    return github_pr.open_fix_pr(
        repo=repo,
        cve=cve,
        package=detail["package"],
        installed_version=detail["installed_version"],
        fixed_version=detail["fixed_version"],
    )
