import json
from collections import Counter
from pathlib import Path

from core import enrich, policy, scanner, store
from core.models import Decision, ScanSummary

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
    store.upsert_decisions(repo, decisions)

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
