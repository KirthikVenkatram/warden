import json
from pathlib import Path

from core.models import Finding

_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}


def _max_cvss(cvss_map: dict) -> float:
    """Prefer nvd's V3 score; otherwise the max V3/V2 score across all sources."""
    if not cvss_map:
        return 0.0

    nvd = cvss_map.get("nvd") or {}
    if nvd.get("V3Score") is not None:
        return float(nvd["V3Score"])

    scores = [
        float(score)
        for source in cvss_map.values()
        for score in (source.get("V3Score"), source.get("V2Score"))
        if score is not None
    ]
    return max(scores) if scores else 0.0


def parse_trivy(report: dict, repo: str) -> list[Finding]:
    """Walk a parsed Trivy JSON report into pre-enrichment Findings for repo."""
    findings = []
    for result in report.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            findings.append(
                Finding(
                    cve=vuln["VulnerabilityID"],
                    package=vuln["PkgName"],
                    installed_version=vuln["InstalledVersion"],
                    fixed_version=vuln.get("FixedVersion") or None,
                    severity=_SEVERITY_MAP[vuln["Severity"].upper()],
                    cvss=_max_cvss(vuln.get("CVSS") or {}),
                    scanner="trivy",
                    repo=repo,
                )
            )
    return findings


def load_fixture(path: str | Path) -> list[Finding]:
    """Load a pre-enriched Finding list straight from JSON (demo fixtures)."""
    data = json.loads(Path(path).read_text())
    return [Finding.model_validate(f) for f in data]
