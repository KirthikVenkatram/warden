from core.models import Decision, Finding

FINDING_JSON = {
    "cve": "CVE-2024-3094",
    "package": "xz-utils",
    "installed_version": "5.6.0",
    "fixed_version": "5.6.2",
    "severity": "critical",
    "cvss": 10.0,
    "epss": 0.94,
    "kev": True,
    "scanner": "trivy",
    "repo": "ubixi/conductor",
}

DECISION_JSON = {
    "cve": "CVE-2024-3094",
    "package": "xz-utils",
    "action": "block",
    "reasons": ["on CISA KEV — known exploited in the wild"],
    "auto_fixable": True,
}


def test_finding_and_decision_round_trip():
    finding = Finding.model_validate(FINDING_JSON)
    assert finding.model_dump(mode="json") == FINDING_JSON

    decision = Decision.model_validate(DECISION_JSON)
    assert decision.model_dump(mode="json") == DECISION_JSON
