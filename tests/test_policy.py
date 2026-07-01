from core.models import Finding
from core.policy import evaluate


def make_finding(**overrides) -> Finding:
    base = {
        "cve": "CVE-2024-0001",
        "package": "example-pkg",
        "installed_version": "1.0.0",
        "fixed_version": "1.0.1",
        "severity": "low",
        "cvss": 3.1,
        "epss": 0.01,
        "kev": False,
        "scanner": "trivy",
        "repo": "org/repo",
    }
    base.update(overrides)
    return Finding(**base)


def test_kev_blocks_even_at_low_cvss():
    finding = make_finding(kev=True, severity="low", cvss=2.0, epss=0.01)
    [decision] = evaluate([finding], tests_green=True)
    assert decision.action == "block"
    assert any("KEV" in r for r in decision.reasons)


def test_quiet_high_severity_not_blocked():
    finding = make_finding(kev=False, severity="high", cvss=7.5, epss=0.02)
    [decision] = evaluate([finding], tests_green=True)
    assert decision.action == "ask"


def test_low_risk_with_fix_and_tests_green_is_auto():
    finding = make_finding(kev=False, severity="low", epss=0.01)
    [decision] = evaluate([finding], tests_green=True)
    assert decision.action == "auto"
    assert decision.auto_fixable is True


def test_low_risk_with_fix_and_tests_not_green_is_ask():
    finding = make_finding(kev=False, severity="medium", epss=0.01)
    [decision] = evaluate([finding], tests_green=False)
    assert decision.action == "ask"
    assert decision.auto_fixable is True


def test_no_fix_is_ignore():
    finding = make_finding(kev=False, severity="low", epss=0.01, fixed_version=None)
    [decision] = evaluate([finding], tests_green=True)
    assert decision.action == "ignore"
    assert decision.auto_fixable is False


def test_critical_severity_blocks_even_without_kev():
    finding = make_finding(kev=False, severity="critical", epss=0.01)
    [decision] = evaluate([finding], tests_green=True)
    assert decision.action == "block"


def test_custom_epss_threshold():
    finding = make_finding(kev=False, severity="high", epss=0.2)
    [decision] = evaluate([finding], tests_green=True, threshold=0.1)
    assert decision.action == "block"
