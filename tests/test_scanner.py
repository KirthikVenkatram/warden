import json
from pathlib import Path

from core.scanner import parse_trivy

FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "trivy_sample.json"


def test_parse_trivy_maps_fields_across_results():
    payload = json.loads(FIXTURE.read_text())

    findings = parse_trivy(payload, repo="org/repo")

    assert len(findings) == 3
    assert all(f.scanner == "trivy" and f.repo == "org/repo" for f in findings)


def test_parse_trivy_fix_present_and_severity_lowered():
    payload = json.loads(FIXTURE.read_text())
    [xz, *_] = parse_trivy(payload, repo="org/repo")

    assert xz.cve == "CVE-2024-3094"
    assert xz.package == "xz-utils"
    assert xz.installed_version == "5.6.0"
    assert xz.fixed_version == "5.6.2"
    assert xz.severity == "critical"


def test_parse_trivy_prefers_nvd_v3_score_over_other_sources():
    payload = json.loads(FIXTURE.read_text())
    [xz, *_] = parse_trivy(payload, repo="org/repo")

    # redhat's V3Score (9.8) is higher, but nvd's (8.9) must win when present.
    assert xz.cvss == 8.9


def test_parse_trivy_missing_fixed_version_becomes_none():
    payload = json.loads(FIXTURE.read_text())
    findings = parse_trivy(payload, repo="org/repo")
    lodash = next(f for f in findings if f.cve == "CVE-2023-9999")

    assert lodash.fixed_version is None
    assert lodash.severity == "high"


def test_parse_trivy_falls_back_to_max_score_without_nvd():
    payload = json.loads(FIXTURE.read_text())
    findings = parse_trivy(payload, repo="org/repo")

    lodash = next(f for f in findings if f.cve == "CVE-2023-9999")
    assert lodash.cvss == 7.8  # max(ghsa 7.8, redhat 7.5)

    requests_finding = next(f for f in findings if f.cve == "CVE-2022-1234")
    assert requests_finding.fixed_version == "2.31.0"
    assert requests_finding.severity == "medium"
    assert requests_finding.cvss == 5.3  # max(V2 5.0, V3 5.3), no nvd source
