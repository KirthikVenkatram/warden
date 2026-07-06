import pytest

from mcp_server.server import draft_fix_pr, explain_finding, get_findings, scan_repo


@pytest.fixture(autouse=True)
def isolate_db(tmp_path, monkeypatch):
    monkeypatch.setenv("WARDEN_DB", str(tmp_path / "warden.db"))


def test_scan_repo_returns_expected_counts_for_fixture():
    summary = scan_repo("acme/orders-api", "fixture:kev_blocking", tests_green=True)

    assert summary["repo"] == "acme/orders-api"
    assert summary["total"] == 1
    assert summary["block"] == 1
    assert summary["auto"] == 0
    assert summary["ask"] == 0
    assert summary["ignore"] == 0


def test_get_findings_filters_by_action():
    scan_repo("acme/orders-api", "fixture:kev_blocking", tests_green=True)

    blocked = get_findings("acme/orders-api", action="block")
    autos = get_findings("acme/orders-api", action="auto")

    assert len(blocked) == 1
    assert blocked[0]["cve"] == "CVE-2026-42208"
    assert autos == []


def test_explain_finding_contains_cve_severity_kev_and_policy_reason():
    scan_repo("acme/orders-api", "fixture:kev_blocking", tests_green=True)

    explanation = explain_finding("CVE-2026-42208", "acme/orders-api")

    assert "CVE-2026-42208" in explanation
    assert "critical" in explanation
    assert "CISA KEV: yes" in explanation
    assert "known exploited in the wild" in explanation


def test_explain_finding_missing_cve_reports_no_stored_finding():
    explanation = explain_finding("CVE-9999-0000", "acme/orders-api")

    assert "No stored finding" in explanation


def test_draft_fix_pr_skips_without_crashing_when_token_unset(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    scan_repo("acme/orders-api", "fixture:kev_blocking", tests_green=True)

    result = draft_fix_pr("CVE-2026-42208", "acme/orders-api")

    assert result["status"] == "skipped"
    assert result["cve"] == "CVE-2026-42208"
    assert "GITHUB_TOKEN" in result["reason"]
