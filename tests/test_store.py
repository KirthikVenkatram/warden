import time

import pytest

from core import store
from core.models import Decision


def make_decision(cve="CVE-2024-0001", package="pkg", action="ask", auto_fixable=True) -> Decision:
    return Decision(cve=cve, package=package, action=action, reasons=["reason"], auto_fixable=auto_fixable)


@pytest.fixture(autouse=True)
def isolate_db(tmp_path, monkeypatch):
    monkeypatch.setenv("WARDEN_DB", str(tmp_path / "warden.db"))


def test_upsert_decisions_reingest_is_idempotent():
    decision = make_decision()

    store.upsert_decisions("org/repo", [decision])
    store.upsert_decisions("org/repo", [decision])

    assert len(store.get_decisions("org/repo")) == 1


def test_upsert_decisions_updates_in_place():
    store.upsert_decisions("org/repo", [make_decision(action="ask")])
    store.upsert_decisions("org/repo", [make_decision(action="auto")])

    [decision] = store.get_decisions("org/repo")
    assert decision.action == "auto"


def test_get_decisions_filters_by_action():
    store.upsert_decisions(
        "org/repo",
        [make_decision(cve="CVE-1", action="auto"), make_decision(cve="CVE-2", action="ask")],
    )

    auto_only = store.get_decisions("org/repo", action="auto")

    assert [d.cve for d in auto_only] == ["CVE-1"]


def test_get_decisions_scopes_to_repo():
    store.upsert_decisions("org/repo-a", [make_decision(cve="CVE-1")])
    store.upsert_decisions("org/repo-b", [make_decision(cve="CVE-2")])

    assert [d.cve for d in store.get_decisions("org/repo-a")] == ["CVE-1"]


def test_snooze_hides_finding_from_get_decisions():
    store.upsert_decisions("org/repo", [make_decision(cve="CVE-1")])

    store.snooze("CVE-1", "org/repo", time.time() + 3600)

    assert store.get_decisions("org/repo") == []
    assert store.is_snoozed("CVE-1", "org/repo") is True


def test_snooze_expiry_respected():
    store.upsert_decisions("org/repo", [make_decision(cve="CVE-1")])

    store.snooze("CVE-1", "org/repo", time.time() - 10)

    decisions = store.get_decisions("org/repo")
    assert [d.cve for d in decisions] == ["CVE-1"]
    assert store.is_snoozed("CVE-1", "org/repo") is False


def test_replace_findings_drops_stale_rows_from_prior_scan():
    store.replace_findings("org/repo", [make_decision(cve="CVE-1"), make_decision(cve="CVE-2")])

    store.replace_findings("org/repo", [make_decision(cve="CVE-2")])

    assert [d.cve for d in store.get_decisions("org/repo")] == ["CVE-2"]


def test_replace_findings_scopes_deletion_to_repo():
    store.replace_findings("org/repo-a", [make_decision(cve="CVE-1")])
    store.replace_findings("org/repo-b", [make_decision(cve="CVE-2")])

    store.replace_findings("org/repo-a", [make_decision(cve="CVE-1")])

    assert [d.cve for d in store.get_decisions("org/repo-a")] == ["CVE-1"]
    assert [d.cve for d in store.get_decisions("org/repo-b")] == ["CVE-2"]


def test_replace_findings_preserves_snooze_when_finding_reappears():
    store.replace_findings("org/repo", [make_decision(cve="CVE-1")])
    store.snooze("CVE-1", "org/repo", time.time() + 3600)

    store.replace_findings("org/repo", [])
    store.replace_findings("org/repo", [make_decision(cve="CVE-1")])

    assert store.get_decisions("org/repo") == []
    assert store.is_snoozed("CVE-1", "org/repo") is True
