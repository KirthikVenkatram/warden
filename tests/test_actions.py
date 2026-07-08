import json
import time

import pytest

from core import store
from core.models import Action, Decision, Finding, PRResult, Severity
from slack_app.app import build_approve_update, build_snooze_update, parse_action_value
from slack_app.blockkit import build_detail


@pytest.fixture(autouse=True)
def isolate_db(tmp_path, monkeypatch):
    monkeypatch.setenv("WARDEN_DB", str(tmp_path / "warden.db"))


def _seed_ask_finding(repo="acme/orders-api", cve="CVE-2021-33503"):
    finding = Finding(
        cve=cve,
        package="urllib3",
        installed_version="1.26.4",
        fixed_version="1.26.5",
        severity=Severity.HIGH,
        cvss=7.5,
        epss=0.6,
        kev=False,
        scanner="trivy",
        repo=repo,
    )
    decision = Decision(cve=cve, package="urllib3", action=Action.ASK, reasons=["high EPSS"], auto_fixable=True)
    store.upsert_decisions(repo, [decision], [finding])
    return finding


def test_parse_action_value_from_button():
    action = {"value": json.dumps({"cve": "CVE-1", "repo": "org/repo"})}
    assert parse_action_value(action) == {"cve": "CVE-1", "repo": "org/repo"}


def test_parse_action_value_from_overflow():
    action = {"selected_option": {"value": json.dumps({"cve": "CVE-1", "repo": "org/repo", "days": 7})}}
    assert parse_action_value(action) == {"cve": "CVE-1", "repo": "org/repo", "days": 7}


def test_approve_update_shows_pr_url_on_opened():
    repo = "acme/orders-api"
    cve = "CVE-2021-33503"
    _seed_ask_finding(repo, cve)
    rows = store.get_render_rows(repo)

    pr_result = PRResult(
        cve=cve, package="urllib3", repo=repo, status="opened",
        url="https://github.com/acme/orders-api/pull/7", number=7,
    )
    update = build_approve_update(repo, rows, cve, pr_result)

    blob = json.dumps(update["blocks"])
    assert "https://github.com/acme/orders-api/pull/7" in blob
    assert "Fix PR opened" in blob
    action_ids = [
        el["action_id"]
        for block in update["blocks"]
        if block["type"] == "actions"
        for el in block["elements"]
    ]
    assert "approve_fix" not in action_ids


def test_approve_update_shows_warning_on_skipped():
    repo = "acme/orders-api"
    cve = "CVE-2021-33503"
    _seed_ask_finding(repo, cve)
    rows = store.get_render_rows(repo)

    pr_result = PRResult(
        cve=cve, package="urllib3", repo=repo, status="skipped", reason="GITHUB_TOKEN is not set",
    )
    update = build_approve_update(repo, rows, cve, pr_result)

    blob = json.dumps(update["blocks"])
    assert "GITHUB_TOKEN is not set" in blob
    assert ":warning:" in blob


def test_snooze_sets_future_timestamp_and_hides_finding():
    repo = "acme/orders-api"
    cve = "CVE-2021-33503"
    _seed_ask_finding(repo, cve)

    until_ts = time.time() + 7 * 86400
    store.snooze(cve, repo, until_ts)

    assert store.is_snoozed(cve, repo) is True
    assert store.get_render_rows(repo) == []


def test_snooze_update_replaces_buttons_with_snoozed_note():
    repo = "acme/orders-api"
    cve = "CVE-2021-33503"
    finding_model = _seed_ask_finding(repo, cve)
    until_ts = time.time() + 86400
    store.snooze(cve, repo, until_ts)

    rows = store.get_render_rows(repo)  # empty now, snooze hides it
    finding = store.get_finding_detail(cve, repo)

    update = build_snooze_update(repo, rows, finding, until_ts)

    blob = json.dumps(update["blocks"])
    assert ":zzz: snoozed until" in blob
    assert cve in blob
    action_ids = [
        el["action_id"]
        for block in update["blocks"]
        if block["type"] == "actions"
        for el in block["elements"]
    ]
    assert action_ids == []


def test_explain_builds_detail_blocks_containing_cve():
    repo = "acme/orders-api"
    cve = "CVE-2021-33503"
    _seed_ask_finding(repo, cve)

    detail = store.get_finding_detail(cve, repo)
    msg = build_detail(detail)

    blob = json.dumps(msg["blocks"])
    assert cve in blob
