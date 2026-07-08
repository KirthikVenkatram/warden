import httpx
import pytest

from core import pipeline, store


@pytest.fixture(autouse=True)
def isolate_db(tmp_path, monkeypatch):
    monkeypatch.setenv("WARDEN_DB", str(tmp_path / "warden.db"))


def test_kev_blocking_fixture_lands_as_block():
    summary = pipeline.run_scan("acme/orders-api", "fixture:kev_blocking", tests_green=True)

    assert summary.total == 1
    assert summary.block == 1
    assert summary.auto == 0
    assert summary.ask == 0
    assert summary.ignore == 0

    [decision] = pipeline.get_decisions("acme/orders-api")
    assert decision.cve == "CVE-2026-42208"
    assert decision.action == "block"


def test_high_epss_fixture_lands_as_ask():
    summary = pipeline.run_scan("acme/orders-api", "fixture:high_epss", tests_green=True)

    assert summary.total == 1
    assert summary.ask == 1
    assert summary.block == 0

    [decision] = pipeline.get_decisions("acme/orders-api")
    assert decision.action == "ask"


def test_quiet_low_fixture_lands_as_auto_when_tests_green():
    summary = pipeline.run_scan("acme/orders-api", "fixture:quiet_low", tests_green=True)

    assert summary.total == 1
    assert summary.auto == 1

    [decision] = pipeline.get_decisions("acme/orders-api")
    assert decision.action == "auto"


def test_quiet_low_fixture_lands_as_ask_when_tests_not_green():
    summary = pipeline.run_scan("acme/orders-api", "fixture:quiet_low", tests_green=False)

    assert summary.total == 1
    assert summary.ask == 1

    [decision] = pipeline.get_decisions("acme/orders-api")
    assert decision.action == "ask"


def test_get_decisions_filters_by_action():
    pipeline.run_scan("acme/orders-api", "fixture:kev_blocking", tests_green=True)

    blocked = pipeline.get_decisions("acme/orders-api", action="block")
    autos = pipeline.get_decisions("acme/orders-api", action="auto")

    assert len(blocked) == 1
    assert autos == []


def test_fixture_path_makes_no_network_calls(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("fixture path must not touch the network")

    monkeypatch.setattr(httpx.Client, "get", fail)

    summary = pipeline.run_scan("acme/orders-api", "fixture:kev_blocking", tests_green=True)

    assert summary.total == 1


def test_rescan_reconciles_instead_of_accumulating():
    pipeline.run_scan("acme/orders-api", "fixture:kev_blocking", tests_green=True)

    summary = pipeline.run_scan("acme/orders-api", "fixture:high_epss", tests_green=True)

    decisions = pipeline.get_decisions("acme/orders-api")
    assert [d.cve for d in decisions] == ["CVE-2021-33503"]
    assert summary.total == len(decisions)


def test_rescan_preserves_snooze_for_reappearing_finding():
    pipeline.run_scan("acme/orders-api", "fixture:kev_blocking", tests_green=True)
    store.snooze("CVE-2026-42208", "acme/orders-api", 9_999_999_999)

    pipeline.run_scan("acme/orders-api", "fixture:high_epss", tests_green=True)
    pipeline.run_scan("acme/orders-api", "fixture:kev_blocking", tests_green=True)

    assert store.is_snoozed("CVE-2026-42208", "acme/orders-api") is True
    assert pipeline.get_decisions("acme/orders-api") == []


def test_scan_summary_counts_match_render_rows_length():
    summary = pipeline.run_scan("acme/orders-api", "fixture:demo_all", tests_green=True)

    rows = store.get_render_rows("acme/orders-api")
    assert summary.total == len(rows)


def test_demo_all_fixture_yields_one_of_each_action():
    summary = pipeline.run_scan("acme/orders-api", "fixture:demo_all", tests_green=True)

    assert summary.block == 1
    assert summary.ask == 1
    assert summary.auto == 1
    assert summary.total == 3
