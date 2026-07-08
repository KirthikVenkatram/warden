from core import store
from core.models import Action, Decision, Finding, Severity
from slack_app.app import parse_scan_command


def test_parses_bare_repo():
    assert parse_scan_command("scan owner/repo") == {
        "repo": "owner/repo",
        "source": "fixture:kev_blocking",
        "tests_green": False,
    }


def test_parses_source_flag():
    assert parse_scan_command("scan owner/repo --source fixture:high_epss") == {
        "repo": "owner/repo",
        "source": "fixture:high_epss",
        "tests_green": False,
    }


def test_parses_tests_green_flag():
    assert parse_scan_command("scan owner/repo --tests-green") == {
        "repo": "owner/repo",
        "source": "fixture:kev_blocking",
        "tests_green": True,
    }


def test_parses_source_and_tests_green_together():
    assert parse_scan_command("scan owner/repo --source fixture:high_epss --tests-green") == {
        "repo": "owner/repo",
        "source": "fixture:high_epss",
        "tests_green": True,
    }


def test_malformed_input_returns_none():
    assert parse_scan_command("") is None
    assert parse_scan_command("owner/repo") is None
    assert parse_scan_command("scan") is None
    assert parse_scan_command("scan owner/repo --bogus") is None
    assert parse_scan_command("scan owner/repo --source") is None


def test_get_render_rows_against_seeded_store(tmp_path, monkeypatch):
    monkeypatch.setenv("WARDEN_DB", str(tmp_path / "warden.db"))

    finding = Finding(
        cve="CVE-2024-3094",
        package="xz-utils",
        installed_version="5.6.0",
        fixed_version="5.6.2",
        severity=Severity.CRITICAL,
        cvss=10.0,
        epss=0.94,
        kev=True,
        scanner="trivy",
        repo="acme/orders-api",
    )
    decision = Decision(
        cve="CVE-2024-3094",
        package="xz-utils",
        action=Action.BLOCK,
        reasons=["on CISA KEV — known exploited in the wild"],
        auto_fixable=True,
    )
    store.upsert_decisions("acme/orders-api", [decision], [finding])

    rows = store.get_render_rows("acme/orders-api")

    assert len(rows) == 1
    row = rows[0]
    assert row["cve"] == "CVE-2024-3094"
    assert row["action"] == "block"
    assert row["severity"] == "critical"
    assert row["kev"] is True

    assert store.get_render_rows("acme/orders-api", action="auto") == []
