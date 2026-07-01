import json

import httpx
import pytest

from core import enrich
from core.models import Finding


def make_finding(cve: str) -> Finding:
    return Finding(
        cve=cve,
        package="xz-utils",
        installed_version="5.6.0",
        fixed_version="5.6.2",
        severity="critical",
        cvss=10.0,
        scanner="trivy",
        repo="ubixi/conductor",
    )


def epss_handler(cve_to_score: dict[str, float]):
    def handler(request: httpx.Request) -> httpx.Response:
        requested = request.url.params["cve"].split(",")
        data = [
            {"cve": cve, "epss": str(cve_to_score[cve])}
            for cve in requested
            if cve in cve_to_score
        ]
        return httpx.Response(200, json={"data": data})

    return handler


def kev_handler(cve_ids: list[str], calls: list[int] | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append(1)
        return httpx.Response(
            200, json={"vulnerabilities": [{"cveID": cve} for cve in cve_ids]}
        )

    return handler


def failing_handler(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("network is down", request=request)


@pytest.fixture(autouse=True)
def isolate_kev_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(enrich, "KEV_CACHE_PATH", tmp_path / "kev.json")


def test_fetch_epss_scores_success():
    handler = epss_handler({"CVE-2024-3094": 0.94, "CVE-2024-0001": 0.02})
    client = httpx.Client(transport=httpx.MockTransport(handler))

    scores = enrich.fetch_epss_scores(["CVE-2024-3094", "CVE-2024-0001"], client=client)

    assert scores == {"CVE-2024-3094": 0.94, "CVE-2024-0001": 0.02}


def test_fetch_epss_scores_missing_cve_defaults_zero():
    handler = epss_handler({"CVE-2024-3094": 0.94})
    client = httpx.Client(transport=httpx.MockTransport(handler))

    scores = enrich.fetch_epss_scores(["CVE-2024-3094", "CVE-9999-0000"], client=client)

    assert scores["CVE-2024-3094"] == 0.94
    assert scores["CVE-9999-0000"] == 0.0


def test_fetch_epss_scores_batches_large_requests():
    cves = [f"CVE-2024-{i:04d}" for i in range(150)]
    seen_batches: list[list[str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested = request.url.params["cve"].split(",")
        seen_batches.append(requested)
        return httpx.Response(
            200, json={"data": [{"cve": c, "epss": "0.5"} for c in requested]}
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    scores = enrich.fetch_epss_scores(cves, client=client)

    assert len(seen_batches) == 2
    assert len(seen_batches[0]) == 100
    assert len(seen_batches[1]) == 50
    assert all(scores[c] == 0.5 for c in cves)


def test_fetch_epss_scores_network_failure_defaults_zero():
    client = httpx.Client(transport=httpx.MockTransport(failing_handler))

    scores = enrich.fetch_epss_scores(["CVE-2024-3094"], client=client)

    assert scores == {"CVE-2024-3094": 0.0}


def test_fetch_kev_catalog_success():
    client = httpx.Client(transport=httpx.MockTransport(kev_handler(["CVE-2024-3094"])))

    kev_ids = enrich.fetch_kev_catalog(client=client)

    assert kev_ids == {"CVE-2024-3094"}


def test_fetch_kev_catalog_uses_cache_on_second_call():
    calls: list[int] = []
    client = httpx.Client(
        transport=httpx.MockTransport(kev_handler(["CVE-2024-3094"], calls=calls))
    )

    first = enrich.fetch_kev_catalog(client=client)
    assert len(calls) == 1
    assert first == {"CVE-2024-3094"}

    second_client = httpx.Client(transport=httpx.MockTransport(failing_handler))
    second = enrich.fetch_kev_catalog(client=second_client)

    assert len(calls) == 1
    assert second == {"CVE-2024-3094"}


def test_fetch_kev_catalog_network_failure_defaults_empty():
    client = httpx.Client(transport=httpx.MockTransport(failing_handler))

    kev_ids = enrich.fetch_kev_catalog(client=client)

    assert kev_ids == set()


def test_enrich_sets_epss_and_kev_from_mocked_responses(monkeypatch):
    findings = [make_finding("CVE-2024-3094"), make_finding("CVE-2024-0001")]

    def fake_fetch_epss(cves, client=None):
        return {"CVE-2024-3094": 0.94, "CVE-2024-0001": 0.01}

    def fake_fetch_kev(client=None):
        return {"CVE-2024-3094"}

    monkeypatch.setattr(enrich, "fetch_epss_scores", fake_fetch_epss)
    monkeypatch.setattr(enrich, "fetch_kev_catalog", fake_fetch_kev)

    result = enrich.enrich(findings)

    assert result[0].epss == 0.94
    assert result[0].kev is True
    assert result[1].epss == 0.01
    assert result[1].kev is False


def test_enrich_network_failure_preserves_findings_with_defaults():
    findings = [make_finding("CVE-2024-3094"), make_finding("CVE-2024-0001")]
    client = httpx.Client(transport=httpx.MockTransport(failing_handler))

    result = enrich.enrich(findings, client=client)

    assert len(result) == 2
    assert all(f.epss == 0.0 and f.kev is False for f in result)


def test_kev_cache_written_to_disk(tmp_path):
    client = httpx.Client(transport=httpx.MockTransport(kev_handler(["CVE-2024-3094"])))

    enrich.fetch_kev_catalog(client=client)

    cache_path = enrich.KEV_CACHE_PATH
    assert cache_path.exists()
    cached = json.loads(cache_path.read_text())
    assert cached["cve_ids"] == ["CVE-2024-3094"]
