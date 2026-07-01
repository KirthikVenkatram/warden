import json
import logging
import time
from pathlib import Path

import httpx

from core.models import Finding

logger = logging.getLogger(__name__)

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE_PATH = Path(".cache/kev.json")
KEV_CACHE_TTL_SECONDS = 24 * 60 * 60
EPSS_BATCH_SIZE = 100


def fetch_epss_scores(cves: list[str], client: httpx.Client | None = None) -> dict[str, float]:
    """Query FIRST.org EPSS for a list of CVEs, batched to stay under URL limits.

    Missing CVEs (or any request failure) default to 0.0 rather than raising.
    """
    scores: dict[str, float] = {cve: 0.0 for cve in cves}
    if not cves:
        return scores

    owns_client = client is None
    client = client or httpx.Client()
    try:
        for i in range(0, len(cves), EPSS_BATCH_SIZE):
            batch = cves[i : i + EPSS_BATCH_SIZE]
            try:
                response = client.get(EPSS_URL, params={"cve": ",".join(batch)})
                response.raise_for_status()
                payload = response.json()
                for entry in payload.get("data", []):
                    cve = entry.get("cve")
                    if cve in scores:
                        scores[cve] = float(entry.get("epss", 0.0))
            except (httpx.HTTPError, ValueError, KeyError) as exc:
                logger.warning("EPSS lookup failed for batch starting at %d: %s", i, exc)
    finally:
        if owns_client:
            client.close()

    return scores


def _load_kev_cache() -> set[str] | None:
    if not KEV_CACHE_PATH.exists():
        return None
    age = time.time() - KEV_CACHE_PATH.stat().st_mtime
    if age > KEV_CACHE_TTL_SECONDS:
        return None
    try:
        cache = json.loads(KEV_CACHE_PATH.read_text())
        return set(cache["cve_ids"])
    except (json.JSONDecodeError, KeyError, OSError) as exc:
        logger.warning("KEV cache read failed, will refetch: %s", exc)
        return None


def _write_kev_cache(cve_ids: set[str]) -> None:
    try:
        KEV_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        KEV_CACHE_PATH.write_text(json.dumps({"cve_ids": sorted(cve_ids)}))
    except OSError as exc:
        logger.warning("KEV cache write failed: %s", exc)


def fetch_kev_catalog(client: httpx.Client | None = None) -> set[str]:
    """Return the set of CVE IDs on the CISA KEV catalog, cached for 24h.

    Any network or parse failure falls back to an empty set (or the stale cache,
    if reading a fresh copy fails but a stale one is on disk).
    """
    cached = _load_kev_cache()
    if cached is not None:
        return cached

    owns_client = client is None
    client = client or httpx.Client()
    try:
        response = client.get(KEV_URL)
        response.raise_for_status()
        payload = response.json()
        cve_ids = {vuln["cveID"] for vuln in payload.get("vulnerabilities", [])}
        _write_kev_cache(cve_ids)
        return cve_ids
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        logger.warning("KEV catalog fetch failed, defaulting to empty set: %s", exc)
        return set()
    finally:
        if owns_client:
            client.close()


def enrich(findings: list[Finding], client: httpx.Client | None = None) -> list[Finding]:
    """Set epss and kev on every finding. Never drops a finding on feed failure."""
    if not findings:
        return findings

    owns_client = client is None
    client = client or httpx.Client()
    try:
        epss_scores = fetch_epss_scores([f.cve for f in findings], client=client)
        kev_ids = fetch_kev_catalog(client=client)
    finally:
        if owns_client:
            client.close()

    for finding in findings:
        finding.epss = epss_scores.get(finding.cve, 0.0)
        finding.kev = finding.cve in kev_ids

    return findings
