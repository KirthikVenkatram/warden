import json

from core.models import ScanSummary
from slack_app.blockkit import build_detail, build_digest

BLOCK_FINDING = {
    "cve": "CVE-2024-3094",
    "repo": "ubixi/conductor",
    "package": "xz-utils",
    "action": "block",
    "reasons": ["on CISA KEV — known exploited in the wild"],
    "auto_fixable": True,
    "severity": "critical",
    "cvss": 10.0,
    "epss": 0.94,
    "kev": True,
    "installed_version": "5.6.0",
    "fixed_version": "5.6.2",
}

ASK_FINDING = {
    "cve": "CVE-2024-1111",
    "repo": "ubixi/conductor",
    "package": "requests",
    "action": "ask",
    "reasons": ["high EPSS at high severity"],
    "auto_fixable": True,
    "severity": "high",
    "cvss": 7.5,
    "epss": 0.6,
    "kev": False,
    "installed_version": "2.28.0",
    "fixed_version": "2.31.0",
}

AUTO_FINDING = {
    "cve": "CVE-2024-2222",
    "repo": "ubixi/conductor",
    "package": "urllib3",
    "action": "auto",
    "reasons": ["low risk, tests green"],
    "auto_fixable": True,
    "severity": "low",
    "cvss": 2.1,
    "epss": 0.01,
    "kev": False,
    "installed_version": "1.26.0",
    "fixed_version": "1.26.5",
    "pr_url": "https://github.com/ubixi/conductor/pull/1",
}

IGNORE_FINDING = {
    "cve": "CVE-2024-3333",
    "repo": "ubixi/conductor",
    "package": "idle-lib",
    "action": "ignore",
    "reasons": ["no fix available"],
    "auto_fixable": False,
    "severity": "medium",
    "cvss": 4.0,
    "epss": 0.02,
    "kev": False,
    "installed_version": "1.0.0",
    "fixed_version": None,
}

SUMMARY = ScanSummary(repo="ubixi/conductor", scanner="trivy", total=4, auto=1, ask=1, block=1, ignore=1)


def test_digest_header_count_line():
    msg = build_digest(SUMMARY, [BLOCK_FINDING, ASK_FINDING, AUTO_FINDING, IGNORE_FINDING])
    header = msg["blocks"][0]
    assert header["type"] == "header"
    text = header["text"]["text"]
    assert "1 blocked" in text
    assert "1 needs approval" in text
    assert "1 auto-fixed" in text
    assert "1 ignored" in text


def test_block_finding_has_no_approve_button():
    msg = build_digest(SUMMARY, [BLOCK_FINDING])
    action_ids = []
    values_text = json.dumps(msg["blocks"])
    for block in msg["blocks"]:
        if block["type"] == "actions":
            for el in block["elements"]:
                action_ids.append(el["action_id"])
    assert "explain_finding" in action_ids
    assert "approve_fix" not in action_ids
    assert "approve_fix" not in values_text


def test_ask_finding_has_all_three_actions():
    msg = build_digest(SUMMARY, [ASK_FINDING])
    action_ids = []
    for block in msg["blocks"]:
        if block["type"] == "actions":
            for el in block["elements"]:
                action_ids.append(el["action_id"])
    assert set(action_ids) == {"approve_fix", "snooze_finding", "explain_finding"}


def test_auto_finding_has_no_buttons():
    msg = build_digest(SUMMARY, [AUTO_FINDING])
    for block in msg["blocks"]:
        assert block["type"] != "actions"


def test_kev_badge_present_when_true():
    msg = build_digest(SUMMARY, [BLOCK_FINDING])
    blob = json.dumps(msg["blocks"])
    assert "KEV" in blob


def test_kev_badge_absent_when_false():
    msg = build_digest(SUMMARY, [ASK_FINDING])
    blob = json.dumps(msg["blocks"])
    assert "KEV" not in blob


def test_findings_ordered_block_ask_auto_ignore():
    msg = build_digest(SUMMARY, [IGNORE_FINDING, AUTO_FINDING, ASK_FINDING, BLOCK_FINDING])
    blob = msg["blocks"]
    cves_in_order = [
        b["text"]["text"]
        for b in blob
        if b["type"] == "section" and "CVE" in b["text"]["text"]
    ]
    # extract just cve substrings in appearance order
    order = []
    for text in cves_in_order:
        for f in (BLOCK_FINDING, ASK_FINDING, AUTO_FINDING, IGNORE_FINDING):
            if f["cve"] in text:
                order.append(f["action"])
    assert order == ["block", "ask", "auto", "ignore"]


def _collect_values(blocks):
    values = []
    for block in blocks:
        if block["type"] == "actions":
            for el in block["elements"]:
                if "value" in el:
                    values.append(el["value"])
                if el.get("type") == "overflow":
                    for opt in el["options"]:
                        values.append(opt["value"])
    return values


def test_all_button_values_are_valid_json_with_cve_repo():
    msg = build_digest(SUMMARY, [BLOCK_FINDING, ASK_FINDING])
    for value in _collect_values(msg["blocks"]):
        parsed = json.loads(value)
        assert "cve" in parsed
        assert "repo" in parsed


def test_build_detail_includes_cve_link_and_reasons():
    detail = {
        "cve": "CVE-2024-3094",
        "repo": "ubixi/conductor",
        "package": "xz-utils",
        "action": "block",
        "reasons": ["on CISA KEV — known exploited in the wild", "critical severity"],
        "auto_fixable": True,
        "severity": "critical",
        "cvss": 10.0,
        "epss": 0.94,
        "kev": True,
        "installed_version": "5.6.0",
        "fixed_version": "5.6.2",
    }
    msg = build_detail(detail)
    blob = json.dumps(msg["blocks"], ensure_ascii=False)
    assert "CVE-2024-3094" in blob
    assert "https://nvd.nist.gov/vuln/detail/CVE-2024-3094" in blob
    for reason in detail["reasons"]:
        assert reason in blob
