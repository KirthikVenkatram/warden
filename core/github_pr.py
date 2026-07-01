import base64
import os
import re

import httpx

from core import store
from core.models import PRResult

GITHUB_API_URL = "https://api.github.com"


def open_fix_pr(
    repo: str,
    cve: str,
    package: str,
    installed_version: str,
    fixed_version: str,
    client: httpx.Client | None = None,
) -> PRResult:
    """Open (or reuse) a PR bumping package from installed_version to fixed_version.

    Python/requirements.txt only. Branch is warden/fix-<cve-lowercased>; reused if it
    already exists rather than recreated. Never raises for an expected "can't do this"
    situation (no token, no requirements.txt, no matching pin) — returns
    PRResult(status="skipped", reason=...) instead so callers never crash on it.
    """
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        return PRResult(cve=cve, package=package, repo=repo, status="skipped", reason="GITHUB_TOKEN is not set")

    branch_name = f"warden/fix-{cve.lower()}"
    owns_client = client is None
    client = client or httpx.Client(base_url=GITHUB_API_URL, headers=_headers(token))
    try:
        default_branch = _default_branch(client, repo)

        if not _branch_exists(client, repo, branch_name):
            head_sha = _branch_head_sha(client, repo, default_branch)
            _create_branch(client, repo, branch_name, head_sha)

        contents = _get_file(client, repo, "requirements.txt", branch_name)
        if contents is None:
            return PRResult(
                cve=cve,
                package=package,
                repo=repo,
                branch=branch_name,
                status="skipped",
                reason="requirements.txt not found on default branch",
            )

        raw = base64.b64decode(contents["content"]).decode()
        new_raw, replaced = _replace_pin(raw, package, installed_version, fixed_version)
        if not replaced:
            return PRResult(
                cve=cve,
                package=package,
                repo=repo,
                branch=branch_name,
                status="skipped",
                reason=f"no pin for {package}=={installed_version} found in requirements.txt",
            )

        _commit_file(client, repo, branch_name, new_raw, contents["sha"], package, fixed_version, cve)

        existing = _find_open_pr(client, repo, branch_name)
        if existing is not None:
            return PRResult(
                cve=cve,
                package=package,
                repo=repo,
                branch=branch_name,
                fixed_version=fixed_version,
                status="reused",
                url=existing["html_url"],
                number=existing["number"],
            )

        pr = _create_pr(client, repo, branch_name, default_branch, package, fixed_version, cve)
        return PRResult(
            cve=cve,
            package=package,
            repo=repo,
            branch=branch_name,
            fixed_version=fixed_version,
            status="opened",
            url=pr["html_url"],
            number=pr["number"],
        )
    finally:
        if owns_client:
            client.close()


def _headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _default_branch(client: httpx.Client, repo: str) -> str:
    resp = client.get(f"/repos/{repo}")
    resp.raise_for_status()
    return resp.json()["default_branch"]


def _branch_head_sha(client: httpx.Client, repo: str, branch: str) -> str:
    resp = client.get(f"/repos/{repo}/git/ref/heads/{branch}")
    resp.raise_for_status()
    return resp.json()["object"]["sha"]


def _branch_exists(client: httpx.Client, repo: str, branch: str) -> bool:
    resp = client.get(f"/repos/{repo}/git/ref/heads/{branch}")
    if resp.status_code == 404:
        return False
    resp.raise_for_status()
    return True


def _create_branch(client: httpx.Client, repo: str, branch: str, sha: str) -> None:
    resp = client.post(f"/repos/{repo}/git/refs", json={"ref": f"refs/heads/{branch}", "sha": sha})
    resp.raise_for_status()


def _get_file(client: httpx.Client, repo: str, path: str, ref: str) -> dict | None:
    resp = client.get(f"/repos/{repo}/contents/{path}", params={"ref": ref})
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    return resp.json()


def _commit_file(
    client: httpx.Client,
    repo: str,
    branch: str,
    new_content: str,
    file_sha: str,
    package: str,
    fixed_version: str,
    cve: str,
) -> None:
    resp = client.put(
        f"/repos/{repo}/contents/requirements.txt",
        json={
            "message": f"fix(deps): bump {package} to {fixed_version} for {cve}",
            "content": base64.b64encode(new_content.encode()).decode(),
            "sha": file_sha,
            "branch": branch,
        },
    )
    resp.raise_for_status()


def _find_open_pr(client: httpx.Client, repo: str, branch: str) -> dict | None:
    owner = repo.split("/", 1)[0]
    resp = client.get(f"/repos/{repo}/pulls", params={"head": f"{owner}:{branch}", "state": "open"})
    resp.raise_for_status()
    results = resp.json()
    return results[0] if results else None


def _create_pr(
    client: httpx.Client, repo: str, branch: str, base: str, package: str, fixed_version: str, cve: str
) -> dict:
    resp = client.post(
        f"/repos/{repo}/pulls",
        json={
            "title": f"fix(deps): bump {package} to {fixed_version} for {cve}",
            "head": branch,
            "base": base,
            "body": _pr_body(repo, cve, package, fixed_version),
        },
    )
    resp.raise_for_status()
    return resp.json()


def _pr_body(repo: str, cve: str, package: str, fixed_version: str) -> str:
    lines = [f"Automated fix for {cve} in {package}, bumped to {fixed_version}.", ""]
    detail = store.get_finding_detail(cve, repo)
    if detail is not None:
        if detail.get("severity") is not None:
            lines.append(f"- Severity: {detail['severity']} (CVSS {detail.get('cvss')})")
        if detail.get("epss") is not None:
            lines.append(f"- EPSS: {detail['epss']:.2f}")
        if detail.get("kev") is not None:
            lines.append(f"- CISA KEV: {'yes' if detail['kev'] else 'no'}")
        if detail.get("reasons"):
            lines.append("- Policy reasons: " + "; ".join(detail["reasons"]))
    return "\n".join(lines)


def _replace_pin(text: str, package: str, installed_version: str, fixed_version: str) -> tuple[str, bool]:
    """Rewrite a `package==installed_version` pin to fixed_version, keeping extras/markers."""
    pattern = re.compile(
        rf"^(?P<pin>{re.escape(package)}(?:\[[^\]]*\])?)\s*==\s*{re.escape(installed_version)}(?P<suffix>\s*(?:;.*)?)$",
        re.IGNORECASE | re.MULTILINE,
    )

    def _sub(match: re.Match) -> str:
        return f"{match.group('pin')}=={fixed_version}{match.group('suffix')}"

    new_text, count = pattern.subn(_sub, text)
    return new_text, count > 0
